package main

import (
	//"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"log"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sync"

	//"sort"
	"strconv"
	"strings"
	//"sync"
	"syscall"
	"time"
	"github.com/BurntSushi/toml"

	"gopkg.in/natefinch/lumberjack.v2"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

//
type tomlConfig struct {
	Database databaseConfig
}
type databaseConfig struct {
	Server string
	Port int
	User string
	Password string
	Database string
}

type siteToCheck struct {
	id primitive.ObjectID
	name string
	host string
	certs map[string]certificate
}

var (
	ctx context.Context
	client *mongo.Client
	config tomlConfig
)

func main() {
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		log.Fatal(err)
	}
	var baseCacheDir= dir
	if strings.HasPrefix(dir, "/private/") || strings.HasPrefix(dir, "/var/folders/") {
		baseCacheDir = "/Users/damien/uptime-sslcheck"
	}

	l := &lumberjack.Logger{
		Filename:   baseCacheDir + "/app.log",
		MaxSize:    1, // megabytes
		MaxBackups: 3,
		MaxAge:     7,    //days
		Compress:   true, // disabled by default
		LocalTime:  true,
	}
	log.SetOutput(l)
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP)

	go func() {
		for {
			<-c
			l.Rotate()
		}
	}()

	log.Println("Reading configuration")
	if _, err := toml.DecodeFile("config.toml", &config); err != nil {
		log.Println(err)
		return
	}

	ctx, _ = context.WithTimeout(context.Background(), 10*time.Second)
	client, err = mongo.Connect(ctx, options.Client().ApplyURI("mongodb://"+config.Database.User+":"+config.Database.Password+"@"+config.Database.Server+":"+strconv.Itoa(config.Database.Port)+"/"+config.Database.Database))

	err = client.Ping(ctx, readpref.Primary())
	if err != nil {
		log.Fatal(err)
	}

	//var listeSitesToCheck= sitesToCheck{}


	hosts := queueHosts()

	var wg sync.WaitGroup
	wg.Add(8)
	for i := 0; i < 8; i++ {
		go func(i int) {
			processQueue(hosts,i)
			wg.Done()
		}(i)
	}
	wg.Wait()
	log.Println("Done")
}


type SiteBdd struct{
	Id primitive.ObjectID  `json:"_id,omitempty" bson:"_id,omitempty"`
	Account primitive.ObjectID `json:"Account,omitempty" bson:"Account,omitempty"`
	CreateDatetime int32 `json:"createDatetime,omitempty" bson:"createDatetime,omitempty"`
	Lastlog int32 `json:"lastlog,omitempty" bson:"lastlog,omitempty"` //Ne marche pas
	Name string
	Url string
	Status int
	UptimeId int32 `json:"uptimeId,omitempty" bson:"uptimeId,omitempty"`
}

func queueHosts() <-chan siteToCheck {
	hosts := make(chan siteToCheck)
	go func() {
		defer close(hosts)

		collection := client.Database(config.Database.Database).Collection("sites")
		cur, err := collection.Find(ctx, bson.D{})
		if err != nil {
			log.Fatal(err)
		}
		defer cur.Close(ctx)
		for cur.Next(ctx) {
			var result SiteBdd
			err := cur.Decode(&result)
			if err != nil {
				log.Fatal(err)
			}

			u, err := url.Parse(result.Url)
			if u.Scheme == "https"{
				hosts <- siteToCheck{name: result.Name, host: u.Host, id:result.Id}
			}else {
				client.Database(config.Database.Database).Collection("sites").FindOneAndUpdate(
					context.Background(),
					bson.M{"_id": result.Id},
					bson.M{"$set": bson.D{
						{"ssl_monitored", false},
					},
					},
				)
			}
		}
		if err := cur.Err(); err != nil {
			log.Fatal(err)
		}
	}()
	return hosts
}
func processQueue(sites <-chan siteToCheck,i int) {
	for site := range sites {
		//fmt.Println("Wor"+strconv.Itoa(i)+" "+site.name)
		sslResult, err := checkHost(site.host)
		if err != nil {
			log.Println("erreur")
			log.Println(err)
		}
		client.Database(config.Database.Database).Collection("sites").FindOneAndUpdate(
				context.Background(),
				bson.M{"_id": site.id},
				bson.M{"$set": bson.D{
					{"ssl_monitored", true},
					{"ssl_error", sslResult.error},
					{"ssl_issuer", sslResult.issuer},
					{"ssl_subject", sslResult.subject},
					{"ssl_algo", sslResult.algo},
					{"ssl_expireDatetime", sslResult.expireAt},
				}},
			)
		log.Println(fmt.Sprintf("%s %v","Worker "+strconv.Itoa(i),sslResult))
	}
}

type certificate struct {
	name    string
	subject string
	algo    string
	issuer  string
	expireAt int
	expireIn string
	warnAlgo    bool
	error   string
	sunset  *sunsetSignatureAlgorithm
}

func checkHost(h string) (certificate, error) {
	if !strings.Contains(h, ":") {
		// default to 443
		h += ":443"
	}
	c, err := tls.Dial("tcp", h, nil)
	if err != nil {
		switch cerr := err.(type) {
		case x509.CertificateInvalidError:
			ht := createHost(h, cerr.Cert)
			ht.error = err.Error()
			return ht, nil
		case x509.UnknownAuthorityError:
			ht := createHost(h, cerr.Cert)
			ht.error = err.Error()
			return ht, nil

		case x509.HostnameError:
			ht := createHost(h, cerr.Certificate)
			ht.error = err.Error()
			return ht, nil

		}
		return certificate{}, fmt.Errorf("tcp dial %s failed: %v", h, err)
	}
	defer c.Close()

	var certToReturn certificate
	certs := make(map[string]certificate)
	for _, chain := range c.ConnectionState().VerifiedChains {
		for n, cert := range chain {
			if _, checked := certs[string(cert.Signature)]; checked {
				continue
			}
			if n >= 1 { //pas de traitement des autres certificats de la chaine
				continue
			}

			certToReturn = createHost(h, cert)
		}
	}
	return certToReturn, nil
}

func createHost(name string, cert *x509.Certificate) certificate {
	host := certificate{
		name:    name,
		subject: cert.Subject.CommonName,
		issuer:  cert.Issuer.CommonName,
		algo:    cert.SignatureAlgorithm.String(),
	}
	host.expireAt = int(cert.NotAfter.UnixNano() / 1000000000)
	expiresIn := int64(time.Until(cert.NotAfter).Hours())
	if expiresIn <= 48 {
		host.expireIn = fmt.Sprintf("%d hours", expiresIn)
	} else {
		host.expireIn = fmt.Sprintf("%d days", expiresIn/24)
	}

	// Check the signature algorithm, ignoring the root certificate.
	if alg, exists := sunsetSignatureAlgorithms[cert.SignatureAlgorithm]; exists {
		if cert.NotAfter.Equal(alg.date) || cert.NotAfter.After(alg.date) {
			host.warnAlgo = true
		}
		host.sunset = &alg
	}

	return host
}



type sunsetSignatureAlgorithm struct {
	name string    // Human readable name of the signature algorithm.
	date time.Time // Date the signature algorithm will be sunset.
}

// sunsetSignatureAlgorithms is an algorithm to string mapping for certificate
// signature algorithms which have been or are being deprecated.  See the
// following links to learn more about SHA1's inclusion on this list.
// - https://technet.microsoft.com/en-us/library/security/2880823.aspx
// - http://googleonlinesecurity.blogspot.com/2014/09/gradually-sunsetting-sha-1.html
var sunsetSignatureAlgorithms = map[x509.SignatureAlgorithm]sunsetSignatureAlgorithm{
	x509.MD2WithRSA: {
		name: "MD2 with RSA",
		date: time.Now(),
	},
	x509.MD5WithRSA: {
		name: "MD5 with RSA",
		date: time.Now(),
	},
	x509.SHA1WithRSA: {
		name: "SHA1 with RSA",
		date: time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC),
	},
	x509.DSAWithSHA1: {
		name: "DSA with SHA1",
		date: time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC),
	},
	x509.ECDSAWithSHA1: {
		name: "ECDSA with SHA1",
		date: time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC),
	},
}