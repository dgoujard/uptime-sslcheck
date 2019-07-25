package main

import (
	//"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"log"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"

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

const (
	defaultWarningDays = 30
)

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
type sitesToCheck []siteToCheck
type siteToCheck struct {
	name string
	host string
	certs map[string]certificate
}

var (
	days   int
	months int
	years  int

	all bool

	debug bool
)

func main() {
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		log.Fatal(err)
	}
	var baseCacheDir = dir
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
	var config tomlConfig
	if _, err := toml.DecodeFile("config.toml", &config); err != nil {
		log.Println(err)
		return
	}

	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	client, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://"+config.Database.User+":"+config.Database.Password+"@"+config.Database.Server+":"+strconv.Itoa(config.Database.Port)+"/"+config.Database.Database))

	err = client.Ping(ctx, readpref.Primary())
	if err != nil {
		log.Fatal(err)
	}

	var listeSitesToCheck = sitesToCheck{}

	collection := client.Database(config.Database.Database).Collection("sites")
	cur, err := collection.Find(ctx, bson.D{})
	if err != nil { log.Fatal(err) }
	defer cur.Close(ctx)
	for cur.Next(ctx) {
		var result bson.M
		err := cur.Decode(&result)
		if err != nil { log.Fatal(err) }
		// do something with result....
		u, err :=  url.Parse(fmt.Sprintf("%v",result["url"]))
		listeSitesToCheck = append(listeSitesToCheck, siteToCheck{name:fmt.Sprintf("%v",result["name"]),host:u.Host})
	}
	if err := cur.Err(); err != nil {
		log.Fatal(err)
	}

	fmt.Println(listeSitesToCheck)
	now := time.Now()
	days = 30
	twarn := now.AddDate(years, months, days)

	certs, err := checkHost(listeSitesToCheck[0].host, twarn)
	if err != nil {
		fmt.Println("erreur");
		fmt.Println(err)
	}
	fmt.Println(certs)
	/*

	// Create a new cli program.
	p := cli.NewProgram()
	p.Name = "certok"
	p.Description = "A tool to check the validity and expiration dates of SSL certificates"

	// Set the GitCommit and Version.
	p.GitCommit = version.GITCOMMIT
	p.Version = version.VERSION

	// Setup the global flags.
	p.FlagSet = flag.NewFlagSet("global", flag.ExitOnError)
	p.FlagSet.IntVar(&years, "years", 0, "Warn if the certificate will expire within this many years.")
	p.FlagSet.IntVar(&months, "months", 0, "Warn if the certificate will expire within this many months.")
	p.FlagSet.IntVar(&days, "days", 0, "Warn if the certificate will expire within this many days.")

	p.FlagSet.BoolVar(&all, "all", false, "Show entire certificate chain, not just the first.")

	p.FlagSet.BoolVar(&debug, "d", false, "enable debug logging")

	// Set the before function.
	p.Before = func(ctx context.Context) error {
		// Set the log level.
		if debug {
			logrus.SetLevel(logrus.DebugLevel)
		}

		// set the default warning days if not set already
		if years == 0 && months == 0 && days == 0 {
			days = defaultWarningDays
		}

		return nil
	}

	// Set the main program action.
	p.Action = func(ctx context.Context, args []string) error {
		// check if we are reading from a file or stdin
		var (
			scanner *bufio.Scanner
		)
		if len(args) == 0 {
			logrus.Debugf("no file passed, reading from stdin...")
			scanner = bufio.NewScanner(os.Stdin)
		} else {
			f, err := os.Open(args[0])
			if err != nil {
				logrus.Fatalf("opening file %s failed: %v", args[0], err)
				os.Exit(1)
			}
			defer f.Close()
			scanner = bufio.NewScanner(f)
		}

		// get the time now
		now := time.Now()
		twarn := now.AddDate(years, months, days)

		// create the WaitGroup
		var wg sync.WaitGroup
		hosts := hosts{}

		for scanner.Scan() {
			wg.Add(1)
			h := scanner.Text()
			go func() {
				certs, err := checkHost(h, twarn)
				if err != nil {
					logrus.Warn(err)
				}
				hosts = append(hosts, host{name: h, certs: certs})
				wg.Done()
			}()
		}

		// wait for all the goroutines to finish
		wg.Wait()

		// Sort the hosts
		sort.Sort(hosts)

		// create the writer
		w := tabwriter.NewWriter(os.Stdout, 20, 1, 2, ' ', 0)
		fmt.Fprintln(w, "NAME\tSUBJECT\tISSUER\tALGO\tEXPIRES\tSUNSET DATE\tERROR")

		// Iterate over the hosts
		for i := 0; i < len(hosts); i++ {
			for _, cert := range hosts[i].certs {
				sunset := ""
				if cert.sunset != nil {
					sunset = cert.sunset.date.Format("Jan 02, 2006")

				}
				expires := cert.expires
				if cert.warn {
					expires = colorstring.Color("[red]" + cert.expires + "[reset]")
				}
				error := cert.error
				if error != "" {
					error = colorstring.Color("[red]" + cert.error + "[reset]")
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", cert.name, cert.subject, cert.issuer, cert.algo, expires, sunset, error)
			}
		}

		// flush the writer
		w.Flush()

		return nil
	}

	// Run our program.
	p.Run()*/
}
/*
func processHosts() {
	done := make(chan struct{})
	defer close(done)

	hosts := queueHosts(done)
	results := make(chan hostResult)

	var wg sync.WaitGroup
	wg.Add(8)
	for i := 0; i < 8; i++ {
		go func() {
			processQueue(done, hosts, results)
			wg.Done()
		}()
	}
	wg.Wait()

	go func() {
		wg.Wait()
		close(results)
	}()

	for r := range results {
		if r.err != nil {
			log.Printf("%s: %v\n", r.host, r.err)
			continue
		}
		for _, cert := range r.certs {
			for _, err := range cert.errs {
				log.Println(err)
			}
		}
	}
}*/

type hosts []host

func (h hosts) Len() int           { return len(h) }
func (h hosts) Less(i, j int) bool { return h[i].name < h[j].name }
func (h hosts) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

type host struct {
	name  string
	certs map[string]certificate
}

type certificate struct {
	name    string
	subject string
	algo    string
	issuer  string
	expires string
	warn    bool
	error   string
	sunset  *sunsetSignatureAlgorithm
}

func checkHost(h string, twarn time.Time) (map[string]certificate, error) {
	if !strings.Contains(h, ":") {
		// default to 443
		h += ":443"
	}
	c, err := tls.Dial("tcp", h, nil)
	if err != nil {
		switch cerr := err.(type) {
		case x509.CertificateInvalidError:
			ht := createHost(h, twarn, cerr.Cert)
			ht.error = err.Error()
			return map[string]certificate{
				string(cerr.Cert.Signature): ht,
			}, nil
		case x509.UnknownAuthorityError:
			ht := createHost(h, twarn, cerr.Cert)
			ht.error = err.Error()
			return map[string]certificate{
				string(cerr.Cert.Signature): ht,
			}, nil
		case x509.HostnameError:
			ht := createHost(h, twarn, cerr.Certificate)
			ht.error = err.Error()
			return map[string]certificate{
				string(cerr.Certificate.Signature): ht,
			}, nil
		}
		return nil, fmt.Errorf("tcp dial %s failed: %v", h, err)
	}
	defer c.Close()

	certs := make(map[string]certificate)
	for _, chain := range c.ConnectionState().VerifiedChains {
		for n, cert := range chain {
			if _, checked := certs[string(cert.Signature)]; checked {
				continue
			}
			if !all && n >= 1 {
				continue
			}

			ht := createHost(h, twarn, cert)

			certs[string(cert.Signature)] = ht
		}
	}

	return certs, nil
}

func createHost(name string, twarn time.Time, cert *x509.Certificate) certificate {
	host := certificate{
		name:    name,
		subject: cert.Subject.CommonName,
		issuer:  cert.Issuer.CommonName,
		algo:    cert.SignatureAlgorithm.String(),
	}

	// check the expiration
	if twarn.After(cert.NotAfter) {
		host.warn = true
	}
	expiresIn := int64(time.Until(cert.NotAfter).Hours())
	if expiresIn <= 48 {
		host.expires = fmt.Sprintf("%d hours", expiresIn)
	} else {
		host.expires = fmt.Sprintf("%d days", expiresIn/24)
	}

	// Check the signature algorithm, ignoring the root certificate.
	if alg, exists := sunsetSignatureAlgorithms[cert.SignatureAlgorithm]; exists {
		if cert.NotAfter.Equal(alg.date) || cert.NotAfter.After(alg.date) {
			host.warn = true
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