package pkg

import (
	"context"
	"fmt"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"gopkg.in/natefinch/lumberjack.v2"
	"log"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

type siteToCheck struct {
	id primitive.ObjectID
	name string
	host string
	certs map[string]certificate
}

var (
	ctx context.Context
	databaseService *DatabaseService
	queueService *QueueService
)

func init()  {
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
}

func LaunchCheck(config *TomlConfig) {

	databaseService = CreateDatabaseConnection(&config.Database)
	queueService = CreateQueueService(&config.Amq)

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

func queueHosts() <-chan siteToCheck {
	hosts := make(chan siteToCheck)
	go func() {
		defer close(hosts)

		siteList := databaseService.GetSitesList(false)
		if len(siteList) == 0{
			return
		}

		for _, site := range siteList {
			u, err := url.Parse(site.Url)
			if err != nil {
				log.Fatal(err)
			}
			if u.Scheme == "https"{
				hosts <- siteToCheck{name: site.Name, host: u.Host, id:site.Id}
			}else {
				databaseService.MarkSiteNotSSLMonitored(&site.Id)
			}
		}
	}()
	return hosts
}
func processQueue(sites <-chan siteToCheck,i int) {
	for site := range sites {
		//fmt.Println("Wor"+strconv.Itoa(i)+" "+site.name)
		sslResult, err := checkSSLHost(site.host)
		if err != nil {
			log.Println("erreur")
			log.Println(err)
		}
		databaseService.UpdateSiteSSLStatus(&site.id, sslResult)
		log.Println(fmt.Sprintf("%s %v","Worker "+strconv.Itoa(i),sslResult))
	}
}
