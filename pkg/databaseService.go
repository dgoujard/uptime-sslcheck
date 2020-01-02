package pkg

import (
	"context"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"log"
	"strconv"
	"time"
)

type DatabaseService struct {
	client *mongo.Client
	databaseName string
}

func CreateDatabaseConnection(config *DatabaseConfig) *DatabaseService {
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	client, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://"+config.User+":"+config.Password+"@"+config.Server+":"+strconv.Itoa(config.Port)+"/"+config.Database))

	err = client.Ping(ctx, readpref.Primary())
	if err != nil {
		log.Fatal(err)
	}
	return &DatabaseService{
		client:client,
		databaseName: config.Database,
	}
}
func (d *DatabaseService) GetSitesList(withPaused bool) (sites []SiteBdd)  {
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	collection := d.client.Database(d.databaseName).Collection("sites")
	var filter = bson.M{}
	if !withPaused {
		filter = bson.M{"status": bson.M{"$ne": SiteStatusPause}}
	}
	cur, err := collection.Find(ctx, filter)
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
		//if(result.Name == "Afficheurs CCI (S6)"){
		sites = append(sites, result)
		//}
	}
	if err := cur.Err(); err != nil {
		log.Fatal(err)
	}
	return sites
}

func (d *DatabaseService) MarkSiteNotSSLMonitored(id *primitive.ObjectID)  {
	d.client.Database(d.databaseName).Collection("sites").FindOneAndUpdate(
		context.Background(),
		bson.M{"_id": id},
		bson.M{"$set": bson.D{
			{"ssl_monitored", false},
		},
		},
	)
}

func (d *DatabaseService) UpdateSiteSSLStatus(id *primitive.ObjectID, sslResult certificate)  {
	d.client.Database(d.databaseName).Collection("sites").FindOneAndUpdate(
		context.Background(),
		bson.M{"_id": id},
		bson.M{"$set": bson.D{
			{"ssl_monitored", true},
			{"ssl_error", sslResult.error},
			{"ssl_issuer", sslResult.issuer},
			{"ssl_subject", sslResult.subject},
			{"ssl_algo", sslResult.algo},
			{"ssl_expireDatetime", sslResult.expireAt},
		},
		},
	)
}