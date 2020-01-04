package pkg

import (
	"context"
	"github.com/dgoujard/uptimeWorker/config"
	"github.com/dgoujard/uptimeWorker/services"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)
type DatabaseService struct {
	*services.DatabaseService
}

func CreateDatabaseConnection(config *config.DatabaseConfig) *DatabaseService {
	return &DatabaseService{
		DatabaseService:services.CreateDatabaseConnection(config),
	}
}

func (d *DatabaseService) MarkSiteNotSSLMonitored(id *primitive.ObjectID)  {
	d.Client.Database(d.DatabaseName).Collection("sites").FindOneAndUpdate(
		context.Background(),
		bson.M{"_id": id},
		bson.M{"$set": bson.D{
			{"ssl_monitored", false},
			{"ssl_alertExpireSended", false},
		},
		},
	)
}

func (d *DatabaseService) UpdateSiteSSLStatus(id *primitive.ObjectID, sslResult certificate, alertExpireSended bool)  {
	d.Client.Database(d.DatabaseName).Collection("sites").FindOneAndUpdate(
		context.Background(),
		bson.M{"_id": id},
		bson.M{"$set": bson.D{
			{"ssl_monitored", true},
			{"ssl_alertExpireSended", alertExpireSended},
			{"ssl_error", sslResult.error},
			{"ssl_issuer", sslResult.issuer},
			{"ssl_subject", sslResult.subject},
			{"ssl_algo", sslResult.algo},
			{"ssl_expireDatetime", sslResult.expireAt},
		},
		},
	)
}