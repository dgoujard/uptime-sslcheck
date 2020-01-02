package pkg

import "go.mongodb.org/mongo-driver/bson/primitive"

const SiteStatusUp = 2
const SiteStatusDown = 9
const SiteStatusPause = 0

const LogTypeStatusUp = 2
const LogTypeStatusDown = 1
const LogTypeStatusPause = 99

type SiteBdd struct{
	Id primitive.ObjectID  `json:"_id,omitempty" bson:"_id,omitempty"`
	Account primitive.ObjectID `json:"Account,omitempty" bson:"Account,omitempty"`
	NotificationGroup primitive.ObjectID `json:"NotificationGroup,omitempty" bson:"NotificationGroup,omitempty"`
	CreateDatetime int32 `json:"createDatetime,omitempty" bson:"createDatetime,omitempty"`
	Lastlog int32 `json:"lastlog,omitempty" bson:"lastlog,omitempty"` //Ne marche pas
	Name string
	Url string
	Status int
	UptimeId int32 `json:"uptimeId,omitempty" bson:"uptimeId,omitempty"`
}
