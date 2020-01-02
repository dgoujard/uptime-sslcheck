package pkg

import (
	"github.com/BurntSushi/toml"
	"log"
)

type TomlConfig struct {
	Database DatabaseConfig
	Amq AmqConfig
}
type AmqConfig struct {
	Uri string
	QueueAlertName string
}
type DatabaseConfig struct {
	Server string
	Port int
	User string
	Password string
	Database string
}


func GetConfig(configPath string) (configFile *TomlConfig) {
	if _, err := toml.DecodeFile(configPath, &configFile); err != nil {
		log.Println(err)
		return
	}
	return
}