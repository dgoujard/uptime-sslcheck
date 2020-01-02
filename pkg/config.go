package pkg

import (
	"github.com/BurntSushi/toml"
	"github.com/dgoujard/uptimeWorker/config"
	"log"
)

type TomlConfig struct {
	Database config.DatabaseConfig
	Amq config.AmqConfig
}

func GetConfig(configPath string) (configFile *TomlConfig) {
	if _, err := toml.DecodeFile(configPath, &configFile); err != nil {
		log.Println(err)
		return
	}
	return
}