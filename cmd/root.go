package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"log"
	"os"
	"path/filepath"
	"strings"
	"uptime-sslcheck/pkg"
)
var configPath string
var rootCmd = &cobra.Command{
	Use:   "check",
	Short: "Uptime - Check SSL certs status",
	Run: func(cmd *cobra.Command, args []string) {
		dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
		if err != nil {
			log.Fatal(err)
		}
		if string(configPath[1]) != "/" && string(configPath[1]) != "."{
			if strings.HasPrefix(dir, "/private/") || strings.HasPrefix(dir, "/var/folders/") {
				configPath = "/Users/damien/uptime-sslcheck/"+configPath
			}else{
				configPath = dir+"/"+configPath
			}
		}
		if !fileExists(configPath) {
			log.Fatal("Config file doesn't exist")
		}

		config := pkg.GetConfig(configPath)
		pkg.LaunchCheck(config)
	},
}
func Execute() {
	rootCmd.Flags().StringVarP(&configPath, "config", "c", "", "Configuration file path")
	rootCmd.MarkFlagRequired("config")
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}