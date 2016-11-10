package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/Sirupsen/logrus"
	"github.com/coreos-inc/apostille/server"
)

type cmdFlags struct {
	configFile string
}

func setupFlags(flagStorage *cmdFlags) {
	flag.StringVar(&flagStorage.configFile, "config", "", "Path to configuration file")
	flag.Usage = usage
}

func main() {
	flagStorage := cmdFlags{}
	setupFlags(&flagStorage)

	flag.Parse()

	ctx, serverConfig, err := parseServerConfig(flagStorage.configFile)
	if err != nil {
		logrus.Fatal(err.Error())
	}

	err = server.Run(ctx, serverConfig)

	if err != nil {
		logrus.Fatal(err.Error())
	}
	return
}

func usage() {
	fmt.Println("usage:", os.Args[0])
	flag.PrintDefaults()
}
