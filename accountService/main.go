package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"syscall"

	"github.com/urfave/cli"
	"golang.org/x/crypto/ssh/terminal"

	"github.com/julienschmidt/httprouter"
)

var self Microservice
var configService Microservice
var client *http.Client

//MicroMap is used everywhere in this directory
var MicroMap MServices

func init() {
	configService = Microservice{
		Name: "configService",
		IP:   "127.0.0.1",
		Port: "8082",
	}
}

func main() {
	var ad admin
	app := cli.NewApp()
	app.Name = "Facebook"
	app.Usage = "Help people interact with each other wherever they are."
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:        "gmail, g",
			Usage:       "Gmail address used to send emails to users when activating their accounts.",
			Destination: &ad.Gmail,
		},
	}
	app.Action = func(c *cli.Context) error {
		//Gmail account verification
		if ad.Gmail == "" {
			return errors.New("invalid gmail address")
		}
		fmt.Println("Enter password for ", ad.Gmail)
		password, err := terminal.ReadPassword(syscall.Stdin)
		if err != nil {
			return errors.New("failed to read password : " + err.Error())
		}
		err = mailAuth(ad.Gmail, string(password))
		if err != nil {
			return errors.New("failed to authenticate with provided gmail address and password\n" + err.Error())
		}
		fmt.Println("Authentication finished successfully!")
		ad.Password = string(password)

		//setup configuration --> self
		b, err := ioutil.ReadFile("conf.json")
		if err != nil {
			log.Fatalln("failed to read file ", err)
		}
		json.Unmarshal(b, &self)

		MicroMap, err = GetAllServicesConf(configService.BuildURL("http://", ""))
		if err != nil {
			log.Fatalln("failed to get service config : ", err)
		}

		//config check (self == / != MicroMap)
		if MicroMap["accountService"].Port != self.Port {
			log.Fatalln("configuration error")
		}
		//configure tls
		tlsConfig, err := setTLSConfig("pem/Cert.pem", "pem/Key.pem", "./pem/others/")
		if err != nil {
			log.Fatalln(err)
		}

		client = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
				//TLSNextProto:    make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
			},
		}

		//setup server
		mux := httprouter.New()
		serverTLS := http.Server{
			Addr:         self.BuildURL("", ""),
			Handler:      mux,
			TLSConfig:    tlsConfig,
			TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 1),
		}

		err = serverTLS.ListenAndServeTLS("", "")
		return err
	}
	err := app.Run(os.Args)
	if err != nil {
		fmt.Println(err)
	}

}
