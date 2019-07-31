package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"syscall"

	"github.com/urfave/cli"
	"golang.org/x/crypto/ssh/terminal"

	"github.com/julienschmidt/httprouter"
)

var self Microservice
var configService Microservice

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
		//register handler
		mux := httprouter.New()
		mux.GET("/admin", adminRegister)

		//configure tls
		cert, err := tls.LoadX509KeyPair("pem/Cert.pem", "pem/Key.pem")
		if err != nil {
			log.Fatalln("failed to create cert : ", err)
		}

		certPool := x509.NewCertPool()
		err = fillCertPool(certPool, "./pem/others/")
		if err != nil {
			log.Fatalln("failed to fill certPool : ", err)
		}

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientCAs:    certPool,
			ClientAuth:   tls.RequireAndVerifyClientCert,
		}
		tlsConfig.BuildNameToCertificate()

		//configure server
		server := http.Server{
			Addr:      self.BuildURL("", ""),
			Handler:   mux,
			TLSConfig: tlsConfig,
		}

		return server.ListenAndServeTLS("", "")
	}
	err := app.Run(os.Args)
	if err != nil {
		fmt.Println(err)
	}

}

func adminRegister(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	fmt.Fprintln(w, "Hello World!")
}

func fillCertPool(certPool *x509.CertPool, filepath string) (err error) {
	files, err := ioutil.ReadDir(filepath)
	if err != nil {
		return
	}
	for _, f := range files {
		path := filepath + f.Name()
		cert, err := ioutil.ReadFile(path)
		if err != nil {
			return errors.New("failed to read " + path + " : " + err.Error())
		}
		certPool.AppendCertsFromPEM(cert)
	}
	return

}

func mailAuth(address, password string) error {
	auth := smtp.PlainAuth(
		"",
		address,
		password,
		"smtp.gmail.com",
	)
	client, err := smtp.Dial("smtp.gmail.com:587")
	if err != nil {
		return err
	}
	err = client.StartTLS(&tls.Config{ServerName: "smtp.gmail.com"})
	if err != nil {
		return err
	}
	err = client.Auth(auth)
	if err != nil {
		return err
	}

	err = client.Mail(address)

	return err
}

//GetAllServicesConf gets configurations from url, which is supposed
//to point to configService
func GetAllServicesConf(url string) (m MServices, err error) {
	micros := []Microservice{}
	resp, err := http.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	err = json.Unmarshal(body, &micros)
	if err != nil {
		return
	}
	//set up MicroMap for later convenient use
	m = ParseIntoMap(micros)
	return
}
