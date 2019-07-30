package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"syscall"

	"github.com/urfave/cli"
	"golang.org/x/crypto/ssh/terminal"

	"github.com/julienschmidt/httprouter"
)

var loginSignupTemplate *template.Template

var self Microservice
var configService Microservice

//MicroMap is used everywhere in this directory
var MicroMap MServices

func init() {
	loginSignupTemplate = template.Must(template.ParseFiles("templates/loginSignup.html"))
	configService = Microservice{
		Name: "configService",
		IP:   "127.0.0.1",
		Port: "8082",
	}
}

func main() {

	//setup configuration --> self
	b, err := ioutil.ReadFile("conf.json")
	if err != nil {
		log.Fatalln("failed to read file ", err)
	}
	json.Unmarshal(b, &self)

	//set up Microservices (get every configuratons of microservices available)
	MicroMap, err = GetAllServicesConf(configService.BuildURL("http://", ""))
	if err != nil {
		log.Fatalln("failed to get service config : ", err)
	}

	//set up client for API request over TLS
	//prepare certificate to be shown to API servers
	cert, err := tls.LoadX509KeyPair("pem/Cert.pem", "pem/Key.pem")
	if err != nil {
		log.Fatalln("failed to load a pair of key and certificate : ", err)
	}

	//prepare certPool
	certPool := x509.NewCertPool()
	err = fillCertPool(certPool, "./pem/others/")
	if err != nil {
		log.Fatalln("failed to fill certPool : ", err)
	}

	//setup tlsConfig
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      certPool,
	}
	//configure client
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

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

		url := MicroMap["accountService"].BuildURL("https://", "admin")
		r, err := client.Get(url)
		if err != nil {
			log.Fatalln("failed to connect account service.")
		}
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			log.Fatal(err)
		}
		defer r.Body.Close()
		fmt.Printf("%s\n", body)

		mux := httprouter.New()
		mux.GET("/", home)
		mux.POST("/login", login)
		mux.POST("/signup", signup)
		mux.ServeFiles("/src/*filepath", http.Dir("src"))

		server := http.Server{
			Addr:    self.BuildURL("", ""),
			Handler: mux,
		}
		return server.ListenAndServe()
	}

	err = app.Run(os.Args)
	if err != nil {
		fmt.Println(err)
	}
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
