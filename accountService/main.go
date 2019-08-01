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

		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
				TLSNextProto:    make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
			},
		}

		//setup server
		mux := httprouter.New()
		mux.GET("/test", test)
		server := http.Server{
			Addr:         self.BuildURL("", ""),
			Handler:      mux,
			TLSConfig:    tlsConfig,
			TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 1),
		}

		//TLS Check webClientService ---> accountService
		fmt.Println("test")
		r, err := client.Get(MicroMap["webClientService"].BuildURL("https://", "test"))
		if err != nil {
			log.Fatalln("Failed to connect webClientService over TLS : ", err)
		}
		defer r.Body.Close()
		b, _ = ioutil.ReadAll(r.Body)
		fmt.Println(string(b))

		err = server.ListenAndServeTLS("", "")
		if err != nil {
			fmt.Println("Here2", err)
		}
		return err
	}
	err := app.Run(os.Args)
	if err != nil {
		fmt.Println(err)
	}

}

func test(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	fmt.Fprintln(w, "Hello World! from accountService")
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

func setTLSConfig(certPath, keyPath, othersCert string) (tlsConfig *tls.Config, err error) {
	//prepare certificate to be shown to API servers
	tlsConfig = &tls.Config{}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		err = errors.New("failed to load a pair of key and certificate : " + err.Error())
		return
	}

	//prepare certPool
	certPool := x509.NewCertPool()
	err = fillCertPool(certPool, othersCert)
	if err != nil {
		err = errors.New("failed to fill certPool : " + err.Error())
		return
	}

	//setup tlsConfig
	tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      certPool,
		ClientCAs:    certPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	tlsConfig.BuildNameToCertificate()
	return
}
