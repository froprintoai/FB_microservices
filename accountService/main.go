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

	"github.com/julienschmidt/httprouter"
)

type admin struct {
	Gmail    string
	Password string
}

//Microservice is a struct used for referring to configuration of other services
type Microservice struct {
	Name string `json:"name"`
	IP   string `json:"ip"`
	Port string `json:"port"`
}

var self Microservice
var configService Microservice

//Microservices is for storing configs of every microservices available
var Microservices []Microservice

func init() {
	configService = Microservice{
		Name: "configService",
		IP:   "127.0.0.1",
		Port: "8082",
	}
}

func main() {
	//prepare configuration
	b, err := ioutil.ReadFile("conf.json")
	if err != nil {
		log.Fatalln("Failed to read from config file : ", err)
	}
	json.Unmarshal(b, &self)

	//set up Microservices (get every configuratons of microservices available)
	resp, err := http.Get("http://" + configService.IP + ":" + configService.Port)
	if err != nil {
		log.Fatalln("failed to connect configService : ", err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln("failed to read body : ", err)
	}
	err = json.Unmarshal(body, &Microservices)
	if err != nil {
		log.Fatalln("failed to unmarshal : ", err)
	}
	fmt.Println(Microservices)

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
		Addr:      self.IP + ":" + self.Port,
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	err = server.ListenAndServeTLS("", "")
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
