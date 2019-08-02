package main

import (
	"crypto/tls"
	"encoding/json"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/julienschmidt/httprouter"
)

var loginSignupTemplate *template.Template
var client *http.Client
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
	//config check (self == / != MicroMap)
	if MicroMap["webClientService"].Port != self.Port {
		log.Fatalln("configuration error")
	}

	//set up client for API request over TLS
	tlsConfig, err := setTLSConfig("pem/Cert.pem", "pem/Key.pem", "./pem/others/")
	if err != nil {
		log.Fatalln(err)
	}

	//setup client
	client = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
			TLSNextProto:    make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
		},
	}
	//setup server
	mux := httprouter.New()
	mux.GET("/", home)
	mux.POST("/login", login)
	mux.POST("/signup", signup)
	mux.ServeFiles("/src/*filepath", http.Dir("src"))
	server := &http.Server{
		Addr:    self.BuildURL("", ""),
		Handler: mux,
	}

	server.ListenAndServe()
}
