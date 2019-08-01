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
	"time"

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
	mux.GET("/test", test)
	mux.GET("/", home)
	mux.POST("/login", login)
	mux.POST("/signup", signup)
	mux.ServeFiles("/src/*filepath", http.Dir("src"))
	serverTLS := &http.Server{
		Addr:         self.BuildURL("", ""),
		Handler:      mux,
		TLSConfig:    tlsConfig,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 1),
	}
	//################################################
	//server.ListenAndServeTLS("", "")
	go func() {
		serverTLS.ListenAndServeTLS("", "")
	}()

	time.Sleep(time.Second * 20)

	//TLS check accountService ---> webClientService
	fmt.Println("test")
	r, err := client.Get(MicroMap["accountService"].BuildURL("https://", "test"))
	if err != nil {
		log.Fatalln("Failed to connect accountService over TLS : ", err)
	}
	defer r.Body.Close()
	b, _ = ioutil.ReadAll(r.Body)
	fmt.Println(string(b))
	//################################################

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
	fmt.Println(micros)
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

func test(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	fmt.Fprintln(w, "Hello from Client over TLS")
}
