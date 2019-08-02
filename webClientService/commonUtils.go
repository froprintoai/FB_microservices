package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
)

//Microservice is a struct used for referring to configuration of other services
type Microservice struct {
	Name string `json:"name"`
	IP   string `json:"ip"`
	Port string `json:"port"`
}

type admin struct {
	Gmail    string
	Password string
}

//MServices is easier to access by enabling coders to access by name
type MServices map[string]*Microservice

//ParseIntoMap converts a slice of Microservice into MService, which is easier to access
func ParseIntoMap(micros []Microservice) (m MServices) {
	m = make(MServices, len(micros))
	for i := 0; i < len(micros); i++ {
		m[micros[i].Name] = &micros[i]
	}
	return
}

//BuildURL returns a full URL such as https://127.0.0.1:8080/admin
func (m *Microservice) BuildURL(suffix, remain string) string {
	if remain != "" {
		remain = "/" + remain
	}
	return suffix + m.IP + ":" + m.Port + remain
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
