package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"
)

type configuration struct {
	IP       string `json:"ip"`
	Port     string `json:"port"`
	Gmail    string
	Password string
}

//Microservice is a struct used for referring to configuration of other services
type Microservice struct {
	Name string `json:"name"`
	IP   string `json:"ip"`
	Port string `json:"port"`
}

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

	for i, service := range Microservices {
		if i == 0 { //ignore configService because it doesn't use TLS
			continue
		}
		locatePEMFile(&service, Microservices, i)
	}
}

//locatePEMFile locates pem files of private key and certificate of a service in its pem directory
//and locates only certificate in pem directories of other services
func locatePEMFile(service *Microservice, allServices []Microservice, num int) {
	Key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("failed to create private Key for %s : %v\n", service.Name, err)
	}
	KeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(Key),
	})
	CertTmpl, err := CertTemplate(service.Name)
	if err != nil {
		log.Fatalf("failed to create certificate template for %s : %v\n", service.Name, err)
	}
	CertTmpl.IPAddresses = []net.IP{net.ParseIP(service.IP)}

	_, CertPEM, err := CreateCert(CertTmpl, CertTmpl, &Key.PublicKey, Key)
	if err != nil {
		log.Fatalf("failed to create certificate PEM for %s : %v\n", service.Name, err)
	}
	createPEMFile(service.Name+"/pem/Key.pem", KeyPEM)
	createPEMFile(service.Name+"/pem/Cert.pem", CertPEM)
	for i, v := range allServices {
		if i == 0 || i == num { //ignore configService and its own turn
			continue
		}
		createPEMFile(v.Name+"/pem/others/"+service.Name+"Cert.pem", CertPEM)
	}

}

//CertTemplate create Certifiate Template with organization name set to its Subject field
func CertTemplate(orgName string) (*x509.Certificate, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, errors.New("failed to generate serial number : " + err.Error())
	}

	tmpl := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{Organization: []string{orgName}},
		SignatureAlgorithm:    x509.SHA256WithRSA,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365), // valid for a year
		BasicConstraintsValid: true,
	}
	return &tmpl, nil
}

func readConfig(filepath string) (*configuration, error) {
	conf := configuration{}
	confFile, err := os.Open(filepath)
	if err != nil {
		err = errors.New("Failed to open " + filepath)
		return &conf, err
	}
	defer confFile.Close()
	b, err := ioutil.ReadAll(confFile)
	if err != nil {
		err = errors.New("Failed to read from " + filepath)
		return &conf, err
	}
	json.Unmarshal(b, &conf)
	return &conf, err
}

//CreateCert creates Certificate and return it in two forms (DER&PEM)
func CreateCert(template, parent *x509.Certificate, pub interface{}, parentPriv interface{}) (cert *x509.Certificate, certPEM []byte, err error) {

	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, pub, parentPriv)
	if err != nil {
		return
	}
	// parse the resulting certificate so we can use it again
	cert, err = x509.ParseCertificate(certDER)
	if err != nil {
		return
	}
	// PEM encode the certificate (this is a standard TLS encoding)
	b := pem.Block{Type: "CERTIFICATE", Bytes: certDER}
	certPEM = pem.EncodeToMemory(&b)
	return
}

func createPEMFile(filename string, data []byte) {
	file, err := os.Create(filename)
	if err != nil {
		log.Fatalf("Failed to create file %s : %v\n", filename, err)
	}
	defer file.Close()
	_, err = file.Write(data)
	if err != nil {
		log.Fatalf("Failed to write to file %s : %v\n", filename, err)
	}
}
