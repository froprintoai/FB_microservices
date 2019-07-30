package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/julienschmidt/httprouter"
)

//Microservice is a configuration for each microservice
type Microservice struct {
	Name string `json:"name"`
	IP   string `json:"ip"`
	Port string `json:"port"`
}

var listMicroServices []string
var microservices []Microservice

func init() {
	listMicroServices = []string{"configService", "webClientService", "accountService"}
}

func main() {
	microservices = make([]Microservice, len(listMicroServices))
	for i, name := range listMicroServices {
		b, err := ioutil.ReadFile(name + "Config.json")
		if err != nil {
			log.Fatalf("failed to read a config from %s : %v\n", name, err)
		}
		err = json.Unmarshal(b, &microservices[i])
		if err != nil {
			log.Fatalf("failed to unmarshal %s : %v\n", name, err)
		}
	}

	mux := httprouter.New()
	mux.GET("/", config)
	server := &http.Server{
		Addr:    microservices[0].IP + ":" + microservices[0].Port,
		Handler: mux,
	}
	server.ListenAndServe()
}

func config(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	b, err := json.MarshalIndent(microservices, "", "\t")
	if err != nil {
		log.Fatalln("failed to marshal : ", err)
	}
	w.Write(b)
}
