package main

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
	for _, v := range micros {
		m[v.Name] = &v
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
