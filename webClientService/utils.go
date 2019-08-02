package main

import (
	"net/http"
	"strconv"

	"github.com/froprintoai/FB_microservices/webClientService/api"
)

func setCookie(uuid string, w http.ResponseWriter) {
	cookie := http.Cookie{
		Name:     "_cookie",
		Value:    uuid,
		Domain:   "127.0.0.1",
		Path:     "/",
		HttpOnly: true,
	}
	http.SetCookie(w, &cookie)
}

func checkValidInput(userData *api.UserSignup) (msg string, f bool) {
	//check 1.every input has value except for and birthday
	if userData.First == "" || userData.Last == "" || userData.Password == "" || userData.Email == "" {
		msg = "There is a problem in name, password, or email."
		return
	}
	//check 1a. birthday
	day, err1 := strconv.Atoi(userData.Day)
	year, err2 := strconv.Atoi(userData.Year)
	if err1 != nil || err2 != nil {
		msg = "day or year is not the number"
		return
	} else if day < 1 || day > 31 || year < 0 { //It's desirable to check if the date really exists
		msg = "day and year are numbers but it's not valid for birthday"
		return
	}
	//2.password has 8 characters or more
	if len(userData.Password) < 8 {
		msg = "password should be 8 or more"
		return
	}
	//3.there is not the same email address in DB
	_, err := api.UserByEmail(userData.Email)
	if err == nil {
		msg = "There is already a user with the email address"
		return
	}
	f = true
	return
}
