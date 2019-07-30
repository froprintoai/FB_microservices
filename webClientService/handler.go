package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"log"
	"net/http"

	"github.com/froprintoai/FB_microservices/webClientService/api"

	"github.com/julienschmidt/httprouter"
)

func home(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	if _, err := r.Cookie("_cookie"); err != nil {
		loginSignup(w, r)
	} else {

	}
}

func loginSignup(w http.ResponseWriter, r *http.Request) {
	var b bytes.Buffer
	err := loginSignupTemplate.ExecuteTemplate(w, "loginSignup", nil)
	if err != nil {
		fmt.Fprint(w, "An error occured.")
		return
	}
	b.WriteTo(w)
}

func login(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	if err := r.ParseForm(); err != nil {
		loginSignup(w, r)
		log.Println("failed to parse post forms. : ", err)
		return
	}
	email := r.PostFormValue("email")
	user, err := api.UserByEmail(email)
	if err != nil {
		loginSignup(w, r)
		return
	}
	combinedBytes := []byte(r.PostFormValue("password") + user.Salt)
	encrypted := fmt.Sprintf("%x", sha256.Sum256(combinedBytes))
	if encrypted == user.Password {
		setCookie(user.UUID, w)
		http.Redirect(w, r, "/", 301)
	}
}

func signup(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	userData := api.UserSignup{}
	if err := r.ParseForm(); err != nil {
		log.Println("signup : failed to parse post forms : ", err)
		loginSignup(w, r)
		return
	}
	userData.First = r.PostFormValue("first")
	userData.Last = r.PostFormValue("last")
	userData.Email = r.PostFormValue("email")
	userData.Password = r.PostFormValue("password")
	userData.Month = r.PostFormValue("month")
	userData.Day = r.PostFormValue("day")
	userData.Year = r.PostFormValue("year")

	if msg, f := checkValidInput(&userData); f == true {
		api.Temp(userData)
		//generate UUID
		//encrypt password and create salt (userData.password)
		//generate activation code
		//create activation file (userData, activationCode, encrypted_pass, salt)
		//create URL (usermail, )
		//send an email to user

		/*以上の処理はaccountServiceでやるのが自然


		//generate UUID
		var err error
		userData.uuid, err = createUUID()
		if err != nil {
			//Need to be modified to show an custim error page
			mylog.LogWTF("Cannot Create UUID : ", err)
		}
		//encrypt password
		encrypted_pass, salt := encryptPassword(userData.password)
		//send an email(auth file activation)
		//create Activation Code
		activation_code, err := createACode()
		if err != nil {
			//Need to be modified to show an custim error page
			mylog.LogWTF("Cannot create activation code", err)
		}
		//create temporary File
		err = createTempFile(userData, activation_code, encrypted_pass, salt)
		if err != nil {
			//Need to be modified to show an custim error page
			mylog.LogWTF("cannot create file", err)
		}
		//create mail
		url := createURL(userData.email, activation_code)
		err = sendMail(url, userData.email)
		if err != nil {
			//Need to be modified to show an custim error page
			mylog.LogWTF("there is an error when sending an mail", err)
		}
		*/
		//show the mail-sent page
		fmt.Fprintf(w, "We sent an email to %s. In order to finish registration, please access to an URL attached to the email in 30 minutes.", userData.Email)
	} else {
		var b bytes.Buffer
		err := loginSignupTemplate.ExecuteTemplate(w, "loginSignup", msg)
		if err != nil {
			fmt.Fprintln(w, "An error occured. Please access to homepage again.")
			return
		}
		b.WriteTo(w)
	}
}
