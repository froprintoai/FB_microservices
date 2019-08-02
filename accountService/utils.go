package main

import (
	"crypto/tls"
	"net/smtp"
)

type admin struct {
	Gmail    string
	Password string
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
