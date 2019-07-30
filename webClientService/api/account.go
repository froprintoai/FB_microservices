package api

//UserAuth is one of structs for authentication, which is used carefully
type UserAuth struct {
	ID    int64
	UUID  string
	First string
	Last  string
	Email string
	//Password is string data resulted from encrypting (user's password + Salt)
	Password string
	Birthday string
	Salt     string
}

//UserSignup is only in use for signing up new users
type UserSignup struct {
	First, Last      string
	Email            string
	Password         string
	Month, Day, Year string
}

func UserByEmail(email string) (user UserAuth, err error) {

	return
}

func Temp(userData UserSignup) {
	//jsonで送信？
}
