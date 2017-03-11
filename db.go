package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"

	jwt "github.com/dgrijalva/jwt-go"
	_ "github.com/lib/pq"
)

type CustomClaims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

const (
	user   = "tsingh"
	dbname = "postgres"
)

var db *sql.DB
var err error
var jwtKey = []byte("secret")

func main() {

	psqlInfo := fmt.Sprintf("user=%s "+
		"dbname=%s sslmode=disable",
		user, dbname)

	db, err = sql.Open("postgres", psqlInfo)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		panic(err)
	}
	fmt.Println("Successfully connected!")

	fmt.Println("# Querying")
	rows, err := db.Query("SELECT * FROM \"user\"")
	if err != nil {
		panic(err)
	}

	for rows.Next() {
		var id int
		var username string
		var password string
		var email string
		err = rows.Scan(&id, &username, &password, &email)
		if err != nil {
			panic(err)
		}
		fmt.Println("id | username | password | email ")
		fmt.Printf("%3v | %8v | %6v | %6v\n", id, username, password, email)
	}

	http.HandleFunc("/login", loginFunc)
	http.HandleFunc("/register", registerFunc)
	http.HandleFunc("/get-token", GetTokenHandler)
	log.Print("running on port 8080")
	log.Fatal(http.ListenAndServe(":8080", nil))

}

func queryDB(query string) (rows *sql.Rows, err error) {
	return db.Query(query)
}

func loginFunc(w http.ResponseWriter, r *http.Request) {
	var message string
	if r.Method == "GET" {
		message = "<h1>Login</h1>" +
			"<form action=\"/login\" method=\"post\">" +
			"Username:<br>" +
			"<input type=\"text\" name=\"username\"><br>" +
			"Password:<br>" +
			"<input type=\"password\" name=\"password\"><br>" +
			"<input type=\"submit\" value=\"Submit\">" +
			"</form>"
	} else {
		if ValidUser(r.FormValue("username"), r.FormValue("password")) {
			message = "you have been logged in"
		} else {
			message = "there was a problem logging you in"
		}
	}
	w.Write([]byte(message))
}

func registerFunc(w http.ResponseWriter, r *http.Request) {
	var message string
	if r.Method == "GET" {
		message = "<h1>Register</h1>" +
			"<form action=\"/register\" method=\"post\">" +
			"Username:<br>" +
			"<input type=\"text\" name=\"username\"><br>" +
			"Password:<br>" +
			"<input type=\"password\" name=\"password\"><br>" +
			"Email:<br>" +
			"<input type=\"text\" name=\"email\"><br>" +
			"<input type=\"submit\" value=\"Submit\">" +
			"</form>"
	} else {
		hash, err := HashPassword(r.FormValue("password"))
		s := fmt.Sprintf("insert into \"user\"(username, password, email) values ('%s', '%s', '%s')", r.FormValue("username"), hash, r.FormValue("email"))
		_, err = db.Exec(s)
		if err != nil {
			message = "there was an unexpected error: " + err.Error()
		} else {
			message = "successfully registered"
		}
	}
	w.Write([]byte(message))
}

func ValidUser(username string, password string) bool {
	var hash string
	db.QueryRow("SELECT password FROM \"user\" WHERE username = '" + username + "'").Scan(&hash)
	return CheckPasswordHash(password, hash)
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

//GetTokenHandler will get a token for the username and password
func GetTokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.Write([]byte("Method not allowed"))
		return
	}

	r.ParseForm()
	username := r.Form.Get("username")
	password := r.Form.Get("password")
	log.Println(username, " ", password)
	if username == "" || password == "" {
		w.Write([]byte("Invalid Username or password"))
		return
	}
	if ValidUser(username, password) {
		/* Set token claims */

		// Create the Claims
		claims := CustomClaims{
			username,
			jwt.StandardClaims{
				ExpiresAt: time.Now().Add(time.Hour * 5).Unix(),
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

		/* Sign the token with our secret */
		tokenString, err := token.SignedString(jwtKey)
		if err != nil {
			log.Println("Something went wrong with signing token")
			w.Write([]byte("Authentication failed"))
			return
		}

		/* Finally, write the token to the browser window */
		w.Write([]byte(tokenString))
	} else {
		w.Write([]byte("Authentication failed"))
	}
}

//ValidateToken will validate the token
func ValidateToken(myToken string) (bool, string) {
	token, err := jwt.ParseWithClaims(myToken, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(jwtKey), nil
	})

	if err != nil {
		return false, ""
	}

	claims := token.Claims.(*CustomClaims)
	return token.Valid, claims.Username
}
