package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/davecgh/go-spew/spew"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID       int    `json:"id"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type JWT struct {
	Token string `json:"token"`
}

type Error struct {
	Message string `json:"message"`
}

var db *sql.DB

func main() {

	pgURL, err := pq.ParseURL("postgres://hpkehkao:laBfifXVkyYSb4pKTtLZLAzk8uVPcE5g@arjuna.db.elephantsql.com:5432/hpkehkao")

	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(db)

	db, err = sql.Open("postgres", pgURL)

	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(db)

	err = db.Ping()

	router := mux.NewRouter()
	router.HandleFunc("/signup", signup).Methods("POST")
	router.HandleFunc("/login", login).Methods("POST")
	router.HandleFunc("/protected", TokenVerifyMiddleWare(protectedEndPoint)).Methods("GET")

	log.Println("Listen on port 8080")
	log.Fatal(http.ListenAndServe(":8080", router))
}

func reponsedWithError(w http.ResponseWriter, status int, error Error) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(error)
}

func responseJSON(w http.ResponseWriter, data interface{}) {
	json.NewEncoder(w).Encode(data)
}

func signup(w http.ResponseWriter, r *http.Request) {
	// w.Write([]byte("successfully called signup"))
	fmt.Println("signup invoked.")
	var user User
	var error Error
	json.NewDecoder(r.Body).Decode(&user)

	if user.Email == "" {
		error.Message = "Email is required."
		reponsedWithError(w, http.StatusBadRequest, error)
		return
	}

	if user.Password == "" {
		error.Message = "Password is required."
		reponsedWithError(w, http.StatusBadRequest, error)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 10)

	if err != nil {
		log.Fatal(err)
	}

	user.Password = string(hash)

	stmt := "insert into users (email, password) values($1, $2) RETURNING id;"
	err = db.QueryRow(stmt, user.Email, user.Password).Scan(&user.ID)

	if err != nil {
		error.Message = "Server error"
		reponsedWithError(w, http.StatusInternalServerError, error)
		return
	}

	user.Password = ""
	w.Header().Set("Content-Type", "application/json")
	responseJSON(w, user)

}

func generateToken(user User) (string, error) {
	var err error
	secret := "secret"

	// a jwt
	//header.payload.secret
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": user.Email,
		"iss":   "course",
	})

	spew.Dump(token)
	tokenString, err := token.SignedString([]byte(secret))

	if err != nil {
		log.Fatal(err)
	}
	return tokenString, nil
}

func login(w http.ResponseWriter, r *http.Request) {

	var user User
	// var jwt JWT
	var error Error

	json.NewDecoder(r.Body).Decode(&user)

	// token, err := generateToken(user)

	// if err != nil {
	// 	log.Fatal(err)
	// }

	// password := user.Password

	row := db.QueryRow("select * from users where email=$1", user.Email)
	err := row.Scan(&user.ID, &user.Email, &user.Password)

	if err != nil {
		if err == sql.ErrNoRows {
			error.Message = "The user does not exist"
			reponsedWithError(w, http.StatusBadRequest, error)
			return
		} else {
			log.Fatal(err)
		}
	}

	spew.Dump(user)

}

func protectedEndPoint(w http.ResponseWriter, r *http.Request) {
	fmt.Println("protectedEndPoint invoked.")
}

func TokenVerifyMiddleWare(next http.HandlerFunc) http.HandlerFunc {
	fmt.Println("TokenVerifyMiddleWar invoked.")
	return nil
}
