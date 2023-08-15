package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"github.com/go-ldap/ldap/v3"
	"github.com/rs/cors"
	"golang.org/x/crypto/bcrypt"
)

type ResetPasswordRequest struct {
	Username       string `json:"username"`
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
}

func hashPassword(password string) string {
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hashedPassword)
}

func resetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ResetPasswordRequest
	json.NewDecoder(r.Body).Decode(&req)

	ldapServer := os.Getenv("LDAP_SERVER")
	ldapPort := os.Getenv("LDAP_PORT")
	ldapUserDN := os.Getenv("LDAP_USER_DN")

	l, _ := ldap.Dial("tcp", ldapServer+":"+ldapPort)
	defer l.Close()

	bindDN := "cn=" + req.Username + "," + ldapUserDN
	l.Bind(bindDN, req.CurrentPassword)

	modifyRequest := ldap.NewModifyRequest(bindDN, nil)
	modifyRequest.Replace("userPassword", []string{hashPassword(req.NewPassword)})
	l.Modify(modifyRequest)

	w.WriteHeader(http.StatusOK)
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/reset", resetPasswordHandler)

	handler := cors.New(cors.Options{
		AllowedOrigins:   []string{"https://www.ewnix.net"},
		AllowedMethods:   []string{"GET", "POST"},
		AllowedHeaders:   []string{"Authorization", "Content-Type"},
		AllowCredentials: true,
	}).Handler(mux)

	log.Fatal(http.ListenAndServe(":8080", handler))
}

