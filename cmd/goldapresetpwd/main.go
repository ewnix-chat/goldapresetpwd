package main

import (
	"encoding/json"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"github.com/rs/cors"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"os"
)

type PasswordResetRequest struct {
	Username        string `json:"username"`
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/reset", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
			return
		}

		decoder := json.NewDecoder(r.Body)
		var req PasswordResetRequest
		err := decoder.Decode(&req)
		if err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		ldapServer := os.Getenv("LDAP_SERVER")
		ldapPort := os.Getenv("LDAP_PORT")
		ldapUserDN := os.Getenv("LDAP_USER_DN")

		l, err := ldap.Dial("tcp", fmt.Sprintf("%s:%s", ldapServer, ldapPort))
		if err != nil {
			http.Error(w, "Failed to connect to LDAP server", http.StatusInternalServerError)
			return
		}
		defer l.Close()

		err = l.Bind(fmt.Sprintf("cn=%s,%s", req.Username, ldapUserDN), req.CurrentPassword)
		if err != nil {
			http.Error(w, "Failed to bind to LDAP server", http.StatusUnauthorized)
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Failed to hash new password", http.StatusInternalServerError)
			return
		}

		modifyRequest := ldap.NewModifyRequest(fmt.Sprintf("cn=%s,%s", req.Username, ldapUserDN), nil)
		modifyRequest.Replace("userPassword", []string{fmt.Sprintf("{CRYPT}%s", string(hashedPassword))})
		err = l.Modify(modifyRequest)
		if err != nil {
			http.Error(w, "Failed to update password", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Password updated successfully"))
	})

	handler := cors.New(cors.Options{
		AllowedOrigins: []string{"https://www.ewnix.net"},
		AllowedMethods: []string{"GET", "POST"},
		AllowedHeaders: []string{"Authorization", "Content-Type"},
	}).Handler(mux)

	log.Fatal(http.ListenAndServe(":8080", handler))
}

