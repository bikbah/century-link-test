package main

import (
	"crypto/rand"
	"crypto/rsa"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/emicklei/go-restful"
)

type LoginData struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

func RegisterLoginService(container *restful.Container) {
	ws := new(restful.WebService)
	ws.
		Path("/login").
		Doc("Manage login").
		Consumes(restful.MIME_JSON)

	ws.Route(ws.POST("").To(login).
		Reads(LoginData{})) // from the request

	container.Add(ws)
}

func login(request *restful.Request, response *restful.Response) {
	loginData := new(LoginData)
	if err := request.ReadEntity(loginData); err != nil {
		response.AddHeader("Content-Type", "text/plain")
		response.WriteErrorString(http.StatusInternalServerError, err.Error())
		return
	}

	if loginData.Password == "secret" {

		rsaKey, err := rsa.GenerateKey(rand.Reader, 512)
		if err != nil {
			log.Printf("Generating RSA key error: %v\n", err)
		}

		//key := []byte("secret")
		token := jwt.New(jwt.SigningMethodRS256)
		token.Claims["exp"] = time.Now().Add(time.Second * 30).Unix()

		tokenString, err := token.SignedString(rsaKey)
		if err != nil {
			log.Printf("Token signing error: %v\n", err)
			response.AddHeader("Content-Type", "text/plain")
			response.WriteErrorString(http.StatusInternalServerError, err.Error())
			return
		}

		response.AddHeader("Authorization", "Access token: "+tokenString)
		response.Write([]byte("see token in headers.."))
	} else {
		response.AddHeader("Content-Type", "text/plain")
		response.WriteErrorString(http.StatusUnauthorized, "Authorization fail.")
	}
}
