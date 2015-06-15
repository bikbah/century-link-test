package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io/ioutil"
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

func RegisterServices(container *restful.Container) {
	ws := new(restful.WebService)
	ws.
		Path("/login").
		Doc("Manage login").
		Consumes(restful.MIME_JSON)

	ws.Route(ws.POST("").To(login).
		Reads(LoginData{}))

	wsSecret := new(restful.WebService)
	wsSecret.Route(wsSecret.GET("/secret").Filter(authFilter).To(secretHandler))

	container.Add(ws)
	container.Add(wsSecret)
}

func login(request *restful.Request, response *restful.Response) {
	loginData := new(LoginData)
	if err := request.ReadEntity(loginData); err != nil {
		response.AddHeader("Content-Type", "text/plain")
		response.WriteErrorString(http.StatusInternalServerError, err.Error())
		return
	}

	if loginData.Password != "secret" {
		response.AddHeader("Content-Type", "text/plain")
		response.WriteErrorString(http.StatusUnauthorized, "Invalid login or password..")
		return
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		log.Printf("Generating RSA key error: %v\n", err)
		return
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		log.Printf("Getting PublicKey bytes error: %v\n", err)
		return
	}

	token := jwt.New(jwt.SigningMethodRS256)
	token.Header["kid"] = base64.StdEncoding.EncodeToString(pubKeyBytes)
	token.Claims["exp"] = time.Now().Add(time.Minute * 1).Unix()

	tokenString, err := token.SignedString(rsaKey)
	if err != nil {
		log.Printf("Token signing error: %v\n", err)
		response.AddHeader("Content-Type", "text/plain")
		response.WriteErrorString(http.StatusInternalServerError, err.Error())
		return
	}

	resBody := `{"access_token":"` + tokenString + `"}`
	response.Write([]byte(resBody))

	if err := ioutil.WriteFile("token", []byte(tokenString), 0644); err != nil {
		log.Printf("Write token file error: %v\n", err)
		return
	}
}

func secretHandler(request *restful.Request, response *restful.Response) {
	response.Write([]byte("Secret data is here"))
}

func authFilter(request *restful.Request, response *restful.Response, chain *restful.FilterChain) {
	token, err := jwt.ParseFromRequest(request.Request, func(token *jwt.Token) (interface{}, error) {
		keyIface, ok := token.Header["kid"]
		if !ok {
			return nil, errors.New("No key in kid")
		}

		keyStr, ok := keyIface.(string)
		if !ok {
			return nil, errors.New("interface{} to string assertion error..")
		}

		keyBytes, err := base64.StdEncoding.DecodeString(keyStr)
		if err != nil {
			return nil, errors.New("Decode base64 string to []bytes error..")
		}

		return x509.ParsePKIXPublicKey(keyBytes)
	})

	if !(err == nil && token.Valid) {
		log.Println("Token parse error: ", err)
		response.WriteError(http.StatusInternalServerError, errors.New("Auth fail.."))
		return
	}

	chain.ProcessFilter(request, response)
}
