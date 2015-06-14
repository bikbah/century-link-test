package main

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"log"
	"math/big"
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
		Reads(LoginData{})) // from the request

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

	if loginData.Password == "secret" {

		rsaKey, err := rsa.GenerateKey(rand.Reader, 512)
		if err != nil {
			log.Printf("Generating RSA key error: %v\n", err)
			return
		}

		token := jwt.New(jwt.SigningMethodRS256)
		token.Header["kid"] = rsaKey.PublicKey
		token.Claims["exp"] = time.Now().Add(time.Hour * 1).Unix()

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

func secretHandler(request *restful.Request, response *restful.Response) {
	response.Write([]byte("Secret data is here"))
}

func authFilter(request *restful.Request, response *restful.Response, chain *restful.FilterChain) {
	token, err := jwt.ParseFromRequest(request.Request, func(token *jwt.Token) (interface{}, error) {
		keyIface, ok := token.Header["kid"]
		if !ok {
			return nil, errors.New("No key in kid")
		}

		key, ok := keyIface.(map[string]interface{})
		if !ok {
			return nil, errors.New("Type assetion error")
		}

		keyN, ok := key["N"]
		if !ok {
			return nil, errors.New("no N")
		}
		keyE, ok := key["E"]
		if !ok {
			return nil, errors.New("no E")
		}

		N, ok := keyN.(*big.Int)
		if !ok {
			log.Println(keyN)
			return nil, errors.New("type N assert error")
		}
		E, ok := keyE.(int)
		if !ok {
			return nil, errors.New("type E assert error")
		}

		return rsa.PublicKey{N: N, E: E}, nil
	})

	if err == nil && token.Valid {
		log.Println("Token is valid")
	} else {
		log.Println("Token parse error: ", err)
		response.WriteError(http.StatusInternalServerError, errors.New("Auth error"))
		return
	}
	chain.ProcessFilter(request, response)
}
