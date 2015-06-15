package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"path"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/dgrijalva/jwt-go"
	"github.com/emicklei/go-restful"
)

// LoginData is simple struct used when Signing In
type LoginData struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

// RegisterServices adds to container WebServices for several routes:
// 1. /login used to sign in and get token
// 2. /public is open for everyone
// 3. /secret is filtered by authFilter. It is open only to authenticated users
// 4. /static is used to show indexx.html. See staticHandler comments.
func RegisterServices(container *restful.Container) {
	ws := new(restful.WebService)
	ws.
		Path("/login").
		Doc("Manage login").
		Consumes(restful.MIME_JSON)

	ws.Route(ws.POST("").To(login).
		Reads(LoginData{}))

	wsOthers := new(restful.WebService)
	wsOthers.Route(wsOthers.GET("/secret").Filter(authFilter).To(secretHandler))
	wsOthers.Route(wsOthers.GET("/public").To(publicHandler))
	wsOthers.Route(wsOthers.GET("/static/{subpath:*}").To(staticHandler))

	container.Add(ws)
	container.Add(wsOthers)
}

// login handler checks if Login/Password are valid
// and returns access token if everything is ok
func login(request *restful.Request, response *restful.Response) {
	loginData := new(LoginData)
	if err := request.ReadEntity(loginData); err != nil {
		log.Printf("Read LoginData entity error: %v\n", err)
		response.AddHeader("Content-Type", "text/plain")
		response.WriteErrorString(http.StatusInternalServerError, err.Error())
		return
	}

	usr, ok := getUser(loginData.Login)
	if !ok {
		response.AddHeader("Content-Type", "text/plain")
		response.WriteErrorString(http.StatusInternalServerError, "No user found")
		return
	}

	hashedPassword, err := base64.StdEncoding.DecodeString(usr.Password)
	if err != nil {
		response.AddHeader("Content-Type", "text/plain")
		response.WriteErrorString(http.StatusInternalServerError, err.Error())
		return
	}

	if err := bcrypt.CompareHashAndPassword(hashedPassword, []byte(loginData.Password)); err != nil {
		response.AddHeader("Content-Type", "text/plain")
		response.WriteErrorString(http.StatusUnauthorized, "Invalid login or password..")
		return
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		response.AddHeader("Content-Type", "text/plain")
		response.WriteErrorString(http.StatusInternalServerError, err.Error())
		return
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		response.AddHeader("Content-Type", "text/plain")
		response.WriteErrorString(http.StatusInternalServerError, err.Error())
		return
	}

	token := jwt.New(jwt.SigningMethodRS256)
	token.Header["kid"] = base64.StdEncoding.EncodeToString(pubKeyBytes)
	token.Claims["exp"] = time.Now().Add(time.Minute * 5).Unix()

	tokenString, err := token.SignedString(rsaKey)
	if err != nil {
		log.Printf("Token signing error: %v\n", err)
		response.AddHeader("Content-Type", "text/plain")
		response.WriteErrorString(http.StatusInternalServerError, err.Error())
		return
	}

	resBody := `{"access_token":"` + tokenString + `"}`
	response.Write([]byte(resBody))

	// if err := ioutil.WriteFile("token", []byte(tokenString), 0644); err != nil {
	// 	log.Printf("Write token file error: %v\n", err)
	// 	return
	// }
}

// secretHandler is protected by authFilter.
func secretHandler(request *restful.Request, response *restful.Response) {
	response.Write([]byte("Secret data is here"))
}

// publicHandler is not protected. Everyone can acces this.
func publicHandler(request *restful.Request, response *restful.Response) {
	response.Write([]byte("Public data is here. Everyone can see this."))
}

// authFilter gets raw token from request header ("Authorization": "Bearer ..."),
// parses it. If token exists and valid, gives access to next handler.
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

// staticHandler serves static files from ./static direstory.
// 1. Open http://localhost:8080/static/indexx.html in your browser.
// 2. Enter your Login/Password pair and click "Sign In"
// 3. Copy access token and paste into Token field.
// 4. Press "See secret handler"
// 5. You will see secret handler response body
func staticHandler(req *restful.Request, resp *restful.Response) {
	rootdir := "static"

	actual := path.Join(rootdir, req.PathParameter("subpath"))
	fmt.Printf("serving %s ... (from %s)\n", actual, req.PathParameter("subpath"))
	http.ServeFile(
		resp.ResponseWriter,
		req.Request,
		actual)
}
