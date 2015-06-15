package main

import (
	"encoding/base64"
	"net/http"

	"golang.org/x/crypto/bcrypt"

	"github.com/emicklei/go-restful"
	"github.com/gocql/gocql"
)

// User is simple struct to be stored in Cassandra (see specific Id of User).
type User struct {
	Id       gocql.UUID
	Login    string `json:"login"`
	Password string `json:"password"`
}

//RegisterUserWS adds to container new restful.WebService implementing REST API for /users
func RegisterUserWS(container *restful.Container) {
	ws := new(restful.WebService)
	ws.
		Path("/users").
		Doc("Manage Users").
		Consumes(restful.MIME_JSON).
		Produces(restful.MIME_JSON)

	ws.Route(ws.GET("/{user-login}").To(findUser).
		Doc("get a user").
		Operation("findUser").
		Param(ws.PathParameter("user-login", "login of the user").DataType("string")).
		Writes(User{}))

	ws.Route(ws.POST("").To(createUser).
		Doc("create a user").
		Operation("createUser").
		Reads(User{}))

	container.Add(ws)
}

// GET http://localhost:8080/users/bah
func findUser(request *restful.Request, response *restful.Response) {
	login := request.PathParameter("user-login")

	usr := User{Login: login}

	if err := DbSession.Query(`SELECT id, password FROM users WHERE login = ? LIMIT 1`,
		usr.Login).Consistency(gocql.One).Scan(&usr.Id, &usr.Password); err != nil {
		response.AddHeader("Content-Type", "text/plain")
		response.WriteErrorString(http.StatusInternalServerError, err.Error())
		return
	}

	response.WriteEntity(usr)
}

// POST http://localhost:8080/users
// {
// 		"login": "myLogin",
// 		"password": "myPassword"
// }
func createUser(request *restful.Request, response *restful.Response) {
	usr := new(User)
	err := request.ReadEntity(usr)
	if err != nil {
		response.AddHeader("Content-Type", "text/plain")
		response.WriteErrorString(http.StatusInternalServerError, err.Error())
		return
	}

	usr.Id = gocql.TimeUUID()
	passwordBytes, err := bcrypt.GenerateFromPassword([]byte(usr.Password), 10)
	if err != nil {
		response.AddHeader("Content-Type", "text/plain")
		response.WriteErrorString(http.StatusInternalServerError, err.Error())
		return
	}

	usr.Password = base64.StdEncoding.EncodeToString(passwordBytes)

	if err := DbSession.Query(`INSERT INTO users (dkey, id, login, password) VALUES (?, ?, ?, ?)`,
		"users", usr.Id, usr.Login, usr.Password).Exec(); err != nil {
		response.AddHeader("Content-Type", "text/plain")
		response.WriteErrorString(http.StatusInternalServerError, err.Error())
		return
	}

	response.WriteHeader(http.StatusCreated)
	response.WriteEntity(usr)
}
