package main

import (
	"encoding/base64"
	"net/http"

	"golang.org/x/crypto/bcrypt"

	"github.com/emicklei/go-restful"
	"github.com/gocql/gocql"
)

type User struct {
	Id       gocql.UUID
	Login    string `json:"login"`
	Password string `json:"password"`
}

type UserResource struct {
	// normally one would use DAO (data access object)
	users map[string]User
}

func (u UserResource) RegisterUserWS(container *restful.Container) {
	ws := new(restful.WebService)
	ws.
		Path("/users").
		Doc("Manage Users").
		Consumes(restful.MIME_JSON).
		Produces(restful.MIME_JSON) // you can specify this per route as well

	ws.Route(ws.GET("/{user-login}").To(u.findUser).
		Doc("get a user").
		Operation("findUser").
		Param(ws.PathParameter("user-login", "login of the user").DataType("string")).
		Writes(User{})) // on the response

	ws.Route(ws.PUT("/{user-id}").To(u.updateUser).
		Doc("update a user").
		Operation("updateUser").
		Param(ws.PathParameter("user-id", "identifier of the user").DataType("string")).
		ReturnsError(409, "duplicate user-id", nil).
		Reads(User{})) // from the request

	ws.Route(ws.POST("").To(u.createUser).
		Doc("create a user").
		Operation("createUser").
		Reads(User{})) // from the request

	ws.Route(ws.DELETE("/{user-id}").To(u.removeUser).
		Doc("delete a user").
		Operation("removeUser").
		Param(ws.PathParameter("user-id", "identifier of the user").DataType("string")))

	container.Add(ws)
}

// GET http://localhost:8080/users/bah
//
func (u UserResource) findUser(request *restful.Request, response *restful.Response) {
	login := request.PathParameter("user-login")

	usr := User{Login: login}

	if err := DbSession.Query(`SELECT id, password FROM users WHERE login = ? LIMIT 1`,
		usr.Login).Consistency(gocql.One).Scan(&usr.Id, &usr.Password); err != nil {
		response.AddHeader("Content-Type", "text/plain")
		response.WriteErrorString(http.StatusInternalServerError, err.Error())
		return
	}

	// usr := u.users[id]
	// if len(usr.Id) == 0 {
	// 	response.AddHeader("Content-Type", "text/plain")
	// 	response.WriteErrorString(http.StatusNotFound, "404: User could not be found.")
	// 	return
	// }
	response.WriteEntity(usr)
}

// POST http://localhost:8080/users
// <User><Name>Melissa</Name></User>
//
func (u *UserResource) createUser(request *restful.Request, response *restful.Response) {
	usr := new(User)
	err := request.ReadEntity(usr)
	if err != nil {
		response.AddHeader("Content-Type", "text/plain")
		response.WriteErrorString(http.StatusInternalServerError, err.Error())
		return
	}
	// usr.Id = strconv.Itoa(len(u.users) + 1) // simple id generation
	// u.users[usr.Id] = *usr
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

// PUT http://localhost:8080/users/1
// <User><Id>1</Id><Name>Melissa Raspberry</Name></User>
//
func (u *UserResource) updateUser(request *restful.Request, response *restful.Response) {
	usr := new(User)
	err := request.ReadEntity(&usr)
	if err != nil {
		response.AddHeader("Content-Type", "text/plain")
		response.WriteErrorString(http.StatusInternalServerError, err.Error())
		return
	}
	response.WriteEntity(usr)
}

// DELETE http://localhost:8080/users/1
//
func (u *UserResource) removeUser(request *restful.Request, response *restful.Response) {
	id := request.PathParameter("user-id")
	delete(u.users, id)
}
