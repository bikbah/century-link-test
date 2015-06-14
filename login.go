package main

import (
	"net/http"

	"github.com/emicklei/go-restful"
)

type LoginData struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

func (ld LoginData) RegisterLoginService(container *restful.Container) {
	ws := new(restful.WebService)
	ws.
		Path("/login").
		Doc("Manage login").
		Consumes(restful.MIME_JSON)

	ws.Route(ws.POST("").To(ld.login).
		Reads(LoginData{})) // from the request

	container.Add(ws)
}

func (ld *LoginData) login(req *restful.Request, res *restful.Response) {
	loginData := new(LoginData)
	if err := request.ReadEntity(loginData); err != nil {
		response.AddHeader("Content-Type", "text/plain")
		response.WriteErrorString(http.StatusInternalServerError, err.Error())
		return
	}

	if LoginData.Password == "secret" {
		return
	}
}
