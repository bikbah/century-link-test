package main

import (
	"log"
	"net/http"

	"github.com/emicklei/go-restful"
)

func main() {
	// to see what happens in the package, uncomment the following
	//restful.TraceLogger(log.New(os.Stdout, "[restful] ", log.LstdFlags|log.Lshortfile))

	defer DbSession.Close()

	wsContainer := restful.NewContainer()
	wsContainer.Router(restful.CurlyRouter{})

	RegisterUserWS(wsContainer)
	RegisterServices(wsContainer)

	log.Printf("start listening on localhost:8080")
	server := &http.Server{Addr: ":8080", Handler: wsContainer}
	log.Fatal(server.ListenAndServe())
}
