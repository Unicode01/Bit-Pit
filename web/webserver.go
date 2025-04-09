package web

import (
	"Bit-Pit/utils"
	_ "embed"
	"fmt"
	"net/http"
)

var (
	server     *http.Server
	VisitToken string
	Data       []byte
	NodeInfo   []byte
)

//go:embed templete/index.html
var PageIndex []byte

//go:embed templete/404.html
var PageNotFound []byte

//go:embed templete/403.html
var PageNoPermission []byte

func generateNodeInfo() {
	NodeInfo = utils.Marshal()
}

func InitWebServer(port int, visitToken string) error {
	VisitToken = visitToken
	server = &http.Server{
		Addr:    ":" + fmt.Sprint(port),
		Handler: http.HandlerFunc(serverHandler),
	}
	err := server.ListenAndServe()
	return err
}

func serverHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			w.Write(PageIndex)
		}
		if r.URL.Path == "/api/getTreeInfo" {
			token := r.Header.Get("Authorization") // bearer token
			// get token
			token = token[7:] // remove "bearer "
			if token == VisitToken {
				w.Header().Set("Content-Type", "application/json")
				w.Write(Data)
			} else {
				w.Header().Set("Content-Type", "text/html")
				w.Write(PageNoPermission)
			}
		}
		if r.URL.Path == "/api/getNodeInfo" {
			token := r.Header.Get("Authorization") // bearer token
			// get token
			token = token[7:] // remove "bearer "
			if token == VisitToken {
				generateNodeInfo()
				w.Header().Set("Content-Type", "application/json")
				w.Write(NodeInfo)
			} else {
				w.Header().Set("Content-Type", "text/html")
				w.Write(PageNoPermission)
			}
		}
	}
	if r.Method == "POST" {
	}
}
