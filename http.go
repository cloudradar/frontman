package frontman

import (
	"encoding/json"
	"log"
	"net/http"
)

func pingHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("pong\n"))
}

func checkHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if req.Header.Get("Content-type") != "application/json" {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	decoder := json.NewDecoder(req.Body)
	var t Input
	err := decoder.Decode(&t)
	if err != nil {
		panic(err)
	}
	log.Printf("%+v\n", t)
	// XXX perform the checks, collect result and pass it back as json
}

func ServeHTTP() error {
	log.Println("ServeHTTP !")
	http.HandleFunc("/ping", pingHandler)
	http.HandleFunc("/check", checkHandler)
	//err := http.ListenAndServeTLS(":443", "server.crt", "server.key", nil)
	return http.ListenAndServe(":8080", nil)
}
