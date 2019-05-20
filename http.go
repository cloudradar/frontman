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

	// XXX 2. stop if content type is not application/json

	w.Header().Set("Content-Type", "application/json")

	decoder := json.NewDecoder(req.Body)
	var t Input
	err := decoder.Decode(&t)
	if err != nil {
		panic(err)
	}
	log.Printf("%+v\n", t)

	// w.Write([]byte(t)
}

func ServeHTTP() error {
	log.Println("ServeHTTP !")
	http.HandleFunc("/ping", pingHandler)
	http.HandleFunc("/check", checkHandler)
	//err := http.ListenAndServeTLS(":443", "server.crt", "server.key", nil)
	return http.ListenAndServe(":8080", nil)
}
