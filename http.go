package frontman

import (
	"encoding/json"
	"log"
	"net/http"
)

func pingHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"alive": true}`))
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
	var inputConfig Input
	err := decoder.Decode(&inputConfig)
	if err != nil {
		log.Println("json decode error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// perform the checks, collect result and pass it back as json
	cfg, _ := HandleAllConfigSetup(DefaultCfgPath)
	fm := New(cfg, DefaultCfgPath, "1.2.3")
	resultsChan := make(chan Result, 100)
	fm.processInput(&inputConfig, resultsChan)
	res := <-resultsChan

	enc, _ := json.Marshal(res)
	w.Write(enc)
}

func ServeHTTP() error {
	log.Println("ServeHTTP !")
	http.HandleFunc("/ping", pingHandler)
	http.HandleFunc("/check", checkHandler)
	//err := http.ListenAndServeTLS(":443", "server.crt", "server.key", nil)
	return http.ListenAndServe(":8080", nil)
}
