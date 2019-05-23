package frontman

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
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

func ServeWeb(cfg HTTPListenerConfig) error {
	// XXX drop http:// prfix from address
	pos := strings.Index(cfg.HTTPListen, "://")
	if pos == -1 {
		return fmt.Errorf("invalid address in http_listen: '%s'", cfg.HTTPListen)
	}
	protocol := cfg.HTTPListen[0:pos]
	address := cfg.HTTPListen[pos+3:]
	log.Println("ServeWeb", protocol+"://"+address)
	http.HandleFunc("/ping", pingHandler)
	http.HandleFunc("/check", checkHandler)
	var err error
	switch protocol {
	case "http":
		err = http.ListenAndServe(address, nil)
	case "https":
		err = http.ListenAndServeTLS(":443", cfg.HTTPTLSCert, cfg.HTTPTLSKey, nil)
	default:
		return fmt.Errorf("invalid protocol: '%s'", protocol)
	}
	return err
}
