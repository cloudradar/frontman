package frontman

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gorilla/handlers"
)

func pingHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"alive": true}`))
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
	_, _ = w.Write(enc)
}

func (listener *HTTPListenerConfig) middlewareLogging(h http.Handler) http.Handler {
	var logFile *os.File
	if listener.HTTPAccessLog != "" {
		absFile, err := filepath.Abs(listener.HTTPAccessLog)
		if err != nil {
			log.Fatal(err)
		}
		path := filepath.Dir(absFile)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			log.Println("Creating directory for http log:", path)
			err = os.MkdirAll(path, os.ModePerm)
			if err != nil {
				log.Fatal(err)
			}
		}
		logFile, err = os.OpenFile(absFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			log.Println(err)
		}
	} else {
		logFile = os.Stdout
	}
	return handlers.LoggingHandler(logFile, h)
}

func (listener HTTPListenerConfig) middlewareAuth(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, pass, _ := r.BasicAuth()
		if user != listener.HTTPAuthUser || pass != listener.HTTPAuthPassword {
			http.Error(w, "Unauthorized.", http.StatusUnauthorized)
			return
		}
		fn(w, r)
	}
}

func (listener HTTPListenerConfig) ServeWeb() error {
	pos := strings.Index(listener.HTTPListen, "://")
	if pos == -1 {
		return fmt.Errorf("invalid address in http_listen: '%s'", listener.HTTPListen)
	}
	protocol := listener.HTTPListen[0:pos]
	address := listener.HTTPListen[pos+3:]
	log.Println("ServeWeb", protocol+"://"+address)
	http.Handle("/ping", listener.middlewareLogging(http.HandlerFunc(pingHandler)))
	http.Handle("/check", listener.middlewareLogging(listener.middlewareAuth(checkHandler)))
	var err error
	switch protocol {
	case "http":
		err = http.ListenAndServe(address, nil)
	case "https":
		err = http.ListenAndServeTLS(":443", listener.HTTPTLSCert, listener.HTTPTLSKey, nil)
	default:
		return fmt.Errorf("invalid protocol: '%s'", protocol)
	}
	return err
}
