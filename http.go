package frontman

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gorilla/handlers"
	"github.com/sirupsen/logrus"
)

func pingHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"alive": true}`))
}

func (fm *Frontman) checkHandler(w http.ResponseWriter, req *http.Request) {
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
		logrus.Errorf("json decode error: '%s'", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// perform the checks, collect result and pass it back as json
	resultsChan := make(chan Result, 100)
	logrus.Println("checkHandler calling processInput")
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
			logrus.Fatal(err)
		}
		path := filepath.Dir(absFile)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			logrus.Info("Creating directory for http log:", path)
			err = os.MkdirAll(path, os.ModePerm)
			if err != nil {
				logrus.Fatal(err)
			}
		}
		logFile, err = os.OpenFile(absFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			logrus.Error(err)
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

// ServeWeb starts the webserver as configured under [http_listener] section of frontman.conf
func (fm *Frontman) ServeWeb() error {
	pos := strings.Index(fm.Config.HTTPListener.HTTPListen, "://")
	if pos == -1 {
		return fmt.Errorf("invalid address in http_listen: '%s'", fm.Config.HTTPListener.HTTPListen)
	}
	protocol := fm.Config.HTTPListener.HTTPListen[0:pos]
	address := fm.Config.HTTPListener.HTTPListen[pos+3:]
	logrus.Info("http_listener listening on ", protocol+"://"+address)
	http.Handle("/ping", fm.Config.HTTPListener.middlewareLogging(http.HandlerFunc(pingHandler)))
	http.Handle("/check", fm.Config.HTTPListener.middlewareLogging(fm.Config.HTTPListener.middlewareAuth(fm.checkHandler)))
	var err error
	switch protocol {
	case "http":
		err = http.ListenAndServe(address, nil)
	case "https":
		err = http.ListenAndServeTLS(address, fm.Config.HTTPListener.HTTPTLSCert, fm.Config.HTTPListener.HTTPTLSKey, nil)
	default:
		return fmt.Errorf("invalid protocol: '%s'", protocol)
	}
	return err
}
