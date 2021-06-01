package main

import (
	"flag"
	"math/rand"
	"time"

	"github.com/cloudradar-monitoring/frontman"
)

func main() {

	rand.Seed(time.Now().UnixNano())

	responseCode := flag.Int("code", 0, "response code")
	flag.Parse()

	hub := frontman.NewMockHub("0.0.0.0:9100")
	if *responseCode != 0 {
		hub.ResponseStatusCode = *responseCode
	}
	hub.Serve()
}
