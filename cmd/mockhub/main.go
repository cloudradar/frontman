package main

import (
	"math/rand"
	"time"

	"github.com/cloudradar-monitoring/frontman"
)

func main() {

	rand.Seed(time.Now().UnixNano())

	hub := frontman.NewMockHub("0.0.0.0:9100")
	hub.Serve()
}
