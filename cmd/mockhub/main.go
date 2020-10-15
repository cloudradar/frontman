package main

import (
	"math/rand"
	"time"

	"github.com/cloudradar-monitoring/frontman"
)

func main() {

	rand.Seed(time.Now().UnixNano())

	hub := frontman.NewMockHub()

	hub.Serve()
}
