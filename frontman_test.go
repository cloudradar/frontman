package frontman

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func helperCreateFrontman(t *testing.T, cfg *Config) *Frontman {
	t.Helper()
	fm, err := New(cfg, DefaultCfgPath, "1.2.3")
	assert.Nil(t, err)
	return fm
}

func TestFrontmanHubInput(t *testing.T) {
	hub := NewMockHub("localhost:9100")
	go hub.Serve()

	cfg, err := HandleAllConfigSetup(DefaultCfgPath)
	assert.Nil(t, err)

	cfg.HubURL = hub.URL() + "/?serviceChecks=10&webChecks=10"
	cfg.LogLevel = "debug"
	cfg.Sleep = 1           // delay between each round of checks
	cfg.SenderBatchSize = 2 // number of results to send to hub at once
	cfg.SenderInterval = 1
	cfg.ICMPTimeout = 0.1
	cfg.HTTPCheckTimeout = 1.0

	fm := helperCreateFrontman(t, cfg)

	resultsChan := make(chan Result, 100)
	interruptChan := make(chan struct{})

	go fm.Run("", nil, interruptChan, resultsChan)

	// stop after some time
	time.Sleep(5 * time.Second)
	close(interruptChan)
	time.Sleep(1 * time.Second)

	assert.Equal(t, true, fm.ipc.len() > 0)
}
