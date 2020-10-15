package frontman

import (
	"testing"

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

	cfg.HubURL = hub.URL() + "/?serviceChecks=0&webChecks=2"

	fm := helperCreateFrontman(t, cfg)

	resultsChan := make(chan Result, 100)
	interruptChan := make(chan struct{})

	fm.Run("", nil, interruptChan, resultsChan)
	// XXX stop after some time
}
