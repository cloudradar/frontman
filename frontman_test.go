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

// XXX end-2-end test

func TestFrontmanHubInput(t *testing.T) {
	// XXX 1. mock hub. fetch checks

	hub := NewMockHub()
	go hub.Serve() // XXX no way to close cleanly

}
