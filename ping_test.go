package frontman

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPing(t *testing.T) {
	cfg, err := HandleAllConfigSetup(DefaultCfgPath)

	cfg.ICMPTimeout = 0.2
	assert.Nil(t, err)
	fm := helperCreateFrontman(t, cfg)

	_, _ = fm.runPing("8.8.8.8")
}
