package frontman

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHostInfoResults(t *testing.T) {
	cfg, err := HandleAllConfigSetup(DefaultCfgPath)
	assert.Nil(t, err)

	// system_fields is deprecated, but we test to make sure system_fields is treated as host_info
	cfg.HostInfo = []string{"uname", "os_kernel", "os_family", "os_arch", "cpu_model", "fqdn"}
	cfg.SystemFields = []string{"hostname", "memory_total_B"}
	fm := New(cfg, DefaultCfgPath, "1.2.3")

	v, err := fm.HostInfoResults()
	assert.Nil(t, err)
	assert.Equal(t, 8, len(v))
	fmt.Printf("%+v\n", v)
}
