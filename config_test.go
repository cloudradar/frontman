package frontman

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/troian/toml"
)

func TestNewMinimumConfig(t *testing.T) {
	envURL := "http://foo.bar"
	envUser := "foo"
	envPass := "bar"

	// TODO: Not sure if this is really a good idea... could mess with other things
	os.Setenv("FRONTMAN_HUB_URL", envURL)
	os.Setenv("FRONTMAN_HUB_USER", envUser)
	os.Setenv("FRONTMAN_HUB_PASSWORD", envPass)

	mvc := NewMinimumConfig()

	assert.Equal(t, envURL, mvc.HubURL, "HubURL should be set from env")
	assert.Equal(t, envUser, mvc.HubUser, "HubUser should be set from env")
	assert.Equal(t, envPass, mvc.HubPassword, "HubPassword should be set from env")

	// Unset in the end for cleanup
	os.Unsetenv("FRONTMAN_HUB_URL")
	os.Unsetenv("FRONTMAN_HUB_USER")
	os.Unsetenv("FRONTMAN_HUB_PASSWORD")
}

func TestTryUpdateConfigFromFile(t *testing.T) {
	cfg := NewConfig()

	const sampleConfig = `
pid = "/pid"
sleep = 1.23
ignore_ssl_errors = true
`

	tmpFile, err := ioutil.TempFile("", "")
	assert.Nil(t, err)
	defer os.Remove(tmpFile.Name())

	err = ioutil.WriteFile(tmpFile.Name(), []byte(sampleConfig), 0755)
	assert.Nil(t, err)

	err = cfg.TryUpdateConfigFromFile(tmpFile.Name())
	assert.Nil(t, err)

	assert.Equal(t, "/pid", cfg.PidFile)
	assert.Equal(t, 1.23, cfg.Sleep)
	assert.Equal(t, true, cfg.IgnoreSSLErrors)

	// make sure default values are propagated
	assert.Equal(t, []string{"uname", "os_kernel", "os_family", "os_arch", "cpu_model", "fqdn", "memory_total_B"}, cfg.HostInfo)
}

func TestHandleAllConfigSetup(t *testing.T) {
	t.Run("config-file-does-exist", func(t *testing.T) {
		const sampleConfig = `
pid = "/pid"
sleep = 1.0
ignore_ssl_errors = true
`

		tmpFile, err := ioutil.TempFile("", "")
		assert.Nil(t, err)
		defer os.Remove(tmpFile.Name())

		err = ioutil.WriteFile(tmpFile.Name(), []byte(sampleConfig), 0755)
		assert.Nil(t, err)

		config, err := HandleAllConfigSetup(tmpFile.Name())
		assert.Nil(t, err)

		assert.Equal(t, "/pid", config.PidFile)
		assert.Equal(t, 1.0, config.Sleep)
		assert.Equal(t, true, config.IgnoreSSLErrors)
	})

	t.Run("config-file-does-not-exist", func(t *testing.T) {
		// Create a temp file to get a file path we can use for temp
		// config generation. But delete it so we can actually write our
		// config file under the path.
		tmpFile, err := ioutil.TempFile("", "")
		assert.Nil(t, err)
		configFilePath := tmpFile.Name()
		err = os.Remove(tmpFile.Name())
		assert.Nil(t, err)

		_, err = HandleAllConfigSetup(configFilePath)
		assert.Nil(t, err)

		_, err = os.Stat(configFilePath)
		assert.Nil(t, err)

		mvc := NewMinimumConfig()
		loadedMVC := &MinValuableConfig{}
		_, err = toml.DecodeFile(configFilePath, loadedMVC)
		assert.Nil(t, err)

		if !assert.ObjectsAreEqual(*mvc, *loadedMVC) {
			t.Errorf("expected %+v, got %+v", *mvc, *loadedMVC)
		}
	})
}
