// +build !quick_tests

package frontman

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFrontman_runSSLCheck(t *testing.T) {
	badSSL := []string{
		"expired.badssl.com",
		"wrong.host.badssl.com",
		"self-signed.badssl.com",
		"untrusted-root.badssl.com",

		"sha1-intermediate.badssl.com",

		// cipher suite
		"rc4-md5.badssl.com",
		"rc4.badssl.com",
		"null.badssl.com",

		// key exchange
		"dh480.badssl.com",
		"dh512.badssl.com",
		"dh1024.badssl.com",
		"dh2048.badssl.com",
		"dh-small-subgroup.badssl.com",
		"dh-composite.badssl.com",

		// certificate transparency
		"invalid-expected-sct.badssl.com",

		// upgrade
		"subdomain.preloaded-hsts.badssl.com",

		// known bad
		"Superfish.badssl.com",
		"eDellRoot.badssl.com",
		"DSDTestProvider.badssl.com",
		"preact-cli.badssl.com",
		"webpack-dev-server.badssl.com",

		// chrome tests
		"captive-portal.badssl.com",
		"mitm-software.badssl.com",

		// defunct
		"sha1-2017.badssl.com",
	}

	goodSSL := []string{
		"badssl.com",
		"sha256.badssl.com",
		"sha384.badssl.com",
		"sha512.badssl.com",

		"1000-sans.badssl.com",
		"ecc256.badssl.com",
		"ecc384.badssl.com",
		"rsa2048.badssl.com",
		"rsa4096.badssl.com",
		"extended-validation.badssl.com",
		"client.badssl.com",
		"mozilla-modern.badssl.com",

		"hsts.badssl.com",
		"upgrade.badssl.com",
		"preloaded-hsts.badssl.com",
		"https-everywhere.badssl.com",

		"long-extended-subdomain-name-containing-many-letters-and-dashes.badssl.com",
		"longextendedsubdomainnamewithoutdashesinordertotestwordwrapping.badssl.com",
	}

	if testing.Short() {
		badSSL = badSSL[:2]
		goodSSL = goodSSL[:2]
	}

	cfg := NewConfig()
	fm := helperCreateFrontman(t, cfg)

	for _, badSSLHost := range badSSL {
		_, err := fm.runSSLCheck(badSSLHost, 443, "https")
		assert.Error(t, err, badSSLHost)
	}

	for _, goodSSLHost := range goodSSL {
		_, err := fm.runSSLCheck(goodSSLHost, 443, "https")
		assert.NoError(t, err, goodSSLHost)
	}
}
