package frontman

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math"
	"net"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

const timeoutPortLookup = time.Second * 3

func certName(cert *x509.Certificate) string {
	return fmt.Sprintf("'%s' issued by %s", cert.Subject.CommonName, cert.Issuer.CommonName)
}

func (fm *Frontman) runSSLCheck(addr *net.TCPAddr, hostname, service string) (m MeasurementsMap, err error) {
	service = strings.ToLower(service)

	if net.ParseIP(hostname) != nil {
		hostname = ""
	}

	if addr.Port == 0 {
		ctx, cancel := context.WithTimeout(context.Background(), timeoutPortLookup)
		defer cancel()

		if port, exists := defaultPortByService[service]; exists {
			addr.Port = port
		} else if port, lerr := net.DefaultResolver.LookupPort(ctx, "tcp", service); port > 0 {
			addr.Port = port
		} else if lerr != nil {
			err = fmt.Errorf("failed to auto-determine port for '%s': %s", service, lerr.Error())
			return
		}
	}

	prefix := fmt.Sprintf("net.tcp.ssl.%d.", addr.Port)

	m = MeasurementsMap{
		prefix + "success": 0,
	}

	dialer := net.Dialer{Timeout: secToDuration(fm.Config.NetTCPTimeout)}
	connection, err := tls.DialWithDialer(&dialer, "tcp", addr.String(), &tls.Config{ServerName: hostname, InsecureSkipVerify: true})

	if err != nil {
		logrus.Debugf("TLS dial err: %s", err.Error())
		if strings.HasPrefix(err.Error(), "tls:") {
			err = fmt.Errorf("service doesn't support SSL")
		}
		return
	}

	defer connection.Close()

	m[prefix+"expiryDaysRemaining"] = nil
	certs := connection.ConnectionState().PeerCertificates

	for i, cert := range certs {
		opts := x509.VerifyOptions{
			Intermediates: x509.NewCertPool(),
		}
		if !cert.IsCA && hostname != "" {
			opts.DNSName = hostname
		}

		if i == 0 {
			addCertificatesToPool(opts.Intermediates, certs[1:])

			// try to predict expiry date before we extract all the chains
			// the field will be updated with more precise value after checking the validity
			m[prefix+"expiryDaysRemaining"] = time.Until(cert.NotAfter).Hours() / 24
		}

		var chains [][]*x509.Certificate
		chains, err = cert.Verify(opts)
		if err != nil {
			logrus.Debugf("serviceCheck: SSL check for '%s' failed: %s", hostname, err.Error())
			err = errors.New(strings.TrimPrefix(err.Error(), "x509: "))
			return
		}

		if i == 0 {
			remainingValidity, firstCertToExpire := findCertRemainingValidity(chains)
			m[prefix+"expiryDaysRemaining"] = remainingValidity

			if remainingValidity <= float64(fm.Config.SSLCertExpiryThreshold) {
				err = fmt.Errorf("certificate will expire soon: %s", certName(firstCertToExpire))
				return
			}
		}
	}

	m[prefix+"success"] = 1
	return
}

func addCertificatesToPool(pool *x509.CertPool, certs []*x509.Certificate) {
	for _, cert := range certs {
		pool.AddCert(cert)
	}
}

func findCertRemainingValidity(certChains [][]*x509.Certificate) (float64, *x509.Certificate) {
	var remainingValidity float64
	var firstToExpire *x509.Certificate

	// find chain with max remaining validity
	for _, chain := range certChains {
		fmt.Printf("checking chain of len %d", len(chain))
		chainRemainingValidity, c := findChainRemainingValidity(chain)
		if chainRemainingValidity > remainingValidity {
			remainingValidity = chainRemainingValidity
			firstToExpire = c
		}
	}
	return remainingValidity, firstToExpire
}

func findChainRemainingValidity(chain []*x509.Certificate) (float64, *x509.Certificate) {
	var min = math.MaxFloat64
	var firstToExpire *x509.Certificate

	// find cert that will expire first
	for _, cert := range chain {
		remainingValidity := time.Until(cert.NotAfter).Hours() / 24
		if remainingValidity < min {
			min = remainingValidity
			firstToExpire = cert
		}
	}
	return min, firstToExpire
}
