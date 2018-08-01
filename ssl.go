package frontman

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	log "github.com/sirupsen/logrus"
	"math"
	"net"
	"strings"
	"time"
	"errors"
)

func certName(cert *x509.Certificate) string {
	return fmt.Sprintf("'%s' issued by %s", cert.Subject.CommonName, cert.Issuer.CommonName)
}

func (fm *Frontman) runSSLCheck(addr *net.TCPAddr, hostname, service string) (m MeasurementsMap, err error) {
	service = strings.ToLower(service)

	if net.ParseIP(hostname) != nil {
		hostname = ""
	}

	if addr.Port == 0 {
		if port, exists := defaultPortByService[service]; exists {
			addr.Port = port
		} else if port, _ := net.LookupPort("tcp", service); port > 0 {
			addr.Port = port
		}
	}

	if addr.Port == 0 {
		err = fmt.Errorf("failed to auto-determine port for '%s'", service)
		return
	}

	prefix := fmt.Sprintf("net.tcp.ssl.%d", addr.Port)

	m = MeasurementsMap{
		prefix + "success": 0,
	}

	dialer := net.Dialer{Timeout: secToDuration(fm.NetTCPTimeout)}
	connection, err := tls.DialWithDialer(&dialer, "tcp", addr.String(), &tls.Config{ServerName: hostname, InsecureSkipVerify: true})

	if err != nil {
		log.Debugf("TLS dial err: %s", err.Error())
		if strings.HasPrefix(err.Error(), "tls:") {
			err = fmt.Errorf("service doesn't support SSL")
		}
		return
	}

	defer connection.Close()

	m[prefix+"expiryDaysRemaining"] = math.MaxFloat64
	for _, cert := range connection.ConnectionState().PeerCertificates {
		remainingValidity := cert.NotAfter.Sub(time.Now()).Hours() / 24

		if remainingValidity < m[prefix+"expiryDaysRemaining"].(float64) {
			m[prefix+"expiryDaysRemaining"] = remainingValidity
		}

		if remainingValidity <= 0 {
			err = fmt.Errorf("certificate is expired: %s", certName(cert))
			return
		} else if remainingValidity <= float64(fm.SSLCertExpiryThreshold) {
			err = fmt.Errorf("certificate will expire soon: %s", certName(cert))
			return
		}

		if cert.NotBefore.After(time.Now()) {
			err = fmt.Errorf("certificate is not valid yet: %s", certName(cert))
			return
		}

		if !cert.IsCA && hostname != "" {
			err = cert.VerifyHostname(hostname)
			if err != nil {
				log.Debugf("serviceCheck: SSL check for '%s' failed: %s", hostname, err.Error())
				err = errors.New(strings.TrimPrefix(err.Error(),"x509: certificate"))
			}
		}

	}

	if err == nil {
		m[prefix+"success"] = 1
	}

	return
}
