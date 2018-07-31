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
)

func certName(cert *x509.Certificate) string {
	return fmt.Sprintf("'%s' issued by %s", cert.Subject.CommonName, cert.Issuer.CommonName)
}

func (fm *Frontman) runSSLCheck(addr *net.TCPAddr, hostname, service string) (m MeasurementsMap, err error) {
	service = strings.ToLower(service)
	prefix := "net.tcp.ssl."

	m = MeasurementsMap{
		prefix + "success": 0,
	}
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
		err = fmt.Errorf("No default port specified for '%s'", service)
		return
	}

	dialer := net.Dialer{Timeout: secToDuration(fm.NetTCPTimeout)}
	connection, err := tls.DialWithDialer(&dialer, "tcp", addr.String(), &tls.Config{ServerName: hostname, InsecureSkipVerify: true})

	if err != nil {
		log.Debugf("TLS dial err: %s", err.Error())
		if strings.HasPrefix(err.Error(), "tls:") {
			err = fmt.Errorf("Service doesn't support SSL")
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
			err = fmt.Errorf("Certificate is expired: %s", certName(cert))
			return
		} else if remainingValidity <= float64(fm.SSLCertExpiryThreshold) {
			err = fmt.Errorf("Certificate will expire soon: %s", certName(cert))
			return
		}

		if cert.NotBefore.After(time.Now()) {
			err = fmt.Errorf("Certificate is not valid yet: %s", certName(cert))
			return
		}

	}

	if hostname != "" && connection.VerifyHostname(hostname) != nil {
		err = fmt.Errorf("Certificate is not valid for host: %s", hostname)
	}

	return
}
