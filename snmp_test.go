package frontman

import (
	"fmt"
	"log"
	"testing"
	"time"

	"github.com/soniah/gosnmp"
)

func TestSNMP(t *testing.T) {

	params := &gosnmp.GoSNMP{
		Target:    "10.10.30.175",
		Port:      161,
		Version:   gosnmp.Version2c,
		Community: "public",
		Timeout:   time.Duration(1) * time.Second,
		/* v3 stuff:
		SecurityModel: gosnmp.UserSecurityModel,
		MsgFlags:      gosnmp.AuthPriv,
		SecurityParameters: &gosnmp.UsmSecurityParameters{UserName: "user",
			AuthenticationProtocol:   gosnmp.SHA,
			AuthenticationPassphrase: "password",
			PrivacyProtocol:          gosnmp.DES,
			PrivacyPassphrase:        "password",
		},
		*/
	}

	err := params.Connect()
	if err != nil {
		log.Fatalf("SNMP Connect() err: %v", err)
	}
	defer params.Conn.Close()

	// preset "basedata"
	basedataOids := []string{
		"1.3.6.1.2.1.1.1.0", // STRING: SG350-10 10-Port Gigabit Managed Switch
		"1.3.6.1.2.1.1.3.0", // Timeticks: (575618700) 66 days, 14:56:27.00
		"1.3.6.1.2.1.1.4.0", // STRING: ops@cloudradar.io
		"1.3.6.1.2.1.1.5.0", // STRING: switch-cloudradar
		"1.3.6.1.2.1.1.6.0", // STRING: Office Berlin
	}
	result, err2 := params.Get(basedataOids)
	if err2 != nil {
		log.Fatalf("SNMP Get() err: %v", err2)
	}

	for _, variable := range result.Variables {
		fmt.Printf("oid: %s ", variable.Name)

		switch variable.Type {
		case gosnmp.OctetString:
			fmt.Printf("string: %s\n", string(variable.Value.([]byte)))

		case gosnmp.TimeTicks:
			fmt.Printf("TimeTicks: %d\n", variable.Value)

		default:
			fmt.Printf("XXX %#v: %d\n", variable.Type, gosnmp.ToBigInt(variable.Value))
		}
	}
}
