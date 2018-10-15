// +build windows nacl plan9

package frontman

import "errors"

func addSyslogHook(syslogURL string) error {
	return errors.New("Syslog not available for windows")
}
