// +build windows

package frontman

import (
	"github.com/kardianos/service"
)

func updateServiceConfig(fm *Frontman, username string) {
	// nothing to do
}

func (fm *Frontman) configureServiceEnabledState(s service.Service) {
	// nothing to do
}
