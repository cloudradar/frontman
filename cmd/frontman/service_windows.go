// +build windows

package main

import (
	"github.com/kardianos/service"

	"github.com/cloudradar-monitoring/frontman"
)

func updateServiceConfig(ca *frontman.Frontman, username string) {
	// nothing to do
}

func configureServiceEnabledState(s service.Service) {
	// nothing to do
}
