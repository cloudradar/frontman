package main

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/kardianos/service"
	"github.com/sirupsen/logrus"
)

func tryStartService(s service.Service) {
	logrus.Info("Starting service...")
	err := s.Start()
	if err != nil {
		logrus.WithError(err).Warningf("Frontman service(%s) startup failed", s.Platform())
	}
}

func tryInstallService(s service.Service, assumeYesPtr *bool) {
	const maxAttempts = 3
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		err := s.Install()
		// Check error case where the service already exists
		switch {
		case err != nil && strings.Contains(err.Error(), "already exists"):
			if attempt == maxAttempts {
				logrus.Fatalf("Giving up after %d attempts", maxAttempts)
			}

			var osSpecificNote string
			if runtime.GOOS == "windows" {
				osSpecificNote = " Windows Services Manager application must be closed before proceeding!"
			}

			fmt.Printf("Frontman service(%s) already installed: %s\n", s.Platform(), err.Error())
			if *assumeYesPtr || askForConfirmation("Do you want to overwrite it?"+osSpecificNote) {
				logrus.Info("Trying to override old service unit...")
				err = s.Stop()
				if err != nil {
					logrus.WithError(err).Warnln("Failed to stop the service")
				}

				// lets try to uninstall despite of this error
				err := s.Uninstall()
				if err != nil {
					logrus.WithError(err).Fatalln("Failed to uninstall the service")
				}
			}
		case err != nil:
			logrus.WithError(err).Fatalf("Frontman service(%s) installation failed", s.Platform())
		default:
			logrus.Infof("Frontman service(%s) has been installed.", s.Platform())
			return
		}
	}
}

func tryUpgradeServiceUnit(s service.Service) {
	_, err := s.Status()
	if err == service.ErrNotInstalled {
		logrus.Error("Can't upgrade service: service is not installed")
		return
	}

	configureServiceEnabledState(s)

	err = s.Stop()
	if err != nil {
		logrus.WithError(err).Warnln("Failed to stop the service")
	}

	err = s.Uninstall()
	if err != nil {
		logrus.WithError(err).Fatalln("Failed to uninstall the service")
	}

	err = s.Install()
	if err != nil {
		logrus.WithError(err).Fatalf("Frontman service(%s) unit upgrade failed", s.Platform())
	}

	logrus.Infof("Frontman service(%s) unit has been upgraded.", s.Platform())
}
