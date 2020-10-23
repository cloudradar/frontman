package frontman

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/kardianos/service"
	"github.com/sirupsen/logrus"

	"github.com/cloudradar-monitoring/frontman/pkg/notification"
)

var (
	serviceName = "frontman"
)

// HandleFlagTest handles -t flag for the frontman executable
// returns exit code
func (fm *Frontman) HandleFlagTest() int {
	ctx := context.Background()
	err := fm.CheckHubCredentials(ctx, "hub_url", "hub_user", "hub_password")
	if err != nil {
		if runtime.GOOS == "windows" {
			// ignore toast error to make the main error clear for user
			// toast error probably means toast not supported on the system
			_ = notification.SendErrorNotification("Hub connection check failed", err.Error())
		}
		logrus.WithError(err).Errorln("Hub connection check failed")
		systemService, err := getServiceFromFlags(fm, "", "")
		if err != nil {
			logrus.WithError(err).Fatalln("Failed to get system service")
		}

		status, err := systemService.Status()
		if err != nil {
			// service seems not installed
			// no need to show the tip on how to restart it
			return 1
		}

		systemManager := service.ChosenSystem()
		if status == service.StatusRunning || status == service.StatusStopped {
			restartCmdSpec := getSystemMangerCommand(systemManager.String(), serviceName, "restart")
			logrus.WithFields(logrus.Fields{
				"restartCmd": restartCmdSpec,
			}).Infoln("Fix the config and then restart the service")
		}

		return 1
	}

	if runtime.GOOS == "windows" {
		_ = notification.SendSuccessNotification("Hub connection check is done", "")
	}
	logrus.Infoln("Hub connection check is done and credentials are correct!")
	return 0
}

// returns exit code
func (fm *Frontman) HandleServiceCommand(check, start, stop, restart bool) int {
	svc, err := getServiceFromFlags(fm, "", "")
	if err != nil {
		logrus.WithError(err).Fatalln("can't find service")
	}

	var status service.Status
	if status, err = svc.Status(); err != nil && err != service.ErrNotInstalled {
		logrus.WithError(err).Fatalln("can't get service status")
	}

	if check {
		switch status {
		case service.StatusRunning:
			fmt.Println("running")
		case service.StatusStopped:
			fmt.Println("stopped")
		case service.StatusUnknown:
			fmt.Println("unknown")
		}
		return 0
	}

	if stop && (status == service.StatusRunning) {
		if err = svc.Stop(); err != nil {
			fmt.Println(err)
			return 1
		}

		fmt.Println("stopped")
		return 0
	} else if stop {
		fmt.Println("service is not running")
		return 0
	}

	if start {
		if status == service.StatusRunning {
			fmt.Println("already")
			return 1
		}

		if err = svc.Start(); err != nil {
			fmt.Println(err)
			return 1
		}

		fmt.Println("started")
		return 0
	}

	if restart {
		if err = svc.Restart(); err != nil {
			fmt.Println(err)
			return 1
		}
		fmt.Println("restarted")
		return 0
	}

	return 0
}

// returns exit code
func (fm *Frontman) HandleFlagServiceUpgrade(cfgPath string, serviceUpgradeFlag *bool, serviceInstallUserPtr *string) int {

	installUser := ""
	if serviceInstallUserPtr != nil {
		installUser = *serviceInstallUserPtr
	}

	systemService, err := getServiceFromFlags(fm, cfgPath, installUser)
	if err != nil {
		logrus.WithError(err).Fatalln("Failed to get system service")
	}

	updateServiceConfig(fm, installUser)
	tryUpgradeServiceUnit(systemService)

	return 0
}

func AskForConfirmation(s string) bool {
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Printf("%s [y/n]: ", s)

		response, err := reader.ReadString('\n')
		if err != nil {
			log.Fatal(err)
		}

		response = strings.ToLower(strings.TrimSpace(response))

		if response == "y" || response == "yes" {
			return true
		} else if response == "n" || response == "no" {
			return false
		}
	}
}

func getServiceFromFlags(fm *Frontman, configPath, userName string) (service.Service, error) {
	prg := &serviceWrapper{Frontman: fm}

	svcConfig := &service.Config{
		Name:        serviceName,
		DisplayName: "CloudRadar Frontman",
		Description: "A versatile open source monitoring agent developed by cloudradar.io. It monitors your local intranet.",
	}

	if configPath != "" {
		if !filepath.IsAbs(configPath) {
			var err error
			configPath, err = filepath.Abs(configPath)
			if err != nil {
				return nil, fmt.Errorf("failed to get absolute path to config at '%s': %s", configPath, err)
			}
		}
		svcConfig.Arguments = []string{"-c", configPath}
	}

	if userName != "" {
		svcConfig.UserName = userName
	}

	return service.New(prg, svcConfig)
}

func getSystemMangerCommand(manager string, service string, command string) string {
	switch manager {
	case "unix-systemv":
		return "sudo service " + service + " " + command
	case "linux-upstart":
		return "sudo initctl " + command + " " + service
	case "linux-systemd":
		return "sudo systemctl " + command + " " + service + ".service"
	case "darwin-launchd":
		switch command {
		case "stop":
			command = "unload"
		case "start":
			command = "load"
		case "restart":
			return "sudo launchctl unload " + service + " && sudo launchctl load " + service
		}
		return "sudo launchctl " + command + " " + service
	case "windows-service":
		return "sc " + command + " " + service
	default:
		return ""
	}
}

// serviceWrapper provides context and methods that satisfies service.Interface
// in order to run Frontman under OS Service Manager
type serviceWrapper struct {
	Frontman      *Frontman
	ResultsChan   chan Result
	InterruptChan chan struct{}
	DoneChan      chan struct{}
}

func (sw *serviceWrapper) Start(s service.Service) error {
	sw.ResultsChan = make(chan Result, 100)
	sw.InterruptChan = make(chan struct{})
	sw.DoneChan = make(chan struct{})
	go func() {
		sw.Frontman.Run("", nil, sw.InterruptChan, sw.ResultsChan)
		sw.DoneChan <- struct{}{}
	}()

	return nil
}

func (sw *serviceWrapper) Stop(s service.Service) error {
	sw.InterruptChan <- struct{}{}
	logrus.Println("Finishing the batch and stop the service...")
	<-sw.DoneChan
	return nil
}
