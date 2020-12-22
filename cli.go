package frontman

import (
	"bufio"
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/kardianos/service"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/cloudradar-monitoring/frontman/pkg/notification"
	"github.com/cloudradar-monitoring/selfupdate"
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
		default:
			// unknown, failed
			fmt.Println("unknown")
		}
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
	fm.tryUpgradeServiceUnit(systemService)

	return 0
}

// returns exit code
func (fm *Frontman) HandleFlagServiceUninstall() int {

	systemService, err := getServiceFromFlags(fm, "", "")
	if err != nil {
		fmt.Println("Failed to get system service: ", err.Error())
		return 1
	}

	status, err := systemService.Status()
	if err != nil {
		fmt.Println("Failed to get service status: ", err.Error())
	}

	if status == service.StatusRunning {
		err = systemService.Stop()
		if err != nil {
			// don't exit here, just write a warning and try to uninstall
			fmt.Println("Failed to stop the running service: ", err.Error())
		}
	}

	err = systemService.Uninstall()
	if err != nil {
		fmt.Println("Failed to uninstall the service: ", err.Error())
		return 1
	}

	return 0
}

// returns exit code
func (fm *Frontman) HandleFlagServiceInstall(systemManager service.System, username string, serviceInstallPtr *bool, cfgPath string, assumeYesPtr *bool) int {

	s, err := getServiceFromFlags(fm, cfgPath, username)
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	updateServiceConfig(fm, username)
	tryInstallService(s, assumeYesPtr)
	tryStartService(s)

	fmt.Printf("Log file located at: %s\n", fm.Config.LogFile)
	fmt.Printf("Config file located at: %s\n", cfgPath)

	if fm.Config.HubURL == "" {
		fmt.Printf(`*** Attention: 'hub_url' config param is empty.\n
*** You need to put the right credentials from your Cloudradar account into the config and then restart the service\n\n`)
	}

	fmt.Printf("Run this command to restart the service: %s\n\n", getSystemMangerCommand(systemManager.String(), fm.serviceConfig.Name, "restart"))
	return 0
}

// returns error code
func (fm *Frontman) HandleFlagOneRunOnlyMode(inputFile string, output *os.File) int {

	logrus.Debug("OneRunOnlyMode invoked (-r)")

	if err := fm.HealthCheck(); err != nil {
		fm.HealthCheckPassedPreviously = false
		logrus.WithError(err).Errorln("Health checks are not passed. Skipping other checks.")
		return 1
	}
	if !fm.HealthCheckPassedPreviously {
		fm.HealthCheckPassedPreviously = true
		logrus.Infoln("All health checks are positive. Resuming normal operation.")
	}

	err := fm.RunOnce(inputFile, output)
	if err != nil {
		fmt.Println(err)
		return 1
	}
	return 0
}

// returns exit code
func (fm *Frontman) HandleFlagPrintStats() int {

	buff, err := ioutil.ReadFile(fm.Config.StatsFile)
	if err != nil {
		fmt.Printf("Could not read stats file: %s\n", fm.Config.StatsFile)
		return 1
	}

	fmt.Printf("%s", buff)
	return 0
}

func (fm *Frontman) HandleFlagPrintConfig() {
	var configHeadline = "# Please refer to https://github.com/cloudradar-monitoring/frontman/blob/master/example.config.toml\n" +
		"# for a fully documented configuration example\n" +
		"#\n"

	fmt.Println(configHeadline)
	fmt.Println(fm.Config.DumpToml())
}

func (fm *Frontman) HandleFlagLogLevel(logLevel string) error {
	if logLevel == string(LogLevelError) || logLevel == string(LogLevelInfo) || logLevel == string(LogLevelDebug) {
		fm.SetLogLevel(LogLevel(logLevel))
	} else if logLevel != "" {
		return fmt.Errorf("Invalid log level: \"%s\". Set to default: \"%s\"", logLevel, fm.Config.LogLevel)
	}
	return nil
}

func (fm *Frontman) WritePidFileIfNeeded() error {
	if fm.Config.PidFile != "" && runtime.GOOS != "windows" {
		err := ioutil.WriteFile(fm.Config.PidFile, []byte(strconv.Itoa(os.Getpid())), 0664)
		if err != nil {
			return fmt.Errorf("Failed to write pid file at: %s", fm.Config.PidFile)
		}
	}
	return nil
}

func (fm *Frontman) RemovePidFileIfNeeded() {
	if fm.Config.PidFile != "" && runtime.GOOS != "windows" {
		err := os.Remove(fm.Config.PidFile)
		if err != nil {
			logrus.Errorf("Failed to remove pid file at: %s", fm.Config.PidFile)
		}
	}
}

// returns exit code
func HandleFlagDaemonizeMode() int {
	err := rerunDetached()
	if err != nil {
		fmt.Println("Failed to fork process: ", err.Error())
		return 1
	}
	return 0
}

func rerunDetached() error {
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}

	cmd := exec.Command(os.Args[0], os.Args[1:]...)
	cmd.Dir = cwd
	cmd.Env = append(os.Environ(), "FRONTMAN_FORK=1")

	err = cmd.Start()
	if err != nil {
		return err
	}

	fmt.Printf("Frontman will continue in background...\nPID %d", cmd.Process.Pid)

	return cmd.Process.Release()
}

// returns exit code
func (fm *Frontman) RunUnderOsServiceManager() int {
	systemService, err := getServiceFromFlags(fm, "", "")
	if err != nil {
		fmt.Println(err)
		return 1
	}

	// we are running under OS service manager
	err = systemService.Run()
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}
	return 0
}

func AskForConfirmation(s string) bool {
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Printf("%s [y/n]: ", s)

		response, err := reader.ReadString('\n')
		if err != nil {
			logrus.Fatal(err)
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

	fm.serviceConfig = service.Config{
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
		fm.serviceConfig.Arguments = []string{"-c", configPath}
	}

	if userName != "" {
		fm.serviceConfig.UserName = userName
	}

	return service.New(prg, &fm.serviceConfig)
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
	Frontman *Frontman
}

func (sw *serviceWrapper) Start(s service.Service) error {
	go func() {
		sw.Frontman.Run("", nil)
		sw.Frontman.DoneChan <- true
	}()

	return nil
}

func (sw *serviceWrapper) Stop(s service.Service) error {

	logrus.Println("Finishing the batch and stop the service...")
	close(sw.Frontman.InterruptChan)
	sw.Frontman.TerminateQueue.Wait()

	<-sw.Frontman.DoneChan
	return nil
}

// returns exit code
func HandleFlagUpdate(assumeYes *bool) int {

	updates, err := printAvailableUpdates()
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	if len(updates) == 0 {
		return 0
	}

	proceedInstallation := (assumeYes != nil && *assumeYes) || AskForConfirmation("Proceed installation?")
	if !proceedInstallation {
		return 0
	}

	fmt.Println("Downloading...")

	err = selfupdate.DownloadAndInstallUpdate(updates[len(updates)-1])
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}
	fmt.Println("Installer executed. Exiting.")
	return 0
}

// returns exit code
func HandleFlagSearchUpdates() int {
	_, err := printAvailableUpdates()
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}
	return 0
}

func printAvailableUpdates() ([]*selfupdate.UpdateInfo, error) {
	fmt.Println("Searching updates...")

	updates, err := selfupdate.ListAvailableUpdates()
	if err != nil {
		return nil, errors.Wrapf(err, "while listing updates")
	}

	if len(updates) == 0 {
		fmt.Println("No updates available")
	} else {
		fmt.Println("Available updates:")
		for _, u := range updates {
			fmt.Printf("\t%s\n", u.Version.Original())
		}
	}
	return updates, nil
}

func HandleFlagInputOutput(inputFile string, outputFile string, oneRunOnlyMode bool) *os.File {

	if inputFile == "" {
		return nil
	}

	var output *os.File
	var err error

	// Set output to stdout
	if outputFile == "-" {
		logrus.SetOutput(ioutil.Discard)
		output = os.Stdout
		return output
	}

	// Try to create the output file directory if it does not exist
	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		dir := filepath.Dir(outputFile)
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			err = os.MkdirAll(dir, 0644)
			if err != nil {
				logrus.WithError(err).Fatalf("Failed to create the output file directory: '%s'", dir)
			}
		}
	}

	mode := os.O_WRONLY | os.O_CREATE

	if oneRunOnlyMode {
		mode |= os.O_TRUNC
	} else {
		mode |= os.O_APPEND
	}

	if outputFile != "" {
		output, err = os.OpenFile(outputFile, mode, 0644)
		if err != nil {
			logrus.WithError(err).Fatalf("Failed to open the output file: '%s'", outputFile)
		}
	}
	return output
}
