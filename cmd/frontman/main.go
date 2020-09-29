package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/cloudradar-monitoring/selfupdate"
	"github.com/kardianos/service"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/cloudradar-monitoring/frontman"
)

var svcConfig = &service.Config{
	Name:        "frontman",
	DisplayName: "CloudRadar Frontman",
	Description: "A versatile open source monitoring agent developed by cloudradar.io. It monitors your local intranet.",
}

func main() {
	systemManager := service.ChosenSystem()

	var serviceInstallUserPtr *string
	var serviceInstallPtr *bool
	var settingsPtr *bool
	var searchUpdatesPtr *bool
	var updatePtr *bool

	// Setup flag pointers
	inputFilePtr := flag.String("i", "", "JSON file to read the list (required)")
	outputFilePtr := flag.String("o", "", "file to write the results (default ./results.out)")
	cfgPathPtr := flag.String("c", frontman.DefaultCfgPath, "config file path")
	testConfigPtr := flag.Bool("t", false, "test the Hub config and exit")
	logLevelPtr := flag.String("v", "", "log level – overrides the level in config file (values \"error\",\"info\",\"debug\")")
	daemonizeModePtr := flag.Bool("d", false, "daemonize – run the process in background")
	oneRunOnlyModePtr := flag.Bool("r", false, "one run only – perform checks once and exit. Overwrites output file")
	serviceUninstallPtr := flag.Bool("u", false, fmt.Sprintf("stop and uninstall the system service(%s)", systemManager.String()))
	printConfigPtr := flag.Bool("p", false, "print the active config")
	versionPtr := flag.Bool("version", false, "show the frontman version")
	statsPtr := flag.Bool("stats", false, "show the frontman stats")
	assumeYesPtr := flag.Bool("y", false, "automatic yes to prompts. Assume 'yes' as answer to all prompts and run non-interactively")
	serviceStatusPtr := flag.Bool("service_status", false, "check service status")
	serviceStartPtr := flag.Bool("service_start", false, "start service")
	serviceStopPtr := flag.Bool("service_stop", false, "stop service")
	serviceRestartPtr := flag.Bool("service_restart", false, "restart service")
	serviceUpgradePtr := flag.Bool("service_upgrade", false, "upgrade service unit configuration")

	// some OS specific flags
	if runtime.GOOS == "windows" {
		serviceInstallPtr = flag.Bool("s", false, fmt.Sprintf("install and start the system service(%s)", systemManager.String()))
		settingsPtr = flag.Bool("x", false, "open the settings UI")
		updatePtr = flag.Bool("update", false, "look for updates and apply them. Requires confirmation. Use -y to suppress the confirmation.")
		searchUpdatesPtr = flag.Bool("search-updates", false, "look for updates and print available")
	} else {
		serviceInstallUserPtr = flag.String("s", "", fmt.Sprintf("username to install and start the system service(%s)", systemManager.String()))
	}

	flag.Parse()
	// version should be handled first to ensure it will be accessible in case of fatal errors before
	handleFlagVersion(*versionPtr)

	// check some incompatible flags
	if serviceInstallUserPtr != nil && *serviceInstallUserPtr != "" ||
		serviceInstallPtr != nil && *serviceInstallPtr {
		if *inputFilePtr != "" {
			fmt.Println("Input file(-i) flag can't be used together with service install(-s) flag")
			os.Exit(1)
		}

		if *outputFilePtr != "" {
			fmt.Println("Output file(-o) flag can't be used together with service install(-s) flag")
			os.Exit(1)
		}

		if *serviceUninstallPtr {
			fmt.Println("Service uninstall(-u) flag can't be used together with service install(-s) flag")
			os.Exit(1)
		}

		if *serviceStartPtr || *serviceRestartPtr || *serviceStopPtr || *serviceStatusPtr {
			fmt.Println("Service management flags can't be used together with service install(-s) flag")
			os.Exit(1)
		}
	}

	cfg, err := frontman.HandleAllConfigSetup(*cfgPathPtr)
	if err != nil {
		log.Fatalf("Failed to handle frontman configuration: %s", err)
	}

	fm, err := frontman.New(cfg, *cfgPathPtr, frontman.Version)
	if err != nil {
		log.Fatalf("Failed to initialize frontman: %s", err)
	}

	handleFlagPrintStats(*statsPtr, fm)
	handleFlagPrintConfig(*printConfigPtr, fm)
	handleFlagSearchUpdates(searchUpdatesPtr)
	handleFlagUpdate(updatePtr, assumeYesPtr)
	handleFlagTest(*testConfigPtr, fm)
	handleFlagSettings(settingsPtr, fm)

	setDefaultLogFormatter()

	// log level set in flag has a precedence. If specified we need to set it ASAP
	handleFlagLogLevel(fm, *logLevelPtr)

	printOSSpecificWarnings()

	writePidFileIfNeeded(fm, oneRunOnlyModePtr)
	defer removePidFileIfNeeded(fm, oneRunOnlyModePtr)

	handleToastFeedback(fm, *cfgPathPtr)

	log.Info("frontman " + frontman.Version + " started")

	if !*oneRunOnlyModePtr && !*testConfigPtr && *inputFilePtr == "" && *outputFilePtr == "" && cfg.HTTPListener.HTTPListen != "" {
		go func() {
			if err := fm.ServeWeb(); err != nil {
				log.Fatal(err)
			}
		}()
	}

	if !service.Interactive() {
		runUnderOsServiceManager(fm)
	}

	if (serviceInstallPtr == nil || !*serviceInstallPtr) &&
		(serviceInstallUserPtr == nil || len(*serviceInstallUserPtr) == 0) &&
		!*serviceUninstallPtr {
		handleServiceCommand(fm, *serviceStatusPtr, *serviceStartPtr, *serviceStopPtr, *serviceRestartPtr)
	}

	handleFlagServiceUpgrade(fm, *cfgPathPtr, serviceUpgradePtr, serviceInstallUserPtr)
	handleFlagServiceUninstall(fm, *serviceUninstallPtr)
	handleFlagServiceInstall(fm, systemManager, serviceInstallUserPtr, serviceInstallPtr, *cfgPathPtr, assumeYesPtr)
	handleFlagDaemonizeMode(*daemonizeModePtr)

	// setup interrupt handler
	interruptChan := make(chan struct{})
	output := handleFlagInputOutput(*inputFilePtr, *outputFilePtr, *oneRunOnlyModePtr)
	if output != nil {
		defer output.Close()
	}

	handleFlagOneRunOnlyMode(fm, *oneRunOnlyModePtr, *inputFilePtr, output, interruptChan)

	// nothing resulted in os.Exit
	// so lets use the default continuous run mode and wait for interrupt
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM)
	doneChan := make(chan struct{})
	go func() {
		fm.Run(*inputFilePtr, output, interruptChan)
		doneChan <- struct{}{}
	}()

	//  Handle interrupts
	select {
	case sig := <-sigc:
		log.Infof("Got %s signal. Finishing the batch and exit...", sig.String())
		interruptChan <- struct{}{}
		os.Exit(0)
	case <-doneChan:
		os.Exit(0)
	}
}

func printOSSpecificWarnings() {
	var osNotice string
	if runtime.GOOS == "windows" && !frontman.CheckIfRawICMPAvailable() {
		osNotice = "!!! You need to run frontman as administrator in order to use ICMP ping on Windows !!!"
	}
	if runtime.GOOS == "linux" && !frontman.CheckIfRootlessICMPAvailable() && !frontman.CheckIfRawICMPAvailable() {
		osNotice = `⚠️ In order to perform rootless ICMP Ping on Linux you need to run this command first:
			sudo sysctl -w net.ipv4.ping_group_range="0   2147483647"`
	}
	if osNotice != "" {
		// print to console without log formatting
		fmt.Println(osNotice)

		// disable logging to stderr temporarily
		log.SetOutput(ioutil.Discard)
		log.Error(osNotice)
		log.SetOutput(os.Stderr)
	}
}

func handleFlagVersion(versionFlag bool) {
	if versionFlag {
		fmt.Printf("frontman v%s released under MIT license. https://github.com/cloudradar-monitoring/frontman/\n", frontman.Version)
		os.Exit(0)
	}
}

func handleFlagPrintConfig(printConfig bool, fm *frontman.Frontman) {
	var configHeadline = "# Please refer to https://github.com/cloudradar-monitoring/frontman/blob/master/example.config.toml\n" +
		"# for a fully documented configuration example\n" +
		"#\n"

	if printConfig {
		fmt.Println(configHeadline)
		fmt.Println(fm.Config.DumpToml())
		os.Exit(0)
	}
}

func handleFlagUpdate(update *bool, assumeYes *bool) {
	if update != nil && *update {
		updates, err := printAvailableUpdates()
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}

		if len(updates) == 0 {
			os.Exit(0)
		}

		proceedInstallation := (assumeYes != nil && *assumeYes) || askForConfirmation("Proceed installation?")
		if !proceedInstallation {
			os.Exit(0)
		}

		fmt.Println("Downloading...")

		err = selfupdate.DownloadAndInstallUpdate(updates[len(updates)-1])
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}
		fmt.Println("Installer executed. Exiting.")
		os.Exit(0)
	}
}

func handleFlagSearchUpdates(searchUpdates *bool) {
	if searchUpdates != nil && *searchUpdates {
		_, err := printAvailableUpdates()
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}
		os.Exit(0)
	}
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

func handleFlagPrintStats(statsFlag bool, fm *frontman.Frontman) {
	if !statsFlag {
		return
	}

	buff, err := ioutil.ReadFile(fm.Config.StatsFile)
	if err != nil {
		fmt.Printf("Could not read stats file: %s\n", fm.Config.StatsFile)
		os.Exit(1)
	}

	fmt.Printf("%s", buff)
	os.Exit(0)
}

func handleFlagSettings(settingsUI *bool, fm *frontman.Frontman) {
	if settingsUI != nil && *settingsUI {
		windowsShowSettingsUI(fm, false)
		os.Exit(0)
	}
}

func handleFlagTest(testConfig bool, fm *frontman.Frontman) {
	if !testConfig {
		return
	}

	ctx := context.Background()
	err := fm.CheckHubCredentials(ctx, "hub_url", "hub_user", "hub_password")
	if err != nil {
		if runtime.GOOS == "windows" {
			// ignore toast error to make the main error clear for user
			// toast error probably means toast not supported on the system
			_ = sendErrorNotification("Hub connection check failed", err.Error())
		}
		log.WithError(err).Errorln("Hub connection check failed")
		systemService, err := getServiceFromFlags(fm, "", "")
		if err != nil {
			log.WithError(err).Fatalln("Failed to get system service")
		}

		status, err := systemService.Status()
		if err != nil {
			// service seems not installed
			// no need to show the tip on how to restart it
			os.Exit(1)
		}

		systemManager := service.ChosenSystem()
		if status == service.StatusRunning || status == service.StatusStopped {
			restartCmdSpec := getSystemMangerCommand(systemManager.String(), svcConfig.Name, "restart")
			log.WithFields(log.Fields{
				"restartCmd": restartCmdSpec,
			}).Infoln("Fix the config and then restart the service")
		}

		os.Exit(1)
	}

	if runtime.GOOS == "windows" {
		_ = sendSuccessNotification("Hub connection check is done", "")
	}
	log.Infoln("Hub connection check is done and credentials are correct!")
	os.Exit(0)
}

func handleFlagLogLevel(fm *frontman.Frontman, logLevel string) {
	// Check loglevel and if needed warn user and set to default
	if logLevel == string(frontman.LogLevelError) || logLevel == string(frontman.LogLevelInfo) || logLevel == string(frontman.LogLevelDebug) {
		fm.SetLogLevel(frontman.LogLevel(logLevel))
	} else if logLevel != "" {
		log.Warnf("Invalid log level: \"%s\". Set to default: \"%s\"", logLevel, fm.Config.LogLevel)
	}
}

func handleFlagInputOutput(inputFile string, outputFile string, oneRunOnlyMode bool) *os.File {
	if outputFile != "" && inputFile == "" {
		fmt.Println("Output(-o) flag can be only used together with input(-i)")
		os.Exit(1)
	}

	if inputFile == "" {
		return nil
	}

	var output *os.File
	var err error

	// Set output to stdout
	if outputFile == "-" {
		log.SetOutput(ioutil.Discard)
		output = os.Stdout
		return output
	}

	// Try to create the output file directory if it does not exist
	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		dir := filepath.Dir(outputFile)
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			err = os.MkdirAll(dir, 0644)
			if err != nil {
				log.WithError(err).Fatalf("Failed to create the output file directory: '%s'", dir)
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
			log.WithError(err).Fatalf("Failed to open the output file: '%s'", outputFile)
		}
	}
	return output
}

func handleFlagOneRunOnlyMode(fm *frontman.Frontman, oneRunOnlyMode bool, inputFile string, output *os.File, interruptChan chan struct{}) {
	if !oneRunOnlyMode {
		return
	}
	log.Debug("OneRunOnlyMode invoked (-r)")

	if err := fm.HealthCheck(); err != nil {
		fm.HealthCheckPassedPreviously = false
		log.WithError(err).Errorln("Health checks are not passed. Skipping other checks.")
		return
	}
	if !fm.HealthCheckPassedPreviously {
		fm.HealthCheckPassedPreviously = true
		log.Infoln("All health checks are positive. Resuming normal operation.")
	}

	input, err := fm.FetchInput(inputFile)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	err = fm.RunOnce(input, output, interruptChan)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	os.Exit(0)
}

func handleFlagDaemonizeMode(daemonizeMode bool) {
	if daemonizeMode && os.Getenv("FRONTMAN_FORK") != "1" {
		err := rerunDetached()
		if err != nil {
			fmt.Println("Failed to fork process: ", err.Error())
			os.Exit(1)
		}

		os.Exit(0)
	}
}

func handleServiceCommand(ca *frontman.Frontman, check, start, stop, restart bool) {
	if !check && !start && !stop && !restart {
		return
	}

	svc, err := getServiceFromFlags(ca, "", "")
	if err != nil {
		log.WithError(err).Fatalln("can't find service")
	}

	var status service.Status
	if status, err = svc.Status(); err != nil && err != service.ErrNotInstalled {
		log.WithError(err).Fatalln("can't get service status")
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

		os.Exit(0)
	}

	if stop && (status == service.StatusRunning) {
		if err = svc.Stop(); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		fmt.Println("stopped")
		os.Exit(0)
	} else if stop {
		fmt.Println("service is not running")
		os.Exit(0)
	}

	if start {
		if status == service.StatusRunning {
			fmt.Println("already")
			os.Exit(1)
		}

		if err = svc.Start(); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		fmt.Println("started")
		os.Exit(0)
	}

	if restart {
		if err = svc.Restart(); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		fmt.Println("restarted")
		os.Exit(0)
	}
}

func handleFlagServiceUpgrade(
	ca *frontman.Frontman,
	cfgPath string,
	serviceUpgradeFlag *bool,
	serviceInstallUserPtr *string,
) {
	if serviceUpgradeFlag == nil || !*serviceUpgradeFlag {
		return
	}

	installUser := ""
	if serviceInstallUserPtr != nil {
		installUser = *serviceInstallUserPtr
	}

	systemService, err := getServiceFromFlags(ca, cfgPath, installUser)
	if err != nil {
		log.WithError(err).Fatalln("Failed to get system service")
	}

	updateServiceConfig(ca, installUser)
	tryUpgradeServiceUnit(systemService)

	os.Exit(0)
}

func handleFlagServiceUninstall(fm *frontman.Frontman, serviceUninstallPtr bool) {
	if !serviceUninstallPtr {
		return
	}

	systemService, err := getServiceFromFlags(fm, "", "")
	if err != nil {
		log.Fatalf("Failed to get system service: %s", err.Error())
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
		os.Exit(1)
	}

	os.Exit(0)
}

func handleFlagServiceInstall(fm *frontman.Frontman, systemManager service.System, serviceInstallUserPtr *string, serviceInstallPtr *bool, cfgPath string, assumeYesPtr *bool) {
	// serviceInstallPtr is currently used on windows
	// serviceInstallUserPtr is used on other systems
	// if both of them are empty - just return
	if (serviceInstallUserPtr == nil || *serviceInstallUserPtr == "") &&
		(serviceInstallPtr == nil || !*serviceInstallPtr) {
		return
	}

	username := ""
	if serviceInstallUserPtr != nil {
		username = *serviceInstallUserPtr
	}

	s, err := getServiceFromFlags(fm, cfgPath, username)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
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

	fmt.Printf("Run this command to restart the service: %s\n\n", getSystemMangerCommand(systemManager.String(), svcConfig.Name, "restart"))

	os.Exit(0)
}

func runUnderOsServiceManager(fm *frontman.Frontman) {
	systemService, err := getServiceFromFlags(fm, "", "")
	if err != nil {
		log.Fatal(err)
	}

	// we are running under OS service manager
	err = systemService.Run()
	if err != nil {
		log.Fatal(err.Error())
	}

	os.Exit(0)
}

// serviceWrapper is created to provide context and methods that satisfies service.Interface
// in order to run Frontman under OS Service Manager
type serviceWrapper struct {
	Frontman      *frontman.Frontman
	InterruptChan chan struct{}
	DoneChan      chan struct{}
}

func (sw *serviceWrapper) Start(s service.Service) error {
	sw.InterruptChan = make(chan struct{})
	sw.DoneChan = make(chan struct{})
	go func() {
		sw.Frontman.Run("", nil, sw.InterruptChan)
		sw.DoneChan <- struct{}{}
	}()

	return nil
}

func (sw *serviceWrapper) Stop(s service.Service) error {
	sw.InterruptChan <- struct{}{}
	log.Println("Finishing the batch and stop the service...")
	<-sw.DoneChan
	return nil
}

func getServiceFromFlags(fm *frontman.Frontman, configPath, userName string) (service.Service, error) {
	prg := &serviceWrapper{Frontman: fm}

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

func writePidFileIfNeeded(fm *frontman.Frontman, oneRunOnlyModePtr *bool) {
	if fm.Config.PidFile != "" && !*oneRunOnlyModePtr && runtime.GOOS != "windows" {
		err := ioutil.WriteFile(fm.Config.PidFile, []byte(strconv.Itoa(os.Getpid())), 0664)
		if err != nil {
			log.Errorf("Failed to write pid file at: %s", fm.Config.PidFile)
		}
	}
}

func removePidFileIfNeeded(fm *frontman.Frontman, oneRunOnlyModePtr *bool) {
	if fm.Config.PidFile != "" && !*oneRunOnlyModePtr && runtime.GOOS != "windows" {
		err := os.Remove(fm.Config.PidFile)
		if err != nil {
			log.Errorf("Failed to remove pid file at: %s", fm.Config.PidFile)
		}
	}
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

func askForConfirmation(s string) bool {
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

func setDefaultLogFormatter() {
	tfmt := log.TextFormatter{FullTimestamp: true}
	if runtime.GOOS == "windows" {
		tfmt.DisableColors = true
	}

	log.SetFormatter(&tfmt)
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
