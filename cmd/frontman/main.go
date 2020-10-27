package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"syscall"

	"github.com/cloudradar-monitoring/selfupdate"
	"github.com/kardianos/service"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/cloudradar-monitoring/frontman"
	"github.com/cloudradar-monitoring/frontman/pkg/winui"
)

var exitCode = 0

func exit() {
	os.Exit(exitCode)
}

func main() {
	// exit will be called last (FILO defer order)
	defer exit()

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
	cpuProfile := flag.String("cpuprofile", "", "write cpu profile to file")

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
	if *versionPtr {
		handleFlagVersion()
		return
	}

	if *cpuProfile != "" {
		fmt.Println("Starting CPU profile")
		f, err := os.Create(*cpuProfile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer func() {
			fmt.Println("Ending CPU profile")
			pprof.StopCPUProfile()
		}()
	}

	// check some incompatible flags
	if serviceInstallUserPtr != nil && *serviceInstallUserPtr != "" ||
		serviceInstallPtr != nil && *serviceInstallPtr {
		if *inputFilePtr != "" {
			fmt.Println("Input file(-i) flag can't be used together with service install(-s) flag")
			exitCode = 1
			return
		}

		if *outputFilePtr != "" {
			fmt.Println("Output file(-o) flag can't be used together with service install(-s) flag")
			exitCode = 1
			return
		}

		if *serviceUninstallPtr {
			fmt.Println("Service uninstall(-u) flag can't be used together with service install(-s) flag")
			exitCode = 1
			return
		}

		if *serviceStartPtr || *serviceRestartPtr || *serviceStopPtr || *serviceStatusPtr {
			fmt.Println("Service management flags can't be used together with service install(-s) flag")
			exitCode = 1
			return
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

	if statsPtr != nil && *statsPtr {
		exitCode = fm.HandleFlagPrintStats()
		return
	}

	if printConfigPtr != nil && *printConfigPtr {
		fm.HandleFlagPrintConfig()
		return
	}

	if searchUpdatesPtr != nil && *searchUpdatesPtr {
		exitCode = handleFlagSearchUpdates()
		return
	}

	if updatePtr != nil && *updatePtr {
		exitCode = handleFlagUpdate(assumeYesPtr)
		return
	}

	if testConfigPtr != nil && *testConfigPtr {
		exitCode = fm.HandleFlagTest()
		return
	}

	if settingsPtr != nil && *settingsPtr {
		handleFlagSettings(fm)
		return
	}

	setDefaultLogFormatter()

	// log level set in flag has a precedence. If specified we need to set it ASAP
	if err := fm.HandleFlagLogLevel(*logLevelPtr); err != nil {
		log.Warn(err)
	}

	printOSSpecificWarnings()

	if oneRunOnlyModePtr != nil && !*oneRunOnlyModePtr {
		if err := fm.WritePidFileIfNeeded(); err != nil {
			log.Error(err)
		}
		defer fm.RemovePidFileIfNeeded()
	}

	winui.HandleFeedback(fm, *cfgPathPtr)

	log.Info("frontman " + frontman.Version + " started")

	if !*oneRunOnlyModePtr && !*testConfigPtr && *inputFilePtr == "" && *outputFilePtr == "" && cfg.HTTPListener.HTTPListen != "" {
		go func() {
			if err := fm.ServeWeb(); err != nil {
				log.Fatal(err)
			}
		}()
	}

	if !service.Interactive() {
		exitCode = fm.RunUnderOsServiceManager()
		return
	}

	if (serviceInstallPtr == nil || !*serviceInstallPtr) &&
		(serviceInstallUserPtr == nil || len(*serviceInstallUserPtr) == 0) &&
		!*serviceUninstallPtr {

		if *serviceStatusPtr || *serviceStartPtr || *serviceStopPtr || *serviceRestartPtr {
			exitCode = fm.HandleServiceCommand(*serviceStatusPtr, *serviceStartPtr, *serviceStopPtr, *serviceRestartPtr)
			return
		}
	}

	if serviceUpgradePtr != nil && *serviceUpgradePtr {
		exitCode = fm.HandleFlagServiceUpgrade(*cfgPathPtr, serviceUpgradePtr, serviceInstallUserPtr)
		return
	}

	if serviceUninstallPtr != nil && *serviceUninstallPtr {
		exitCode = fm.HandleFlagServiceUninstall()
		return
	}

	if (serviceInstallUserPtr != nil && *serviceInstallUserPtr != "") || (serviceInstallPtr != nil && !*serviceInstallPtr) {
		exitCode = fm.HandleFlagServiceInstall(systemManager, *serviceInstallUserPtr, serviceInstallPtr, *cfgPathPtr, assumeYesPtr)
		return
	}

	if *daemonizeModePtr && os.Getenv("FRONTMAN_FORK") != "1" {
		exitCode = frontman.HandleFlagDaemonizeMode()
		return
	}

	// in case HUB server will hang on response we will need a buffer to continue perform checks
	resultsChan := make(chan frontman.Result, 100)

	// setup interrupt handler
	interruptChan := make(chan struct{})

	if *inputFilePtr != "" && *outputFilePtr == "" {
		fmt.Println("Output(-o) flag can be only used together with input(-i)")
		exitCode = 1
		return
	}

	output := handleFlagInputOutput(*inputFilePtr, *outputFilePtr, *oneRunOnlyModePtr)
	if output != nil {
		defer output.Close()
	}

	if *oneRunOnlyModePtr {
		exitCode = fm.HandleFlagOneRunOnlyMode(*inputFilePtr, output, interruptChan)
		return
	}

	// nothing resulted in os.Exit
	// so lets use the default continuous run mode and wait for interrupt
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM)
	doneChan := make(chan bool)
	go func() {
		fm.Run(*inputFilePtr, output, interruptChan, resultsChan)
		doneChan <- true
	}()

	//  Handle interrupts
	select {
	case sig := <-sigc:
		log.Infof("Got %s signal. Finishing the batch and exit...", sig.String())
		close(interruptChan)
		fm.TerminateQueue.Wait()
		return
	case <-doneChan:
		return
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

func handleFlagVersion() {
	fmt.Printf("frontman v%s released under MIT license. https://github.com/cloudradar-monitoring/frontman/\n", frontman.Version)
}

// returns exit code
func handleFlagUpdate(assumeYes *bool) int {

	updates, err := printAvailableUpdates()
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	if len(updates) == 0 {
		return 0
	}

	proceedInstallation := (assumeYes != nil && *assumeYes) || frontman.AskForConfirmation("Proceed installation?")
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
func handleFlagSearchUpdates() int {
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

func handleFlagSettings(fm *frontman.Frontman) {
	winui.WindowsShowSettingsUI(fm, false)
}

func handleFlagInputOutput(inputFile string, outputFile string, oneRunOnlyMode bool) *os.File {

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

func setDefaultLogFormatter() {
	tfmt := log.TextFormatter{FullTimestamp: true}
	if runtime.GOOS == "windows" {
		tfmt.DisableColors = true
	}
	log.SetFormatter(&tfmt)
}
