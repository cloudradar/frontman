package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strconv"
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
	handleFlagVersion(*versionPtr)

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

	handleFlagPrintStats(*statsPtr, fm)
	handleFlagPrintConfig(*printConfigPtr, fm)
	handleFlagSearchUpdates(searchUpdatesPtr)
	handleFlagUpdate(updatePtr, assumeYesPtr)
	if *testConfigPtr {
		exitCode = fm.HandleFlagTest()
		return
	}
	handleFlagSettings(settingsPtr, fm)

	setDefaultLogFormatter()

	// log level set in flag has a precedence. If specified we need to set it ASAP
	handleFlagLogLevel(fm, *logLevelPtr)

	printOSSpecificWarnings()

	writePidFileIfNeeded(fm, oneRunOnlyModePtr)
	defer removePidFileIfNeeded(fm, oneRunOnlyModePtr)

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
	handleFlagDaemonizeMode(*daemonizeModePtr)

	// in case HUB server will hang on response we will need a buffer to continue perform checks
	resultsChan := make(chan frontman.Result, 100)

	// setup interrupt handler
	interruptChan := make(chan struct{})
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

		proceedInstallation := (assumeYes != nil && *assumeYes) || frontman.AskForConfirmation("Proceed installation?")
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
		winui.WindowsShowSettingsUI(fm, false)
		os.Exit(0)
	}
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

func setDefaultLogFormatter() {
	tfmt := log.TextFormatter{FullTimestamp: true}
	if runtime.GOOS == "windows" {
		tfmt.DisableColors = true
	}

	log.SetFormatter(&tfmt)
}
