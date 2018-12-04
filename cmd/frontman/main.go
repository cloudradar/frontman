package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/cloudradar-monitoring/frontman"
	"github.com/kardianos/service"
	log "github.com/sirupsen/logrus"
)

// set it in case user provided only input(-i) file
const defaultOutputFile = "./results.out"

var (
	// set on build:
	// go build -o frontman -ldflags="-X main.version=$(git --git-dir=src/github.com/cloudradar-monitoring/frontman/.git describe --always --long --dirty --tag)" github.com/cloudradar-monitoring/frontman/cmd/frontman
	version string
)

var svcConfig = &service.Config{
	Name:        "frontman",
	DisplayName: "Frontman",
	Description: "Monitoring proxy for agentless monitoring of subnets",
}

func main() {
	setDefaultLogFormatter()
	systemManager := service.ChosenSystem()

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM)

	var serviceInstallUserPtr *string
	var serviceInstallPtr *bool

	// Setup flag pointers
	inputFilePtr := flag.String("i", "", "JSON file to read the list (required)")
	outputFilePtr := flag.String("o", "", "file to write the results (default ./results.out)")
	cfgPathPtr := flag.String("c", frontman.DefaultCfgPath, "config file path")
	logLevelPtr := flag.String("v", "", "log level – overrides the level in config file (values \"error\",\"info\",\"debug\")")
	daemonizeModePtr := flag.Bool("d", false, "daemonize – run the proccess in background")
	oneRunOnlyModePtr := flag.Bool("r", false, "one run only – perform checks once and exit. Overwrites output file")
	serviceUninstallPtr := flag.Bool("u", false, fmt.Sprintf("stop and uninstall the system service(%s)", systemManager.String()))
	printConfigPtr := flag.Bool("p", false, "print the active config")
	versionPtr := flag.Bool("version", false, "show the frontman version")

	// some OS specific flags
	if runtime.GOOS == "windows" {
		serviceInstallPtr = flag.Bool("s", false, fmt.Sprintf("install and start the system service(%s)", systemManager.String()))
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
	}

	// initiate Frontman with default in-memory config
	fm := frontman.New(version)
	// read config file from path
	// or create the minimal config file if it doesn't exist
	err := frontman.HandleConfig(fm, *cfgPathPtr)
	if err != nil {
		log.Fatal(err)
	}

	// need to proccess some of fields that was set in frontman.New() & frontman.HandleConfig()
	// e.g. set the log level and add syslog webhook
	err = fm.Initialize()
	if err != nil {
		log.Fatal(err)
	}

	// log level set in flag has a precedence. If specified we need to set it ASAP
	handleFlagLogLevel(fm, *logLevelPtr)

	printOSSpecificWarnings()

	writePidFileIfNeeded(fm, oneRunOnlyModePtr)
	defer removePidFileIfNeeded(fm, oneRunOnlyModePtr)

	if !service.Interactive() {
		runUnderOsServiceManager(fm)
	}

	handleFlagPrintConfig(*printConfigPtr, fm)
	handleFlagServiceUninstall(fm, *serviceUninstallPtr)
	handleFlagServiceInstall(fm, systemManager, serviceInstallUserPtr, serviceInstallPtr, *cfgPathPtr)
	handleFlagDaemonizeMode(*daemonizeModePtr)

	// setup interrupt handler
	interruptChan := make(chan struct{})
	output := handleFlagInputOutput(*inputFilePtr, *outputFilePtr, *oneRunOnlyModePtr)

	handleFlagOneRunOnlyMode(fm, *oneRunOnlyModePtr, *inputFilePtr, output, interruptChan)

	// no any flag resulted in os.Exit
	// so lets use the default continuous run mode
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
		fmt.Printf("frontman v%s released under MIT license. https://github.com/cloudradar-monitoring/frontman/\n", version)
		os.Exit(0)
	}
}

func handleFlagPrintConfig(printConfig bool, fm *frontman.Frontman) {
	if printConfig {
		fmt.Println(fm.DumpConfigToml())
		os.Exit(0)
	}
}

func handleFlagLogLevel(fm *frontman.Frontman, logLevel string) {
	// Check loglevel and if needed warn user and set to default
	if logLevel == string(frontman.LogLevelError) || logLevel == string(frontman.LogLevelInfo) || logLevel == string(frontman.LogLevelDebug) {
		fm.SetLogLevel(frontman.LogLevel(logLevel))
	} else if logLevel != "" {
		log.Warnf("Invalid log level: \"%s\". Set to default: \"%s\"", logLevel, fm.LogLevel)
	}
}

func handleFlagInputOutput(inputFile string, outputFile string, oneRunOnlyMode bool) (output *os.File) {
	if outputFile != "" && inputFile == "" {
		fmt.Println("Output(-o) flag can be only used together with input(-i)")
		os.Exit(1)
	}

	if inputFile == "" {
		return nil
	}

	if inputFile != "" && outputFile == "" {
		fmt.Printf("Output file not specified. Will use the default one: %s\n", defaultOutputFile)
		outputFile = defaultOutputFile
	}

	if outputFile == "-" {
		log.SetOutput(ioutil.Discard)
		output = os.Stdout
	} else {
		if _, err := os.Stat(outputFile); os.IsNotExist(err) {
			dir := filepath.Dir(outputFile)
			if _, err := os.Stat(dir); os.IsNotExist(err) {
				err = os.MkdirAll(dir, 0644)
				if err != nil {
					log.WithError(err).Errorf("Failed to create the output file directory: '%s'", dir)
				}
			}
		}

		mode := os.O_WRONLY | os.O_CREATE

		if oneRunOnlyMode {
			mode = mode | os.O_TRUNC
		} else {
			mode = mode | os.O_APPEND
		}

		var err error
		output, err = os.OpenFile(outputFile, mode, 0644)
		if err != nil {
			log.WithError(err).Fatalf("Failed to open the output file: '%s'", outputFile)
		}
		defer output.Close()
	}

	return
}

func handleFlagOneRunOnlyMode(fm *frontman.Frontman, oneRunOnlyMode bool, inputFile string, output *os.File, interruptChan chan struct{}) {
	if oneRunOnlyMode {
		input, err := fm.FetchInput(inputFile)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		err = fm.RunOnce(input, output, interruptChan, false)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		os.Exit(0)
	}
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

func handleFlagServiceUninstall(fm *frontman.Frontman, serviceUninstallPtr bool) {
	if !serviceUninstallPtr {
		return
	}

	systemService, err := getServiceFromFlags(fm, "", "")
	if err != nil {
		log.Fatal(err)
	}

	err = systemService.Stop()
	if err != nil {
		// don't return error here, just write a warning and try to uninstall
		fmt.Println("Failed to stop the service: ", err.Error())
	}

	err = systemService.Uninstall()
	if err != nil {
		fmt.Println("Failed to uninstall the service: ", err.Error())
		os.Exit(1)
	}

	os.Exit(0)
}

func handleFlagServiceInstall(fm *frontman.Frontman, systemManager service.System, serviceInstallUserPtr *string, serviceInstallPtr *bool, cfgPath string) {
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

	if fm.HubURL == "" {
		fmt.Printf("To install the service you first need to set 'hub_url' config param")
		os.Exit(1)
	}

	if runtime.GOOS != "windows" {
		userName := *serviceInstallUserPtr
		u, err := user.Lookup(userName)
		if err != nil {
			fmt.Printf("Failed to find the user '%s'\n", userName)
			os.Exit(1)
		}

		svcConfig.UserName = userName
		// we need to chown log file with user who will run service
		// because installer can be run under root so the log file will be also created under root
		err = chownFile(fm.LogFile, u)
		if err != nil {
			fmt.Printf("Failed to chown log file for '%s' user\n", userName)
		}
	}
	const maxAttempts = 3
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		err = s.Install()
		if err != nil && strings.Contains(err.Error(), "already exists") {
			fmt.Printf("Frontman service(%s) already installed: %s\n", systemManager.String(), err.Error())

			if attempt == maxAttempts {
				fmt.Printf("Give up after %d attempts\n", maxAttempts)
				os.Exit(1)
			}

			osSpecificNote := ""
			if runtime.GOOS == "windows" {
				osSpecificNote = " Windows Services Manager app should not be opened!"
			}
			if askForConfirmation("Do you want to overwrite it?" + osSpecificNote) {
				err = s.Stop()
				if err != nil {
					fmt.Println("Failed to stop the service: ", err.Error())
				}

				// lets try to uninstall despite of this error
				err := s.Uninstall()
				if err != nil {
					fmt.Println("Failed to unistall the service: ", err.Error())
					os.Exit(1)
				}
			}

		} else if err != nil {
			fmt.Printf("Frontman service(%s) installing error: %s\n", systemManager.String(), err.Error())
			os.Exit(1)
		} else {
			break
		}
	}

	fmt.Printf("Frontman service(%s) installed. Starting...\n", systemManager.String())
	err = s.Start()
	if err != nil {
		fmt.Println(err.Error())
	}

	switch systemManager.String() {
	case "unix-systemv":
		fmt.Printf("Run this command to stop it:\nsudo service %s stop\n\n", svcConfig.Name)
	case "linux-upstart":
		fmt.Printf("Run this command to stop it:\nsudo initctl stop %s\n\n", svcConfig.Name)
	case "linux-systemd":
		fmt.Printf("Run this command to stop it:\nsudo systemctl stop %s.service\n\n", svcConfig.Name)
	case "darwin-launchd":
		fmt.Printf("Run this command to stop it:\nsudo launchctl unload %s\n\n", svcConfig.Name)
	case "windows-service":
		fmt.Printf("Use the Windows Service Manager to stop it\n\n")
	}

	fmt.Printf("Log file located at: %s\n", fm.LogFile)
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
				return nil, fmt.Errorf("Failed to get absolute path to config at '%s': %s", configPath, err)
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
	if fm.PidFile != "" && !*oneRunOnlyModePtr && runtime.GOOS != "windows" {
		err := ioutil.WriteFile(fm.PidFile, []byte(strconv.Itoa(os.Getpid())), 0664)
		if err != nil {
			log.Errorf("Failed to write pid file at: %s", fm.PidFile)
		}
	}
}

func removePidFileIfNeeded(fm *frontman.Frontman, oneRunOnlyModePtr *bool) {
	if fm.PidFile != "" && !*oneRunOnlyModePtr && runtime.GOOS != "windows" {
		err := os.Remove(fm.PidFile)
		if err != nil {
			log.Errorf("Failed to remove pid file at: %s", fm.PidFile)
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

func chownFile(filePath string, u *user.User) error {
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return fmt.Errorf("Chown files: error converting UID(%s) to int", u.Uid)
	}

	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return fmt.Errorf("Chown files: error converting GID(%s) to int", u.Gid)
	}

	return os.Chown(filePath, uid, gid)
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
