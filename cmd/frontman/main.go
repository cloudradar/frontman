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

	"github.com/kardianos/service"
	log "github.com/sirupsen/logrus"

	"github.com/cloudradar-monitoring/frontman"
)

var (
	// set on build:
	// go build -o frontman -ldflags="-X main.version=$(git --git-dir=src/github.com/cloudradar-monitoring/frontman/.git describe --always --long --dirty --tag)" github.com/cloudradar-monitoring/frontman/cmd/frontman
	version string
)

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

func main() {
	fm := frontman.New()
	fm.SetVersion(version)

	defer func() {
		if runtime.GOOS == "windows" {
			_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
			if err != nil {
				log.Errorf("Seems frontman(%s) doesn't have admin rights: %s", runtime.GOARCH, err.Error())
			} else {
				log.Infof("Seems frontman(%s) have admin rights!", runtime.GOARCH)
			}
		}
	}()
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM)

	var serviceInstallUserPtr *string
	var serviceInstallPtr *bool
	inputFilePtr := flag.String("i", "", "JSON file to read the list (required)")
	outputFilePtr := flag.String("o", "", "file to write the results (default ./results.out)")

	cfgPathPtr := flag.String("c", frontman.DefaultCfgPath, "config file path")
	logLevelPtr := flag.String("v", "", "log level – overrides the level in config file (values \"error\",\"info\",\"debug\")")
	systemManager := service.ChosenSystem()
	daemonizeModePtr := flag.Bool("d", false, "daemonize – run the proccess in background")
	oneRunOnlyModePtr := flag.Bool("r", false, "one run only – perform checks once and exit. Overwrites output file")

	if runtime.GOOS == "windows" {
		serviceInstallPtr = flag.Bool("s", false, fmt.Sprintf("install and start the system service(%s)", systemManager.String()))
	} else {
		serviceInstallUserPtr = flag.String("s", "", fmt.Sprintf("username to install and start the system service(%s)", systemManager.String()))
	}

	serviceUninstallPtr := flag.Bool("u", false, fmt.Sprintf("stop and uninstall the system service(%s)", systemManager.String()))
	versionPtr := flag.Bool("version", false, "show the frontman version")

	flag.Parse()

	if *versionPtr {
		fmt.Printf("frontman v%s released under MIT license. https://github.com/cloudradar-monitoring/frontman/\n", version)
		return
	}
	tfmt := log.TextFormatter{FullTimestamp: true}
	if runtime.GOOS == "windows" {
		tfmt.DisableColors = true
	}

	log.SetFormatter(&tfmt)

	if cfgPathPtr != nil {
		err := fm.ReadConfigFromFile(*cfgPathPtr, true)
		if err != nil {
			if strings.Contains(err.Error(), "cannot load TOML value of type int64 into a Go float") {
				log.Fatalf("Config load error: please use numbers with a decimal point for numerical values")
			} else {
				log.Fatalf("Config load error: %s", err.Error())
			}
		}
	}

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

	if *logLevelPtr == string(frontman.LogLevelError) || *logLevelPtr == string(frontman.LogLevelInfo) || *logLevelPtr == string(frontman.LogLevelDebug) {
		fm.SetLogLevel(frontman.LogLevel(*logLevelPtr))
	}
	if (inputFilePtr == nil || *inputFilePtr == "") && fm.HubURL == "" && !*serviceUninstallPtr {
		if serviceInstallPtr != nil && *serviceInstallPtr || serviceInstallUserPtr != nil && *serviceInstallUserPtr != "" {
			fmt.Println(" ****** Before start you need to set 'hub_url' config param at ", *cfgPathPtr)
		} else {
			fmt.Println("Missing input file flag(-i) or hub_url param in config")
			flag.PrintDefaults()
			return
		}
	}

	var err error
	var output *os.File

	if inputFilePtr != nil && *inputFilePtr != "" {

		if outputFilePtr == nil || *outputFilePtr == "" {
			*outputFilePtr = "./results.out"
		}

		if *outputFilePtr != "-" {

			if _, err := os.Stat(*outputFilePtr); os.IsNotExist(err) {
				dir := filepath.Dir(*outputFilePtr)
				if _, err := os.Stat(dir); os.IsNotExist(err) {
					err = os.MkdirAll(dir, 0644)
					if err != nil {
						log.WithError(err).Errorf("Failed to create the output file directory: '%s'", dir)
					}
				}
			}

			mode := os.O_WRONLY | os.O_CREATE

			if *oneRunOnlyModePtr {
				mode = mode | os.O_TRUNC
			} else {
				mode = mode | os.O_APPEND
			}

			output, err = os.OpenFile(*outputFilePtr, mode, 0644)
			defer output.Close()

			if err != nil {
				log.WithError(err).Fatalf("Failed to open the output file: '%s'", *outputFilePtr)
			}
		} else {
			log.SetOutput(ioutil.Discard)
			output = os.Stdout
		}

	} else {
		if outputFilePtr != nil && *outputFilePtr != "" {
			fmt.Println("Output(-o) flag can be only used together with input(-i)")
			return
		}
	}

	if serviceInstallPtr != nil && *serviceInstallPtr || serviceInstallUserPtr != nil && *serviceInstallUserPtr != "" || *serviceUninstallPtr || !service.Interactive() {
		prg := &serviceWrapper{Frontman: fm}
		if cfgPathPtr != nil && *cfgPathPtr != frontman.DefaultCfgPath {
			path := *cfgPathPtr
			if !filepath.IsAbs(path) {
				path, err = filepath.Abs(path)
				if err != nil {
					log.Fatalf("Failed to get absolute path to config at '%s': %s", path, err)
				}
			}
			svcConfig.Arguments = []string{"-c", path}
		}

		s, err := service.New(prg, svcConfig)
		if err != nil {
			log.Fatal(err)
		}

		if service.Interactive() {

			if *serviceUninstallPtr {
				err = s.Stop()
				if err != nil {
					fmt.Println("Failed to stop the service: ", err.Error())
				}

				err = s.Uninstall()

				if err != nil {
					fmt.Println("Failed to uninstall the service: ", err.Error())
				}
				return
			}

			if inputFilePtr != nil && *inputFilePtr != "" {
				fmt.Println("Input file(-i) flag can't be used together with service install(-s) flag")
				return
			}
			if outputFilePtr != nil && *outputFilePtr != "" {
				fmt.Println("Output file(-o) flag can't be used together with service install(-s) flag")
				return
			}
			if runtime.GOOS != "windows" {

				u, err := user.Lookup(*serviceInstallUserPtr)
				if err != nil {
					log.Errorf("Failed to find the user '%s'", *serviceInstallUserPtr)
					return
				} else {
					svcConfig.UserName = *serviceInstallUserPtr
				}
				defer func() {
					uid, err := strconv.Atoi(u.Uid)
					if err != nil {
						log.Errorf("Chown files: error converting UID(%s) to int", u.Uid)
						return
					}

					gid, err := strconv.Atoi(u.Gid)
					if err != nil {
						log.Errorf("Chown files: error converting GID(%s) to int", u.Gid)
						return
					}
					os.Chown(fm.LogFile, uid, gid)
				}()
			}

		install:
			err = s.Install()

			if err != nil && strings.Contains(err.Error(), "already exists") {

				fmt.Printf("Frontman service(%s) already installed: %s\n", systemManager.String(), err.Error())

				note := ""
				if runtime.GOOS == "windows" {
					note = " Windows Services Manager app should not be opened!"
				}
				if askForConfirmation("Do you want to overwrite it?" + note) {
					s.Stop()
					err := s.Uninstall()
					if err != nil {
						fmt.Printf("Failed to unistall the service: %s\n", err.Error())
						return
					}
					goto install
				}
				s.Uninstall()

			} else if err != nil {
				fmt.Printf("Frontman service(%s) installing error: %s", systemManager.String(), err.Error())
				return
			} else {
				fmt.Printf("Frontman service(%s) installed. Starting...\n", systemManager.String())
			}

			err = s.Start()

			if err != nil {
				fmt.Printf("Already running\n")
			}

			switch systemManager.String() {
			case "unix-systemv":
				fmt.Printf("Run this command to stop/start it:\nservice %s stop\nservice %s start\n\n", svcConfig.Name, svcConfig.Name)
			case "linux-upstart", "linux-systemd":
				fmt.Printf("Run this command to stop/start it:\nstop %s\nstart %s\n\n", svcConfig.Name, svcConfig.Name)
			case "darwin-launchd":
				fmt.Printf("Run this command to stop/start it:\nlaunchctl unload %s\nlaunchctl load %s\n\n", svcConfig.Name, svcConfig.Name)
			case "windows-service":
				fmt.Printf("Use the Windows Service Manager to stop/start it\n\n")
			}

			fmt.Printf("Logs file located at: %s\n", fm.LogFile)
			return
		}

		err = s.Run()

		if err != nil {
			log.Error(err.Error())
		}

		return
	}

	if *daemonizeModePtr && os.Getenv("FRONTMAN_FORK") != "1" {
		rerunDetached()
		log.SetOutput(ioutil.Discard)

		return
	}

	interruptChan := make(chan struct{})
	doneChan := make(chan struct{})

	if *oneRunOnlyModePtr == true {
		fm.Run(inputFilePtr, output, interruptChan, true)
		return
	} else {
		go func() {
			fm.Run(inputFilePtr, output, interruptChan, false)
			doneChan <- struct{}{}
		}()
	}

	select {
	case sig := <-sigc:
		log.Infof("Got %s signal. Finishing the batch and exit...", sig.String())
		interruptChan <- struct{}{}
		os.Exit(0)
	case <-doneChan:
		return
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

	cmd.Process.Release()
	return nil
}

type serviceWrapper struct {
	Frontman      *frontman.Frontman
	InterruptChan chan struct{}
	DoneChan      chan struct{}
}

func (sw *serviceWrapper) Start(s service.Service) error {
	sw.InterruptChan = make(chan struct{})
	sw.DoneChan = make(chan struct{})
	go func() {
		s := ""
		sw.Frontman.Run(&s, nil, sw.InterruptChan, false)
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

var svcConfig = &service.Config{
	Name:        "frontman",
	DisplayName: "Frontman",
	Description: "Monitoring proxy for agentless monitoring of subnets",
}
