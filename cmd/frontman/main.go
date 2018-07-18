package main

import (
	"github.com/cloudradar-monitoring/frontman"
	log "github.com/sirupsen/logrus"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"flag"
	"fmt"
	"io/ioutil"
	"os/exec"
	"runtime"
)

func main() {
	fm := frontman.New()

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM)

	inputFilePtr := flag.String("i", "", "JSON file to read the list (required)")
	outputFilePtr := flag.String("o", "./results.out", "file to write the results")

	cfgPathPtr := flag.String("c", frontman.DefaultCfgPath, "config file path")
	logLevelPtr := flag.String("v", "", "log level – overrides the level in config file (values \"error\",\"info\",\"debug\")")

	daemonizeModePtr := flag.Bool("d", false, "daemonize – run the proccess in background")
	oneRunOnlyModePtr := flag.Bool("r", false, "one run only – perform checks once and exit. Overwrites output file")

	flag.Parse()

	tfmt := log.TextFormatter{FullTimestamp: true}
	if runtime.GOOS == "windows" {
		tfmt.DisableColors = true
	}

	log.SetFormatter(&tfmt)

	if *daemonizeModePtr && os.Getenv("FRONTMAN_FORK") != "1" {
		rerunDetached()
		log.SetOutput(ioutil.Discard)
		return
	}

	if cfgPathPtr != nil {
		err := fm.ReadConfigFromFile(*cfgPathPtr, true)
		if err != nil {
			log.Fatalf("Config load error: %s", err.Error())
		}
	}

	if *logLevelPtr == string(frontman.LogLevelError) || *logLevelPtr == string(frontman.LogLevelInfo) || *logLevelPtr == string(frontman.LogLevelDebug) {
		fm.SetLogLevel(frontman.LogLevel(*logLevelPtr))
	}

	if (inputFilePtr == nil || *inputFilePtr == "") && fm.HubURL == "" {
		fmt.Println("Missing input file flag(-i) or hub_url param in config")
		flag.PrintDefaults()
		return
	}

	var input *frontman.Input
	var err error
	var output *os.File

	if inputFilePtr != nil && *inputFilePtr != "" {
		input, err = frontman.InputFromFile(*inputFilePtr)

		if err != nil {
			log.Fatalf("InputFromFile(%s) error: %s", *inputFilePtr, err.Error())
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
				log.WithError(err).Fatalf("Failed to open the output file: '%s'")
			}
		} else {
			log.SetOutput(ioutil.Discard)
			output = os.Stdout
		}

	} else {
		input, err = frontman.InputFromHub(fm.HubURL, fm.HubUser, fm.HubPassword)

		if err != nil {
			auth := ""
			if fm.HubUser != "" {
				auth = fmt.Sprintf(" HTTP_BASIC(%s, ***)", fm.HubUser)
			}
			log.Fatalf("InputFromHub(%s%s) error: %s", fm.HubURL, auth, err.Error())
		}
	}

	log.Infof("Running %d service checks...", len(input.ServiceChecks))

	interruptChan := make(chan struct{})
	doneChan := make(chan struct{})

	if runtime.GOOS == "windows" && !frontman.CheckIfRawICMPAvailable() {
		log.Error("!!! You need to run frontman as administrator in order to use ICMP ping on Windows !!!")
	}

	if *oneRunOnlyModePtr == true {
		fm.Once(input, output)
		return
	} else {
		go func() {
			fm.Run(input, output, interruptChan)
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
