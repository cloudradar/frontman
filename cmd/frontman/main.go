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
	oneRunOnlyModePtr := flag.Bool("r", false, "one run only – perform checks once and exit, useful for testing")

	flag.Parse()

	if *daemonizeModePtr && os.Getenv("FRONTMAN_FORK") != "1" {
		rerunDetached()
		log.SetOutput(ioutil.Discard)
		return
	}

	if cfgPathPtr != nil {
		fm.ReadConfigFromFile(*cfgPathPtr, true)
	}

	if *logLevelPtr == string(frontman.LogLevelError) || *logLevelPtr == string(frontman.LogLevelInfo) || *logLevelPtr == string(frontman.LogLevelDebug) {
		fm.SetLogLevel(frontman.LogLevel(*logLevelPtr))
	}

	fm.OneRunOnly = *oneRunOnlyModePtr

	if inputFilePtr == nil || *inputFilePtr == "" {
		fmt.Println("Missing input file")
		flag.PrintDefaults()
		return
	}

	input, err := frontman.InputFromFile(*inputFilePtr)

	if err != nil {
		log.Fatal(err)
	}

	var output *os.File
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

		output, err = os.OpenFile(*outputFilePtr, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
		defer output.Close()

		if err != nil {
			log.WithError(err).Fatalf("Failed to open the output file: '%s'")
		}
	} else {
		log.SetOutput(ioutil.Discard)
		output = os.Stdout
	}

	log.Infof("Running %d service checks...", len(input.ServiceChecks))

	interruptChan := make(chan struct{})
	doneChan := make(chan struct{})

	go func() {
		fm.Run(input, output, interruptChan)
		doneChan <- struct{}{}
	}()

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

	fmt.Printf("Frontman will continue in background...\nPID %d", cmd.Process)

	cmd.Process.Release()
	return nil
}
