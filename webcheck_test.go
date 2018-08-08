package frontman_test

import (
	"context"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"
)

func TestWebchecks(t *testing.T) {
	calledResults := make(map[string]bool)
	methodsToTest := []string{"get", "post", "head"}
	methodsToTestMtx := sync.Mutex{}

	// Create http.HandlerFunc for all the methods we want to test
	// Register them under test_METHOD
	for _, m := range methodsToTest {
		endpoint := "/test_" + m
		// Put the value into an extra variable because we create a closure
		// inside the loop.
		method := m
		handleF := func(w http.ResponseWriter, r *http.Request) {
			methodsToTestMtx.Lock()
			calledResults[method] = true
			methodsToTestMtx.Unlock()
		}
		http.HandleFunc(endpoint, handleF)
	}

	testHTTPServer := http.Server{}

	serverErrorChan := make(chan error)

	go func() {
		serverErrorChan <- http.ListenAndServe("127.0.0.1:4321", nil)
	}()

	fm, err := startFrontman(t)
	if err != nil {
		t.Errorf("Failed to start frontman: %s", err)
		return
	}

	select {
	case err := <-serverErrorChan:
		t.Errorf("Error running http server: %s", err)
	// Timeout
	case <-time.After(time.Millisecond * 100):
	}

	for _, m := range methodsToTest {
		if calledResults[m] != true {
			t.Errorf("Endpoint for testing method [%s] was not called", m)
		}
	}

	testHTTPServer.Shutdown(context.Background())
	fm.Process.Signal(os.Interrupt)
}

func startFrontman(t *testing.T) (*exec.Cmd, error) {
	f, err := ioutil.TempFile("", "")
	if err != nil {
		t.Errorf("Failed to created temp config file: %s", err)
		return nil, err
	}
	f.Close()

	checksString := `{
		"webChecks": [
			{
			"checkUUID": "test_head",
			"check": { "url": "http://127.0.0.1:4321/test_head", "method": "head", "expectedHttpStatus": 200}
			},
			{
			"checkUUID": "test_post",
			"check": { "url": "http://127.0.0.1:4321/test_post", "method": "post", "expectedHttpStatus": 200}
			},
			{
				"checkUUID": "test_get",
				"check": { "url": "http://127.0.0.1:4321/test_get", "method": "get", "expectedHttpStatus": 200}
			}
		]}`
	err = ioutil.WriteFile(f.Name(), []byte(checksString), 0700)
	if err != nil {
		t.Errorf("Failed to write temp checks file: %s", err)
	}
	cmd := exec.Command("frontman", "-i", f.Name())
	// Can be useful for debugging
	// cmd.Stderr = os.Stdout
	// cmd.Stdout = os.Stdout

	go func() {
		err := cmd.Run()
		if err != nil {
			t.Errorf("Error running frontman: %s", err)
		}
	}()
	return cmd, nil
}
