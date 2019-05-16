// +build windows

package main

import (
	"context"
	"strings"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func (ui *UI) reloadService() (err error) {
	ctx := context.Background()

	m, err2 := mgr.Connect()
	if err2 != nil {
		err = errors.New("Failed to connect to Windows Service Manager")
		return
	}
	defer m.Disconnect()

	s, err := m.OpenService("frontman")
	if err != nil {
		err = errors.New("Failed to find Frontman service")
		return
	}
	defer s.Close()

	ui.SaveButton.SetText("Stopping the service...")

	if err2 := stopService(ctx, s); err2 != nil {
		err = errors.New("Failed to stop Frontman service")
		return
	}

	ui.SaveButton.SetText("Starting the service...")
	if err2 := startService(ctx, s); err2 != nil {
		err = errors.New("Failed to start Frontman service")
		return
	}

	ui.StatusBar.SetText("Status: successfully connected to the Hub")
	ui.StatusBar.SetIcon(ui.SuccessIcon)
	return
}

func startService(ctx context.Context, s *mgr.Service) error {
	err := s.Start("is", "manual-started")
	if err != nil {
		err = errors.Wrap(err, "could not schedule a service to start")
		return err
	}

	return waitServiceState(ctx, s, svc.Running)
}

func stopService(ctx context.Context, s *mgr.Service) error {
	status, err := s.Control(svc.Stop)
	if err != nil {
		if strings.Contains(err.Error(), "has not been started") {
			return nil
		}
		err = errors.Wrap(err, "could not schedule a service to stop")
		return err
	}
	if status.State == svc.Stopped {
		return nil
	}
	return waitServiceState(ctx, s, svc.Stopped)
}

// waitServiceState checks the current state of a service and waits until it will match
// the expectedState, or a context deadline appearing first.
func waitServiceState(ctx context.Context, s *mgr.Service, expectedState svc.State) error {
	for {
		select {
		case <-ctx.Done():
			if ctx.Err() == context.DeadlineExceeded {
				err := errors.Wrap(ctx.Err(), "timeout waiting for service to stop")
				return err
			}
			return nil
		default:
			currentStatus, err := s.Query()
			if err != nil {
				err := errors.Wrap(err, "could not retrieve service status")
				return err
			}
			if currentStatus.State == expectedState {
				return nil
			}
			time.Sleep(300 * time.Millisecond)
		}
	}
}
