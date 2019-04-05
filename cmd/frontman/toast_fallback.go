// +build !windows

package main

import (
	"errors"

	"github.com/cloudradar-monitoring/frontman"
)

func sendErrorNotification(_, _ string) error {
	return errors.New("implemented only or Windows")
}

func sendSuccessNotification(_, _ string) error {
	return errors.New("implemented only or Windows")
}

func handleToastFeedback(_ *frontman.Frontman, _ string) {
	// only for windows
}
