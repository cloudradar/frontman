// +build !windows

package notification

import (
	"errors"
)

func SendErrorNotification(_, _ string) error {
	return errors.New("implemented only or Windows")
}

func SendSuccessNotification(_, _ string) error {
	return errors.New("implemented only or Windows")
}
