// +build windows

package notification

import (
	"os"
	"path/filepath"

	"gopkg.in/toast.v1"
)

const toastErrorIcon = "resources\\error.png"
const toastSuccessIcon = "resources\\success.png"
const toastAppID = "cloudradar.frontman"

func getExecutablePath() string {
	ex, err := os.Executable()
	if err != nil {
		return ""
	}

	return filepath.Dir(ex)
}

func SendErrorNotification(title, message string) error {
	msg := toast.Notification{
		AppID:    toastAppID,
		Title:    title,
		Message:  message,
		Duration: toast.Long, // last for 25sec
		Actions: []toast.Action{{
			Type:      "protocol",
			Label:     "Open settings",
			Arguments: "frontman:settings",
		}}}

	iconPath := getExecutablePath() + "\\" + toastErrorIcon
	if _, err := os.Stat(iconPath); err == nil {
		msg.Icon = iconPath
	}
	return msg.Push()
}

func SendSuccessNotification(title, message string) error {
	msg := toast.Notification{
		AppID:    toastAppID,
		Title:    title,
		Message:  message,
		Duration: toast.Long, // last for 25sec
		Actions:  []toast.Action{},
	}

	iconPath := getExecutablePath() + "\\" + toastSuccessIcon
	if _, err := os.Stat(iconPath); err == nil {
		msg.Icon = iconPath
	}
	return msg.Push()
}
