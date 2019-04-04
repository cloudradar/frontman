// +build !windows

package main

import (
	"github.com/cloudradar-monitoring/frontman"
)

// windowsShowSettingsUI stub exists only for cross-platform compiling on platforms that don't implement Windows UI.
func windowsShowSettingsUI(_ *frontman.Frontman, _ bool) {

}
