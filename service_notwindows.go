// +build !windows

package frontman

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"

	"github.com/kardianos/service"
	"github.com/sirupsen/logrus"
)

func updateServiceConfig(fm *Frontman, userName string) {
	u, err := user.Lookup(userName)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"user": userName,
		}).WithError(err).Fatalln("Failed to find the user")
	}
	svcConfig.UserName = userName
	// we need to chown log file with user who will run service
	// because installer can be run under root so the log file will be also created under root
	err = chownFile(fm.Config.LogFile, u)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"user": userName,
		}).WithError(err).Warnln("Failed to chown log file")
	}
}

func chownFile(filePath string, u *user.User) error {
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return fmt.Errorf("chown files: error converting UID(%s) to int", u.Uid)
	}

	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return fmt.Errorf("chown files: error converting GID(%s) to int", u.Gid)
	}

	return os.Chown(filePath, uid, gid)
}

func configureServiceEnabledState(s service.Service) {
	serviceMgrName := s.Platform()
	isServiceAlreadyEnabled := true
	if serviceMgrName == "linux-systemd" {
		isServiceAlreadyEnabled = checkIfSystemdServiceEnabled(svcConfig.Name)
	}
	if serviceMgrName == "unix-systemv" {
		isServiceAlreadyEnabled = checkIfSysvServiceEnabled(svcConfig.Name)
	}

	if svcConfig.Option == nil {
		svcConfig.Option = service.KeyValue{}
	}

	svcConfig.Option["Enabled"] = isServiceAlreadyEnabled
}

func checkIfSystemdServiceEnabled(serviceName string) bool {
	cmd := exec.Command("systemctl", "is-enabled", serviceName+".service")
	err := cmd.Run()
	return err == nil
}

func checkIfSysvServiceEnabled(serviceName string) bool {
	configPath := "/etc/init.d/" + serviceName
	runLevels := []string{"1", "2", "3", "4", "5"}

	// search config symlinks in each runlevel folder:
	for _, level := range runLevels {
		dirFiles, _ := filepath.Glob("/etc/rc" + level + ".d/*" + serviceName)
		for _, file := range dirFiles {
			linkSrc, _ := filepath.EvalSymlinks(file)
			if absLinkPath, _ := filepath.Abs(linkSrc); absLinkPath == configPath {
				return true
			}
		}
	}

	return false
}
