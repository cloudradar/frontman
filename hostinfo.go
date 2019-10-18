package frontman

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/host"
	"github.com/shirou/gopsutil/mem"
	"github.com/sirupsen/logrus"
)

// HostInfoResults fetches information about the host itself which can be
// send to the hub alongside measurements.
func (fm *Frontman) HostInfoResults() (MeasurementsMap, error) {
	res := MeasurementsMap{}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	info, err := host.InfoWithContext(ctx)
	errs := []string{}

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			err = fmt.Errorf("timeout exceeded")
		}

		logrus.Errorf("[SYSTEM] Failed to read host info: %s", err.Error())
		errs = append(errs, err.Error())
	}

	for _, field := range fm.Config.HostInfo {
		switch strings.ToLower(field) {
		case "os_kernel":
			if info != nil {
				res[field] = info.OS
			} else {
				res[field] = nil
			}
		case "os_family":
			if info != nil {
				res[field] = info.PlatformFamily
			} else {
				res[field] = nil
			}
		case "uname":
			uname, err := Uname()
			if err != nil {
				logrus.Errorf("[SYSTEM] Failed to read host uname: %s", err.Error())
				errs = append(errs, err.Error())
				res[field] = nil
			} else {
				res[field] = uname
			}
		case "fqdn":
			res[field] = getFQDN()
		case "cpu_model":
			cpuInfo, err := cpu.Info()
			if err != nil {
				logrus.Errorf("[SYSTEM] Failed to read cpu info: %s", err.Error())
				errs = append(errs, err.Error())
				res[field] = nil
				continue
			}
			res[field] = cpuInfo[0].ModelName
		case "os_arch":
			res[field] = runtime.GOARCH
		case "memory_total_b":
			memStat, err := mem.VirtualMemory()
			if err != nil {
				logrus.Errorf("[SYSTEM] Failed to read mem info: %s", err.Error())
				errs = append(errs, err.Error())
				res[field] = nil
				continue
			}
			res[field] = memStat.Total
		case "hostname":
			name, err := os.Hostname()
			if err != nil {
				logrus.Errorf("[SYSTEM] Failed to read hostname: %s", err.Error())
				errs = append(errs, err.Error())
				res[field] = nil
				continue
			}
			res[field] = name
		}
	}

	if len(errs) == 0 {
		return res, nil
	}

	return res, errors.New("SYSTEM: " + strings.Join(errs, "; "))
}
