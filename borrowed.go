package frontman

import (
	"bytes"
	"context"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/shirou/gopsutil/host"
)

type Invoker interface {
	Command(string, ...string) ([]byte, error)
	CommandWithContext(context.Context, string, ...string) ([]byte, error)
}

type Invoke struct{}

func (i Invoke) Command(name string, arg ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return i.CommandWithContext(ctx, name, arg...)
}

func (i Invoke) CommandWithContext(ctx context.Context, name string, arg ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, arg...)

	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf

	if err := cmd.Start(); err != nil {
		return buf.Bytes(), err
	}

	if err := cmd.Wait(); err != nil {
		return buf.Bytes(), err
	}

	return buf.Bytes(), nil
}

var invoke Invoker = Invoke{}

func Uname() (string, error) {
	if runtime.GOOS == "windows" {
		info, err := host.Info()

		if err != nil {
			return "", err
		}
		return info.Platform + " " + info.PlatformVersion + " " + info.PlatformFamily, nil
	}
	uname, err := exec.LookPath("uname")
	if err != nil {
		return "", err
	}
	b, err := invoke.Command(uname, "-a")
	return string(b), err
}

func getFQDN() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}

	addrs, err := net.LookupIP(hostname)
	if err != nil {
		return hostname
	}

	for _, addr := range addrs {
		if ipv4 := addr.To4(); ipv4 != nil {
			ip, err := ipv4.MarshalText()
			if err != nil {
				return hostname
			}
			hosts, err := net.LookupAddr(string(ip))
			if err != nil || len(hosts) == 0 {
				return hostname
			}
			fqdn := hosts[0]
			return strings.TrimSuffix(fqdn, ".")
		}
	}
	return hostname
}
