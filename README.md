## How to build from sources
- [Install Golang 1.9 or newer](https://golang.org/dl/)
```bash
go get -d -u github.com/cloudradar-monitoring/frontman
go build -o -ldflags="-X main.VERSION=$(git --git-dir=src/github.com/cloudradar-monitoring/frontman/.git describe --always --long --dirty --tag)" frontman github.com/cloudradar-monitoring/frontman/cmd/frontman
```

## Run the example

```bash
./frontman -i src/github.com/cloudradar-monitoring/frontman/example.json -o result.out
```
Use `ctrl-c` to stop it

## Configuration
Check the [example config](https://github.com/cloudradar-monitoring/frontman/blob/master/example.config.toml)

Default locations:
* Mac OS: `~/.frontman/frontman.conf`
* Windows: `./frontman.conf`
* UNIX: `/etc/frontman/frontman.conf`

## Logs location
* Mac OS: `~/.frontman/frontman.log`
* Windows: `./frontman.log`
* UNIX: `/etc/frontman/frontman.conf`

## Build binaries and deb/rpm packages
– Install [goreleaser](https://goreleaser.com/introduction/)
```bash
FRONTMAN_VERSION=$(git describe --always --long --dirty --tag) goreleaser --snapshot
```

## Build MSI package
– Should be done on Windows machine
– Open command prompt(cmd.exe)
– Go to frontman directory `cd path_to_directory`
– Run `goreleaser --snapshot` to build binaries
– Run `build-win.bat`