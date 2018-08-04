## How to build from sources
- [Install Golang 1.9 or newer](https://golang.org/dl/)
- [Install Go Dep](https://golang.github.io/dep/docs/installation.html)
```bash
go get -d github.com/cloudradar-monitoring/frontman
cd $GOPATH/src/github.com/cloudradar-monitoring/frontman
dep ensure -vendor-only
go build -o frontman github.com/cloudradar-monitoring/frontman/cmd/frontman
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

