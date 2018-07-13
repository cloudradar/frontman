## Requirements

[Golang 1.9 or newer](https://golang.org/dl/)

## How to install from sources

```bash
go get -u github.com/cloudradar-monitoring/frontman
go build github.com/cloudradar-monitoring/frontman/cmd/frontman
```

## Run the example

```bash
./frontman -i src/github.com/cloudradar-monitoring/frontman/example.json -o result.out
```
Use `ctrl-c` to stop it

## Configuration location
It will be automatically created on the first run. You can open it to check the possible options
* Mac OS: `~/.frontman/frontman.conf`
* Windows: `./frontman.conf`
* UNIX: `/etc/frontman/frontman.conf`

## Logs location
* Mac OS: `~/.frontman/frontman.log`
* Windows: `./frontman.log`
* UNIX: `/etc/frontman/frontman.conf`

