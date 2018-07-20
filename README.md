## How to install from sources
[Install Golang 1.9 or newer](https://golang.org/dl/)

```bash
go get -u github.com/cloudradar-monitoring/frontman
go build -o frontman github.com/cloudradar-monitoring/frontman/cmd/frontman
./frontman
```

## Run the example

```bash
./frontman -i src/github.com/cloudradar-monitoring/frontman/example.json -o result.out
```
Use `ctrl-c` to stop it

## Configuration
Check the [example config](https://github.com/cloudradar-monitoring/frontman/blob/master/example.toml)

Default locations:
* Mac OS: `~/.frontman/frontman.conf`
* Windows: `./frontman.conf`
* UNIX: `/etc/frontman/frontman.conf`

## Logs location
* Mac OS: `~/.frontman/frontman.log`
* Windows: `./frontman.log`
* UNIX: `/etc/frontman/frontman.conf`

