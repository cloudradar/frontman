module github.com/cloudradar-monitoring/frontman

go 1.15

require (
	github.com/StackExchange/wmi v1.2.1 // indirect
	github.com/cloudradar-monitoring/selfupdate v0.0.0-20200615195818-3bc6d247a637
	github.com/cloudradar-monitoring/toml v0.4.3-0.20190904091934-b07890c4335d
	github.com/felixge/httpsnoop v1.0.2 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.3 // indirect
	github.com/go-ldap/ldap/v3 v3.4.1
	github.com/go-ping/ping v0.0.0-20210911151512-381826476871
	github.com/google/uuid v1.3.0 // indirect
	github.com/gorilla/handlers v1.5.1
	github.com/gosnmp/gosnmp v1.32.0
	github.com/hashicorp/go-version v1.3.0 // indirect
	github.com/kardianos/service v1.2.0
	github.com/lxn/walk v0.0.0-20190515104301-6cf0bf1359a5
	github.com/lxn/win v0.0.0-20190514122436-6f00d814e89c
	github.com/nu7hatch/gouuid v0.0.0-20131221200532-179d4d0c4d8d // indirect
	github.com/pkg/errors v0.9.1
	github.com/shirou/gopsutil v3.21.8+incompatible
	github.com/shirou/w32 v0.0.0-20160930032740-bb4de0191aa4
	github.com/sirupsen/logrus v1.8.1
	github.com/stretchr/testify v1.7.0
	github.com/tklauser/go-sysconf v0.3.9 // indirect
	golang.org/x/crypto v0.0.0-20210921155107-089bfa567519 // indirect
	golang.org/x/net v0.0.0-20210924054057-cf34111cab4d
	golang.org/x/sys v0.0.0-20210923061019-b8560ed6a9b7
	gopkg.in/Knetic/govaluate.v3 v3.0.0 // indirect
	gopkg.in/toast.v1 v1.0.0-20180812000517-0a84660828b2
)

replace github.com/kardianos/service v1.0.1-0.20190514155156-fffe6c52ed0f => github.com/cloudradar-monitoring/service v1.0.1-0.20190819150840-489f2db8fe1e
