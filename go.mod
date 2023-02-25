module github.com/cloudradar-monitoring/frontman

go 1.15

require (
	github.com/StackExchange/wmi v0.0.0-20190523213315-cbe66965904d // indirect
	github.com/cloudradar-monitoring/selfupdate v0.0.0-20200615195818-3bc6d247a637
	github.com/cloudradar-monitoring/toml v0.4.3-0.20190904091934-b07890c4335d
	github.com/go-ole/go-ole v1.2.4 // indirect
	github.com/go-ping/ping v0.0.0-20201022122018-3977ed72668a
	github.com/golang/mock v1.4.4 // indirect
	github.com/gorilla/handlers v1.5.1
	github.com/kardianos/service v1.2.0
	github.com/lxn/walk v0.0.0-20190515104301-6cf0bf1359a5
	github.com/lxn/win v0.0.0-20190514122436-6f00d814e89c
	github.com/nu7hatch/gouuid v0.0.0-20131221200532-179d4d0c4d8d // indirect
	github.com/pkg/errors v0.9.1
	github.com/shirou/gopsutil v2.20.9+incompatible
	github.com/shirou/w32 v0.0.0-20160930032740-bb4de0191aa4
	github.com/sirupsen/logrus v1.7.0
	github.com/soniah/gosnmp v1.21.1-0.20190510081145-1b12be15031c
	github.com/stretchr/testify v1.6.1
	golang.org/x/net v0.7.0
	golang.org/x/sys v0.5.0
	gopkg.in/Knetic/govaluate.v3 v3.0.0 // indirect
	gopkg.in/asn1-ber.v1 v1.0.0-20181015200546-f715ec2f112d // indirect
	gopkg.in/ldap.v3 v3.0.3
	gopkg.in/toast.v1 v1.0.0-20180812000517-0a84660828b2
)

replace github.com/kardianos/service v1.0.1-0.20190514155156-fffe6c52ed0f => github.com/cloudradar-monitoring/service v1.0.1-0.20190819150840-489f2db8fe1e
