 # Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
BINARY_NAME=frontman
# BINARY_UNIX=$(BINARY_NAME)_unix

all: test build
build: 
	$(GOBUILD) -o $(BINARY_NAME) -v ./cmd/frontman/...

test: 
	$(GOTEST) -v ./...

clean: 
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	# rm -f $(BINARY_UNIX)

run:
	$(GOBUILD) -o $(BINARY_NAME) -v ./cmd/frontman/...
	./$(BINARY_NAME)

ci: goreleaser-rm-dist windows-sign

goreleaser-rm-dist:
	goreleaser --rm-dist

goreleaser-snapshot:
	goreleaser --snapshot

windows-sign:
	# Create remote build dir
	ssh -i /tmp/id_win_ssh -p 24481 -oStrictHostKeyChecking=no hero@144.76.9.139 mkdir -p /cygdrive/C/Users/hero/ci/frontman_ci/build_msi/${CIRCLE_BUILD_NUM}/dist
	# Copy exe files to Windows VM for bundingling and signing
	scp -i /tmp/id_win_ssh -P 24481 -oStrictHostKeyChecking=no /go/src/github.com/cloudradar-monitoring/frontman/dist/windows_386/frontman.exe  hero@144.76.9.139:/cygdrive/C/Users/hero/ci/frontman_ci/build_msi/${CIRCLE_BUILD_NUM}/dist/frontman_386.exe
	scp -i /tmp/id_win_ssh -P 24481 -oStrictHostKeyChecking=no /go/src/github.com/cloudradar-monitoring/frontman/dist/windows_amd64/frontman.exe hero@144.76.9.139:/cygdrive/C/Users/hero/ci/frontman_ci/build_msi/${CIRCLE_BUILD_NUM}/dist/frontman_64.exe
	# Copy other build dependencies
	scp -i /tmp/id_win_ssh -P 24481 -oStrictHostKeyChecking=no /go/src/github.com/cloudradar-monitoring/frontman/build-win.bat hero@144.76.9.139:/cygdrive/C/Users/hero/ci/frontman_ci/build_msi/${CIRCLE_BUILD_NUM}/build-win.bat
	ssh -i /tmp/id_win_ssh -p 24481 -oStrictHostKeyChecking=no hero@144.76.9.139 chmod +x /cygdrive/C/Users/hero/ci/frontman_ci/build_msi/${CIRCLE_BUILD_NUM}/build-win.bat
	scp -r -i /tmp/id_win_ssh -P 24481 -oStrictHostKeyChecking=no /go/src/github.com/cloudradar-monitoring/frontman/pkg-scripts/  hero@144.76.9.139:/cygdrive/C/Users/hero/ci/frontman_ci/build_msi/${CIRCLE_BUILD_NUM}
	scp -i /tmp/id_win_ssh -P 24481 -oStrictHostKeyChecking=no /go/src/github.com/cloudradar-monitoring/frontman/example.config.toml hero@144.76.9.139:/cygdrive/C/Users/hero/ci/frontman_ci/build_msi/${CIRCLE_BUILD_NUM}/example.config.toml
	scp -i /tmp/id_win_ssh -P 24481 -oStrictHostKeyChecking=no /go/src/github.com/cloudradar-monitoring/frontman/example.json hero@144.76.9.139:/cygdrive/C/Users/hero/ci/frontman_ci/build_msi/${CIRCLE_BUILD_NUM}/example.json
	scp -i /tmp/id_win_ssh -P 24481 -oStrictHostKeyChecking=no /go/src/github.com/cloudradar-monitoring/frontman/LICENSE hero@144.76.9.139:/cygdrive/C/Users/hero/ci/frontman_ci/build_msi/${CIRCLE_BUILD_NUM}/LICENSE
	scp -i /tmp/id_win_ssh -P 24481 -oStrictHostKeyChecking=no /go/src/github.com/cloudradar-monitoring/frontman/wix.json hero@144.76.9.139:/cygdrive/C/Users/hero/ci/frontman_ci/build_msi/${CIRCLE_BUILD_NUM}/wix.json
	# Trigger msi creating
	ssh -i /tmp/id_win_ssh -p 24481 -oStrictHostKeyChecking=no hero@144.76.9.139 /cygdrive/C/Users/hero/ci/frontman_ci/build_msi/${CIRCLE_BUILD_NUM}/build-win.bat ${CIRCLE_BUILD_NUM} ${CIRCLE_TAG}
	# Trigger signing 
	ssh -i /tmp/id_win_ssh -p 24481 -oStrictHostKeyChecking=no hero@144.76.9.139 curl http://localhost:8080/?file=frontman_32.msi
	ssh -i /tmp/id_win_ssh -p 24481 -oStrictHostKeyChecking=no hero@144.76.9.139 curl http://localhost:8080/?file=frontman_64.msi
	# Copy msi files back to build machine
	scp -i /tmp/id_win_ssh -P 24481 -oStrictHostKeyChecking=no hero@144.76.9.139:/cygdrive/C/Users/hero/ci/frontman_32.msi /go/src/github.com/cloudradar-monitoring/frontman/dist/frontman_386.msi
	scp -i /tmp/id_win_ssh -P 24481 -oStrictHostKeyChecking=no hero@144.76.9.139:/cygdrive/C/Users/hero/ci/frontman_64.msi /go/src/github.com/cloudradar-monitoring/frontman/dist/frontman_64.msi
	# Add files to Github release
	github-release upload --user cloudradar-monitoring --repo frontman --tag ${CIRCLE_TAG} --name "frontman_${CIRCLE_TAG}_Windows_386.msi" --file "/go/src/github.com/cloudradar-monitoring/frontman/dist/frontman_386.msi"
	github-release upload --user cloudradar-monitoring --repo frontman --tag ${CIRCLE_TAG} --name "frontman_${CIRCLE_TAG}_Windows_x86_64.msi" --file "/go/src/github.com/cloudradar-monitoring/frontman/dist/frontman_64.msi"
