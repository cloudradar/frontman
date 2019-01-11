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
	ssh -i /tmp/id_win_ssh -oStrictHostKeyChecking=no hero@13.80.137.211 mkdir -p /cygdrive/c/Users/hero/frontman_ci/build_msi/${CIRCLE_BUILD_NUM}/dist
	# Copy exe files to Windows VM for bundingling and signing
	scp -i /tmp/id_win_ssh -oStrictHostKeyChecking=no /go/src/github.com/cloudradar-monitoring/frontman/dist/windows_386/frontman.exe  hero@13.80.137.211:/cygdrive/c/Users/hero/frontman_ci/build_msi/${CIRCLE_BUILD_NUM}/dist/frontman_386.exe
	scp -i /tmp/id_win_ssh -oStrictHostKeyChecking=no /go/src/github.com/cloudradar-monitoring/frontman/dist/windows_amd64/frontman.exe hero@13.80.137.211:/cygdrive/c/Users/hero/frontman_ci/build_msi/${CIRCLE_BUILD_NUM}/dist/frontman_64.exe
	# Copy other build dependencies
	scp -i /tmp/id_win_ssh -oStrictHostKeyChecking=no /go/src/github.com/cloudradar-monitoring/frontman/build-win.bat hero@13.80.137.211:/cygdrive/c/Users/hero/frontman_ci/build_msi/${CIRCLE_BUILD_NUM}/build-win.bat
	ssh -i /tmp/id_win_ssh -oStrictHostKeyChecking=no hero@13.80.137.211 chmod +x /cygdrive/c/Users/hero/frontman_ci/build_msi/${CIRCLE_BUILD_NUM}/build-win.bat
	scp -r -i /tmp/id_win_ssh -oStrictHostKeyChecking=no /go/src/github.com/cloudradar-monitoring/frontman/pkg-scripts/  hero@13.80.137.211:/cygdrive/c/Users/hero/frontman_ci/build_msi/${CIRCLE_BUILD_NUM}
	scp -i /tmp/id_win_ssh -oStrictHostKeyChecking=no /go/src/github.com/cloudradar-monitoring/frontman/example.config.toml hero@13.80.137.211:/cygdrive/c/Users/hero/frontman_ci/build_msi/${CIRCLE_BUILD_NUM}/example.config.toml
	scp -i /tmp/id_win_ssh -oStrictHostKeyChecking=no /go/src/github.com/cloudradar-monitoring/frontman/example.json hero@13.80.137.211:/cygdrive/c/Users/hero/frontman_ci/build_msi/${CIRCLE_BUILD_NUM}/example.json
	scp -i /tmp/id_win_ssh -oStrictHostKeyChecking=no /go/src/github.com/cloudradar-monitoring/frontman/LICENSE hero@13.80.137.211:/cygdrive/c/Users/hero/frontman_ci/build_msi/${CIRCLE_BUILD_NUM}/LICENSE
	scp -i /tmp/id_win_ssh -oStrictHostKeyChecking=no /go/src/github.com/cloudradar-monitoring/frontman/wix.json hero@13.80.137.211:/cygdrive/c/Users/hero/frontman_ci/build_msi/${CIRCLE_BUILD_NUM}/wix.json
	# Trigger msi creating and signing
	ssh -i /tmp/id_win_ssh -oStrictHostKeyChecking=no hero@13.80.137.211 /cygdrive/c/Users/hero/frontman_ci/build_msi/${CIRCLE_BUILD_NUM}/build-win.bat ${CIRCLE_BUILD_NUM} ${CIRCLE_TAG} ${SIGN_CERT_PASS}
	# Copy msi files back to build machine
	scp -i /tmp/id_win_ssh -oStrictHostKeyChecking=no hero@13.80.137.211:/cygdrive/c/Users/hero/frontman_ci/build_msi/${CIRCLE_BUILD_NUM}/dist/frontman_32.msi /go/src/github.com/cloudradar-monitoring/frontman/dist/frontman_386.msi
	scp -i /tmp/id_win_ssh -oStrictHostKeyChecking=no hero@13.80.137.211:/cygdrive/c/Users/hero/frontman_ci/build_msi/${CIRCLE_BUILD_NUM}/dist/frontman_64.msi /go/src/github.com/cloudradar-monitoring/frontman/dist/frontman_64.msi
	github-release upload --user cloudradar-monitoring --repo frontman --tag ${CIRCLE_TAG} --name "frontman_${CIRCLE_TAG}_Windows_386.msi" --file "/go/src/github.com/cloudradar-monitoring/frontman/dist/frontman_386.msi"
	github-release upload --user cloudradar-monitoring --repo frontman --tag ${CIRCLE_TAG} --name "frontman_${CIRCLE_TAG}_Windows_x86_64.msi" --file "/go/src/github.com/cloudradar-monitoring/frontman/dist/frontman_64.msi"
