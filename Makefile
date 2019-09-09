.PHONY: synology-spk

PROJECT_DIR=/go/src/github.com/cloudradar-monitoring/frontman

 # Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GORUN=$(GOCMD) run
BINARY_NAME=frontman
# BINARY_UNIX=$(BINARY_NAME)_unix

all: test build
build:
	$(GOBUILD) -v ./cmd/frontman/...

test:
	$(GOTEST) -v ./...

clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	# rm -f $(BINARY_UNIX)

run:
	$(GORUN) -v ./cmd/frontman/...

 update-vendor:
	dep ensure
	dep ensure -update

goimports:
	goimports -l $$(find . -type f -name '*.go' -not -path "./vendor/*")

ci: goreleaser-rm-dist windows-sign

aptly:
	# Create remote work dir
	ssh -p 24480 -oStrictHostKeyChecking=no cr@repo.cloudradar.io mkdir -p /home/cr/work/aptly/frontman_${CIRCLE_BUILD_NUM}
	# Upload deb files
	rsync -e 'ssh -oStrictHostKeyChecking=no -p 24480' --recursive ${PROJECT_DIR}/dist/*.deb cr@repo.cloudradar.io:/home/cr/work/aptly/frontman_${CIRCLE_BUILD_NUM}/
	# Trigger repository update
	ssh -p 24480 -oStrictHostKeyChecking=no cr@repo.cloudradar.io /home/cr/work/aptly/update_repo.sh /home/cr/work/aptly/frontman_${CIRCLE_BUILD_NUM} ${CIRCLE_TAG}

createrepo:
	# Create remote work dir
	ssh -p 24480 -oStrictHostKeyChecking=no cr@repo.cloudradar.io mkdir -p /home/cr/work/rpm/frontman_${CIRCLE_BUILD_NUM}
	# Upload rpm files
	rsync -e 'ssh -oStrictHostKeyChecking=no -p 24480' --recursive ${PROJECT_DIR}/dist/*.rpm  cr@repo.cloudradar.io:/home/cr/work/rpm/frontman_${CIRCLE_BUILD_NUM}/
	# Trigger repository update
	ssh -p 24480 -oStrictHostKeyChecking=no cr@repo.cloudradar.io /home/cr/work/rpm/update_repo_frontman.sh /home/cr/work/rpm/frontman_${CIRCLE_BUILD_NUM} ${CIRCLE_TAG}


goreleaser-rm-dist:
	goreleaser --rm-dist

goreleaser-snapshot:
	goreleaser --snapshot

windows-sign:
	# Create remote build dir
	ssh -p 24481 -oStrictHostKeyChecking=no hero@144.76.9.139 mkdir -p /cygdrive/C/Users/hero/ci/frontman_ci/build_msi/${CIRCLE_BUILD_NUM}/dist
	# Copy exe files to Windows VM for bundingling and signing
	scp -P 24481 -oStrictHostKeyChecking=no ${PROJECT_DIR}/dist/frontman_windows_386/frontman.exe  hero@144.76.9.139:/cygdrive/C/Users/hero/ci/frontman_ci/build_msi/${CIRCLE_BUILD_NUM}/dist/frontman_386.exe
	scp -P 24481 -oStrictHostKeyChecking=no ${PROJECT_DIR}/dist/frontman_windows_amd64/frontman.exe hero@144.76.9.139:/cygdrive/C/Users/hero/ci/frontman_ci/build_msi/${CIRCLE_BUILD_NUM}/dist/frontman_64.exe
	# Copy other build dependencies
	scp -P 24481 -oStrictHostKeyChecking=no ${PROJECT_DIR}/build-win.bat hero@144.76.9.139:/cygdrive/C/Users/hero/ci/frontman_ci/build_msi/${CIRCLE_BUILD_NUM}/build-win.bat
	ssh -p 24481 -oStrictHostKeyChecking=no hero@144.76.9.139 chmod +x /cygdrive/C/Users/hero/ci/frontman_ci/build_msi/${CIRCLE_BUILD_NUM}/build-win.bat
	scp -r -P 24481 -oStrictHostKeyChecking=no ${PROJECT_DIR}/pkg-scripts/  hero@144.76.9.139:/cygdrive/C/Users/hero/ci/frontman_ci/build_msi/${CIRCLE_BUILD_NUM}
	scp -r -P 24481 -oStrictHostKeyChecking=no ${PROJECT_DIR}/resources/  hero@144.76.9.139:/cygdrive/C/Users/hero/ci/frontman_ci/build_msi/${CIRCLE_BUILD_NUM}
	scp -P 24481 -oStrictHostKeyChecking=no ${PROJECT_DIR}/example.config.toml hero@144.76.9.139:/cygdrive/C/Users/hero/ci/frontman_ci/build_msi/${CIRCLE_BUILD_NUM}/example.config.toml
	scp -P 24481 -oStrictHostKeyChecking=no ${PROJECT_DIR}/example.json hero@144.76.9.139:/cygdrive/C/Users/hero/ci/frontman_ci/build_msi/${CIRCLE_BUILD_NUM}/example.json
	scp -P 24481 -oStrictHostKeyChecking=no ${PROJECT_DIR}/LICENSE hero@144.76.9.139:/cygdrive/C/Users/hero/ci/frontman_ci/build_msi/${CIRCLE_BUILD_NUM}/LICENSE
	scp -P 24481 -oStrictHostKeyChecking=no ${PROJECT_DIR}/wix.json hero@144.76.9.139:/cygdrive/C/Users/hero/ci/frontman_ci/build_msi/${CIRCLE_BUILD_NUM}/wix.json
	# Trigger msi creating
	ssh -p 24481 -oStrictHostKeyChecking=no hero@144.76.9.139 /cygdrive/C/Users/hero/ci/frontman_ci/build_msi/${CIRCLE_BUILD_NUM}/build-win.bat ${CIRCLE_BUILD_NUM} ${CIRCLE_TAG}
	# Trigger signing 
	ssh -p 24481 -oStrictHostKeyChecking=no hero@144.76.9.139 curl -s -S -f http://localhost:8080/?file=frontman_32.msi
	ssh -p 24481 -oStrictHostKeyChecking=no hero@144.76.9.139 curl -s -S -f http://localhost:8080/?file=frontman_64.msi
	# Copy msi files back to build machine
	scp -P 24481 -oStrictHostKeyChecking=no hero@144.76.9.139:/cygdrive/C/Users/hero/ci/frontman_32.msi ${PROJECT_DIR}/dist/frontman_386.msi
	scp -P 24481 -oStrictHostKeyChecking=no hero@144.76.9.139:/cygdrive/C/Users/hero/ci/frontman_64.msi ${PROJECT_DIR}/dist/frontman_64.msi
	# Add files to Github release
	github-release upload --user cloudradar-monitoring --repo frontman --tag ${CIRCLE_TAG} --name "frontman_${CIRCLE_TAG}_Windows_386.msi" --file "${PROJECT_DIR}/dist/frontman_386.msi"
	github-release upload --user cloudradar-monitoring --repo frontman --tag ${CIRCLE_TAG} --name "frontman_${CIRCLE_TAG}_Windows_x86_64.msi" --file "${PROJECT_DIR}/dist/frontman_64.msi"

synology-spk:
	cd synology-spk && ./create_spk.sh ${CIRCLE_TAG}
	# Add files to Github release
	github-release upload --user cloudradar-monitoring --repo frontman --tag ${CIRCLE_TAG} --name "frontman_${CIRCLE_TAG}_synology_amd64.spk" --file "${PROJECT_DIR}/synology-spk/frontman-amd64.spk"
	github-release upload --user cloudradar-monitoring --repo frontman --tag ${CIRCLE_TAG} --name "frontman_${CIRCLE_TAG}_synology_armv7.spk" --file "${PROJECT_DIR}/synology-spk/frontman-armv7.spk"
	github-release upload --user cloudradar-monitoring --repo frontman --tag ${CIRCLE_TAG} --name "frontman_${CIRCLE_TAG}_synology_armv8.spk" --file "${PROJECT_DIR}/synology-spk/frontman-armv8.spk"
