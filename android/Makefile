
# - Single device or ANDROID_SERIAL set.

DEVICES := $(wildcard ${HOME}/.dmesh/devices/*)
-include ${HOME}/.dmesh/env.mk

CTL_PORT ?= 7227
ANDROID_SERIAL ?= 99LAY1ANQ3
export ANDROID_SERIAL
GO=go build
ADB ?= adb

ports:
	adb forward tcp:${CTL_PORT} tcp:5227

bt_disc:
	curl localhost:${CTL_PORT}/dmesh/uds/?q=/bt/disc

bt_scan:
	curl localhost:${CTL_PORT}/dmesh/uds/?q=/bt/scan

bt_sync:
	curl localhost:${CTL_PORT}/dmesh/uds/?q=/bt/sync

cmd:
	curl localhost:${CTL_PORT}/dmesh/uds/?q=${DCMD}

android:
	GOARCH=arm64 GOOS=linux GOARM=7 ${GO} -o libdmesh/src/main/jniLibs/arm64-v8a/libDM.so ../cmd/libDM

libDM:
	GOARCH=arm GOOS=linux GOARM=7 ${GO}  -o ${OUT}/bin/arm/libDM.so ./cmd/libDM
	GOARCH=arm64 GOOS=linux GOARM=7 ${GO} -o ${OUT}/bin/arm64/libDM.so ./cmd/libDM
	GOARCH=mips GOOS=linux GOMIPS=softfloat ${GO}  -o ${OUT}/bin/mips/libDM.so ./cmd/libDM
	${GO} -o ${OUT}/bin/libDM.so ./cmd/libDM

connect:
	${ADB} connect "10.1.10.238:39950" # P2XL
	${ADB} connect "10.1.10.222:42337" # P3XL
	${ADB} connect "10.1.10.208:38409" # P3A1
	${ADB} connect 10.1.10.219 # N7
	${ADB} connect 10.1.10.240 # N9
	${ADB} connect 10.1.10.239 # N5
	${ADB} connect 10.1.10.221 # NexusS - dmeshlite

define TXT_template =

$(1)/run:
	$(2) $(MAKE) device_run

.PHONY: run/$(1)

ALL += $(2).txt

endef

#$(info $(DEVICES))

$(foreach src,$(DEVICES),$(eval $(call TXT_template, $(notdir $(src)), $(shell cat $(src)) ) ))

#.SECONDARY_EXPANSION:
#all_s: $(ALL)

# Test devices
prepare:
	ANDROID_SERIAL=99LAY1ANQ3 $(MAKE) ports
	ANDROID_SERIAL=711KPKN0649013 CTL_PORT=7228 $(MAKE) ports

# BT manual tests
# First - requires UI, 5 min window
p2x/bt_disc:
	ANDROID_SERIAL=711KPKN0649013 CTL_PORT=7228 $(MAKE) bt_disc

# App in foreground OR 'location when not running' perm
p3a/bt_scan:
	ANDROID_SERIAL=99LAY1ANQ3 $(MAKE) bt_scan

p3a/bt_sync:
	ANDROID_SERIAL=99LAY1ANQ3 $(MAKE) bt_sync

docker/apk:
	docker run --it --rm -v $(shell pwd):/src costinm/android:latest gradlew assembleDebug

apk:
	./gradlew assembleDebug
