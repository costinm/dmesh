
# - Single device or ANDROID_SERIAL set.

CTL_PORT ?= 7227
ANDROID_SERIAL ?= 99LAY1ANQ3
export ANDROID_SERIAL
GO=go build

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

native:
	GOARCH=arm64 GOOS=linux GOARM=7 ${GO} -o libdmesh/src/main/jniLibs/arm64-v8a/libDM.so ../cmd/libDM

libDM:
	GOARCH=arm GOOS=linux GOARM=7 ${GO}  -o ${OUT}/bin/arm/libDM.so ./cmd/libDM
	GOARCH=arm64 GOOS=linux GOARM=7 ${GO} -o ${OUT}/bin/arm64/libDM.so ./cmd/libDM
	GOARCH=mips GOOS=linux GOMIPS=softfloat ${GO}  -o ${OUT}/bin/mips/libDM.so ./cmd/libDM
	${GO} -o ${OUT}/bin/libDM.so ./cmd/libDM


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
