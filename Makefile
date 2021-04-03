
#GOMOBILE=gomobile
#GOBIND=$(GOMOBILE) bind
#BUILDDIR=$(shell pwd)/build
#ANDROID_ARTIFACT=$(BUILDDIR)/dmesh.aar
#ANDROID_TARGET=android
#LDFLAGS='-s -w'
#
#IMPORT_PATH=github.com/costinm/dmesh/pkg/libDM
#
#BUILD_ANDROID="cd $(BUILDDIR) && $(GOBIND) -a -ldflags $(LDFLAGS) -target=$(ANDROID_TARGET) -o $(ANDROID_ARTIFACT) $(IMPORT_PATH)"

all: build/android

#init:
#	#	go get golang.org/x/mobile/cmd/gomobile
#	#	go install golang.org/x/mobile/cmd/gomobile
#	#	gomobile init
#	# >5G
#	#docker pull karalabe/xgo-latest
#	# Last v: 1.13
#	#go get github.com/karalabe/xgo
#
#	go get src.techknowlogick.com/xgo

# Based on the docker image
ANDROID_NDK_HOME?=/opt/android/android-ndk-r22b
#/a/opt/Android/Sdk/ndk/23.0.7196353
ANDROID_HOME?=/opt/android/sdk
# /a/opt/Android/Sdk
GOROOT?=/a/opt/go
PATH:=/ws/go/bin:${GOROOT}/bin:/a/opt/android-studio/jre/bin:${PATH}
export ANDROID_NDK_HOME
export ANDROID_HOME
export PATH

init:
	go get golang.org/x/mobile/cmd/gomobile

build/android:
	cd android/wpgate-aar && gomobile bind -a -ldflags '-s -w' -target android

#build/arm:
#	#mkdir -p $(BUILDDIR)
#	#eval $(BUILD_ANDROID)
#	# -v -x
#	#
#	# mips, mipsle, arm64
#	xgo   --targets=linux/arm64  --pkg cmd/libDM   ./

clean:
	rm -rf $(BUILDDIR)
