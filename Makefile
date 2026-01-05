
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

all: native


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
ANDROID_HOME?=${HOME}/Android/Sdk
# Should be a symlink to the actual SDK
ANDROID_NDK_HOME?= ${ANDROID_HOME}/ndk
NDK_HOME?= ${ANDROID_NDK_HOME}

GOROOT?=/a/opt/go
JAVA_HOME=/x/opt/android-studio/jbr
PATH:=/ws/go/bin:${GOROOT}/bin:${JAVA_HOME}/bin:/a/opt/android-studio/jre/bin:${PATH}
export ANDROID_NDK_HOME
export ANDROID_HOME
export PATH

init:
	go install golang.org/x/mobile/cmd/gomobile

rustinit:
	rustup target add  aarch64-linux-android 
	rustup target add  x86_64-linux-android
	rustup target add  armv7-linux-androideabi

rust:
	cargo ndk build -t x86_64-linux-android -o android/app-dmesh/src/main/jniLibs/
	cargo ndk build -t aarch64-linux-android -o android/app-dmesh/src/main/jniLibs/

native:
	cd pkg/dmjni && \
	  gomobile bind \
	     -o ../../android/wpgate-aar/wpgate.aar \
	     -androidapi 25 \
		 -a -ldflags '-s -w' \
		 -target android -tags android

NDK_GO_ARCH_x86 := 386
NDK_GO_ARCH_x86_64 := amd64
NDK_GO_ARCH_arm := arm
NDK_GO_ARCH_arm64 := arm64
NDK_GO_ARCH_mips := mipsx
NDK_GO_ARCH_mips64 := mips64x

ANDROID_NDK_ROOT=${HOME}/Android/Sdk/ndk/29.0.14206865
SYSROOT=${ANDROID_NDK_ROOT}/toolchains/llvm/prebuilt/linux-x86_64/sysroot
export NDK_LOG=1

JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
# CLANG_FLAGS := --target=$(ANDROID_LLVM_TRIPLE) --gcc-toolchain=$(ANDROID_TOOLCHAIN_ROOT) --sysroot=$(ANDROID_SYSROOT)
CGO_CFLAGS:="${CLANG_FLAGS} ${CFLAGS} -I${JAVA_HOME}/include/linux -I${JAVA_HOME}/include"
# export CGO_LDFLAGS := $(CLANG_FLAGS) $(LDFLAGS) -Wl,-soname=${SONAME}
# export CC := $(ANDROID_C_COMPILER)
# export GOARCH := $(NDK_GO_ARCH_$(ANDROID_ARCH_NAME))
# export GOOS := android

jni:
	mkdir -p android/app-dmesh/src/test/jniLibs
	# CGO appears to be required
	CGO_CFLAGS=${CGO_CFLAGS} CGO_ENABLED=1 GOARCH=amd64 \
	go build -o android/app-dmesh/src/test/jniLibs/libdmjni.so -buildmode c-shared ./pkg/dmeshd

ajni:
	CC=${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android35-clang GOOS=android CGO_CFLAGS=${CGO_CFLAGS} CGO_ENABLED=1 GOARCH=amd64 \
	 go build \
	   -o android/app-dmesh/src/main/jniLibs/x86_64/libdmjni.so -buildmode c-shared ./pkg/dmeshd



connect:
	# IP and port from the wireless adb
	# adb connect 127.0.0.1:6018
	adb connect $IP

#build/arm:
#	#mkdir -p $(BUILDDIR)
#	#eval $(BUILD_ANDROID)
#	# -v -x
#	#
#	# mips, mipsle, arm64
#	xgo   --targets=linux/arm64  --pkg cmd/libDM   ./

clean:
	rm -rf $(BUILDDIR)
