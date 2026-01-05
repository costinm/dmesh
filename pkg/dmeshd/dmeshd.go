package main

/*
#include "jni.h"
#include <stdlib.h>
*/
import "C"


// https://github.com/timob/jnigi - wrappers
// Recommends: export CGO_CFLAGS="-I/usr/lib/jvm/default-java/include -I/usr/lib/jvm/default-java/include/linux"



// dmeshd can run on Linux or Android.
// If UID is root, it can use LWIP and TAP. For android the
// JNI library gets the VPN socket, no root needed.
//
// This is part of a device mesh, will attempt to discover
// local devices and register for discovery.
// Security is based on workload identity - using android
// certificates as equivalent.
func main() {

}

//export Java_dmjni_Go_setup
func Java_dmjni_Go_setup(env uintptr, clazz uintptr) int {
	return 100
}
