package wpgate

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"syscall"
	"time"

	// Use LWIP for VPN
	"github.com/costinm/tungate/lwip/pkg/lwip"
	"github.com/costinm/ugate"
	"github.com/costinm/ugate/dns"

	// Local discovery
	"github.com/costinm/ugate/pkg/local"

	// Control
	msgs "github.com/costinm/ugate/webpush"

	"github.com/costinm/ugate/pkg/http_proxy"
	// UDP and TCP proxy
	"github.com/costinm/ugate/pkg/udp"
	"github.com/costinm/ugate/pkg/ugatesvc"
)
/*
	gomobile bindings

- called 2x, once with lang=java and once with lang=go

- Signed integer and floating point types.

- String and boolean types.

- Byte slice types. Note that byte slices are passed by reference,
  and support mutation.

- Any function type all of whose parameters and results have
  supported types. Functions must return either no results,
  one result, or two results where the type of the second is
  the built-in 'error' type.

- Any interface type, all of whose exported methods have
  supported function types.

- Any struct type, all of whose exported methods have
  supported function types and all of whose exported fields
  have supported types.

 */


// Adapter from func to interface
type MessageHandler interface {
	Handle(topic string, meta []byte, data []byte)
}

var (
	ld *local.LLDiscovery
	gw *ugatesvc.UGate
	udpGate *udp.UDPGate
	vpnFile *os.File
)

// Update is called in a Job, with wake locks.
func Update() {
	if ld != nil {
		ld.RefreshNetworks()
	}
}

// Called to inject a message into Go impl
func Send(cmdS string, meta []byte, data []byte) {
	switch cmdS {
	case "r":
		// refresh networks
		log.Println("UDS: refresh network (r)")
		go func() {
			time.Sleep(2 * time.Second)
			ld.RefreshNetworks()
		}()
		return
		// TODO: P - properties, json
		// CON - STOP/START - set connected WIFI
		// Stop VPN - message
	}
	metao := map[string]string{}
	if meta != nil {
		json.Unmarshal(meta, &metao)
		log.Println("Decoded meta: ", metao)
	}
	log.Println("Java2Native", cmdS)
	msgs.DefaultMux.SendMeta(cmdS, metao, data)
}

func StopVPN() {
	if vpnFile != nil {
		vpnFile.Close()
		vpnFile = nil
	}
}
// Directly pass the VPN, start processing it in go.
func StartVPN(fd int) {
	syscall.SetNonblock(fd, false)
	vpnFile = os.NewFile(uintptr(fd), "dmesh-socket-"+strconv.Itoa(fd))
	log.Println("Received VPN UDS client (v), starting TUN", fd)
	tun := lwip.NewTUNFD(vpnFile,gw, udpGate)
	//tun := netstack.NewTUNFD(fa, gw, udpNat)
	udpGate.TransparentUDPWriter = tun
}

// Android and device version of DMesh.
func InitDmesh(baseDir string, callbackFunc MessageHandler) []byte {

	// SYSTEMSERVERCLASSPATH=/system/framework/services.jar:/system/framework/ethernet-service.jar:/system/framework/wifi-service.jar:/system/framework/com.android.location.provider.jar
	// PATH=/sbin:/system/sbin:/system/bin:/system/xbin:/odm/bin:/vendor/bin:/vendor/xbin
	// STORAGE=/storage/emulated/0/Android/data/com.github.costinm.dmwifi/files
	// ANDROID_DATA=/data
	// ANDROID_SOCKET_zygote_secondary=12
	// ASEC_MOUNTPOINT=/mnt/asec
	// EXTERNAL_STORAGE=/sdcard
	// ANDROID_BOOTLOGO=1
	// ANDROID_ASSETS=/system/app
	// BASE=/data/user/0/com.github.costinm.dmwifi/files
	// ANDROID_STORAGE=/storage
	// ANDROID_ROOT=/system
	// DOWNLOAD_CACHE=/data/cache
	// BOOTCLASSPATH=/system/framework/core-oj.jar:/system/framework/core-libart.jar:/system/framework/conscrypt.jar:/system/framework/okhttp.jar:/system/framework/bouncycastle.jar:/system/framework/apache-xml.jar:/system/framework/ext.jar:/system/framework/framework.jar:/system/framework/telephony-common.jar:/system/framework/voip-common.jar:/system/framework/ims-common.jar:/system/framework/android.hidl.base-V1.0-java.jar:/system/framework/android.hidl.manager-V1.0-java.jar:/system/framework/framework-oahl-backward-compatibility.jar:/system/framework/android.test.base.jar:/system/framework/com.google.vr.platform.jar]

	// File-based config
	config := ugatesvc.NewConf(baseDir)
	log.Println("Starting native on ", baseDir)
	// Init or load certificates/keys

	gcfg := &ugate.GateCfg{
		BasePort: 15000,
		Name: os.Getenv("HOSTNAME"),
		Domain: "v.webinf.info",
	}

	gw = ugatesvc.NewGate(nil, nil, gcfg, config)

	msgs.DefaultMux.Auth = gw.Auth

	msgs.DefaultMux.AddHandler("*", msgs.HandlerCallbackFunc(func(ctx context.Context, cmdS string, meta map[string]string, data []byte) {
		var metaB []byte
		metaB, _ = json.Marshal(meta)
		log.Println("XXX Go2java ", cmdS)
		callbackFunc.Handle(cmdS, metaB, data)
	}))

	msgs.DefaultMux.Send("./test/local", nil)

	hproxy := http_proxy.NewHTTPProxy(gw)
	hproxy.HttpProxyCapture(fmt.Sprintf("127.0.0.1:%d", gcfg.BasePort+ugate.PORT_HTTP_PROXY))

	// ugatesvc.Conf(config, "MESH", "v.webinf.info:5222")

	// If key=="" - uses port 443
	// Else - default is 15007
	// Set host config for other settings
	//gw.Config.H2R["h.webinf.info"] = "B5B6KYYUBVKCX4PWPWSWAIHW2X2D3Q4HZPJYWZ6UECL2PAODHTFA"
	gcfg.H2R["c1.webinf.info"] = ""

	gw.H2Handler.UpdateReverseAccept()

	//// Connect to a mesh node
	//if meshH != "" {
	//	GW.Vpn = meshH
	//	go sshgate.MaintainVPNConnection(GW)
	//}

	// Local discovery interface - multicast, local network IPs
	ld = local.NewLocal(gw, gw.Auth)
	// go ld.PeriodicThread() - not using the thread, use the Android call
	go ld.RefreshNetworks()
	local.ListenUDP(ld)

	gw.Mux.HandleFunc("/dmesh/ll/if", ld.HttpGetLLIf)


	//h2s, err := h2.NewTransport(authz)
	//if err != nil {
	//	log.Fatal(err)
	//}

	// DNS capture, interpret the names, etc
	// Off until DNS moved to smaller package.
	dnss, _ := dns.NewDmDns(5223)
	//gw.DNS = dnss
	net.DefaultResolver.PreferGo = true
	net.DefaultResolver.Dial = dns.DNSDialer(5223)

	udpGate = udp.New(gw)

	//hgw := httpproxy.NewHTTPGate(GW, h2s)
	//hgw.HttpProxyCapture("localhost:5204")

	go dnss.Serve()

	log.Printf("Loading with VIP6: %v ID64: %s\n",
		gw.Auth.VIP6,
		base64.RawURLEncoding.EncodeToString(gw.Auth.VIP6[8:]))

	callbackFunc.Handle("/STARTED", nil, nil)
	msgs.DefaultMux.Send("/START1", nil)
	return gw.Auth.VIP6
}

