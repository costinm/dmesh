package main

import (
	"context"
	"encoding/base64"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/costinm/dmesh-l2/pkg/lmnet"
	"github.com/costinm/dmesh-l2/pkg/netstacktun"
	"github.com/costinm/wpgate/pkg/auth"
	"github.com/costinm/wpgate/pkg/conf"
	"github.com/costinm/wpgate/pkg/dns"
	"github.com/costinm/wpgate/pkg/h2"
	"github.com/costinm/wpgate/pkg/mesh"
	"github.com/costinm/wpgate/pkg/msgs"
	"github.com/costinm/wpgate/pkg/transport/httpproxy"
	"github.com/costinm/wpgate/pkg/transport/local"
	sshgate "github.com/costinm/wpgate/pkg/transport/ssh"
	"github.com/costinm/wpgate/pkg/transport/udp"
	uds2 "github.com/costinm/wpgate/pkg/transport/uds"
	"github.com/costinm/wpgate/pkg/ui"
)

// Android and device version of DMesh.
func main() {
	log.Print("Starting native process pwd=", os.Getenv("PWD"), os.Environ())

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

	cfgf := os.Getenv("BASE")
	if cfgf == "" {
		cfgf = os.Getenv("HOME")
		if cfgf == "" {
			cfgf = os.Getenv("TEMPDIR")
		}
		if cfgf == "" {
			cfgf = os.Getenv("TMP")
		}
		if cfgf == "" {
			cfgf = "/tmp"
		}
	}

	cfgf += "/"

	// File-based config
	config := conf.NewConf(cfgf)

	meshH := auth.Conf(config, "MESH", "v.webinf.info:5222")

	// Init or load certificates/keys
	authz := auth.NewAuth(config, os.Getenv("HOSTNAME"), "v.webinf.info")
	msgs.DefaultMux.Auth = authz

	// HTTPGate - common structures
	GW := mesh.New(authz, nil)

	// SSH transport + reverse streams.
	sshg := sshgate.NewSSHGate(GW, authz)
	GW.SSHGate = sshg
	sshg.InitServer()
	sshg.ListenSSH(":5222")

	// Connect to a mesh node
	if meshH != "" {
		GW.Vpn = meshH
		go sshgate.MaintainVPNConnection(GW)
	}

	// Local discovery interface - multicast, local network IPs
	ld := local.NewLocal(GW, authz)
	go ld.PeriodicThread()

	h2s, err := h2.NewTransport(authz)
	if err != nil {
		log.Fatal(err)
	}

	dnss, err := dns.NewDmDns(5223)
	GW.DNS = dnss
	net.DefaultResolver.PreferGo = true
	net.DefaultResolver.Dial = dns.DNSDialer(5223)

	udpNat  := udp.NewUDPGate(GW)
	udpNat.DNS = dnss
	go initUDSConnection(GW, ld, config, udpNat)

	hgw := httpproxy.NewHTTPGate(GW, h2s)
	hgw.HttpProxyCapture("localhost:5204")

	// Start a basic UI on the debug port
	u, _ := ui.NewUI(GW, h2s, hgw, ld)

	udpNat.InitMux(h2s.LocalMux)

	//// Periodic registrations.
	//m.Registry.RefreshNetworksPeriodic()

	log.Printf("Loading with VIP6: %v ID64: %s\n",
		authz.VIP6,
		base64.RawURLEncoding.EncodeToString(authz.VIP6[8:]))

	go dnss.Serve()
	err = http.ListenAndServe("localhost:5227", u)
	if err != nil {
		log.Println(err)
	}
}

func initUDSConnection(gw *mesh.Gateway, ld *local.LLDiscovery, cfg *conf.Conf, udpNat *udp.UDPGate) {

	var vpn *os.File
	// Attempt to connect to local UDS socket, to communicate with android app.
	for i := 0; i < 5; i++ {
		ucon, err := uds2.Dial("dmesh", msgs.DefaultMux, map[string]string{})
		if err != nil {
			log.Println("Failed to initialize UDS ", err)
			time.Sleep(1 * time.Second)
		} else {
			lmnet.NewWifi(ld, &ucon.MsgConnection, ld)

			// Special messages:
			// - close - terminate program, java side dead
			// - KILL - explicit request to stop
			ucon.Handler = msgs.HandlerCallbackFunc(func(ctx context.Context, cmdS string, meta map[string]string, data []byte) {
				args := strings.Split(cmdS, "/")

				switch args[1] {

				case "KILL":
					log.Printf("Kill command received, exit")
					os.Exit(1)

					// Handshake's first message - metadata for the other side.
				case "P": // properties - on settings change. Properties will be stored in H2.Conf
					log.Println("Received settings: ", meta)
					for k, v := range meta {
						cfg.Conf[k] = v
						if k == "ua" {
							//dm.Registry.UserAgent = v
							gw.UA = v
						}
					}
					ld.RefreshNetworks()

				case "r": // refresh networks
					log.Println("UDS: refresh network (r)")
					go func() {
						time.Sleep(2 * time.Second)
						ld.RefreshNetworks()
					}()

				case "k": // VPN kill
					if vpn != nil {
						vpn.Close()
						vpn = nil
						log.Println("Closing VPN")
					}
				case "v": // VPN client for android
					fa := ucon.File()
					vpn = fa
					if fa != nil {
						log.Println("Received VPN UDS client (v), starting TUN", fa, ucon.Files)
						// The dmtun will be passed as a reader when connecting to the VPN.
						//mesh.Tun = NewTun(fa, fa)
						link := netstacktun.NewReaderWriterLink(fa, fa, &netstacktun.Options{MTU: 1600})
						netstack := netstacktun.NewTunCapture(&link, gw, udpNat, false)
						udpNat.UDPWriter = netstack
					} else {
						log.Println("ERR: UDS: VPN TUN: invalid VPN file descriptor (v)")
					}

				case "V": // VPN master
					fa := ucon.File()
					vpn = fa
					if fa != nil {
						log.Println("Received VPN UDS master (V), starting VPN DmDns", fa, ucon.Files)
						link := netstacktun.NewReaderWriterLink(fa, fa, &netstacktun.Options{MTU: 1600})
						netstack := netstacktun.NewTunCapture(&link, gw, udpNat, false)
						udpNat.UDPWriter = netstack
					} else {
						log.Println("ERR: UDS: invalid VPN file descriptor (V)")
					}

				case "CON":
					switch args[2] {
					case "STOP":
						ld.RefreshNetworks()
						ld.WifiInfo.Net = ""
					case "START":
						ld.RefreshNetworks()
						ld.WifiInfo.Net = meta["ssid"]
					}
				}
			})
			go func() {
				for {
					ucon.HandleStream()
					// Connection closes if the android side is dead.
					// TODO: this is only for the UDS connection !!!
					log.Printf("UDS: parent closed, exiting ")
					os.Exit(4)
				}
			}()

			break
		}
	}
}
