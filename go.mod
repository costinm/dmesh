module github.com/costinm/dmesh

go 1.22.0

//replace github.com/costinm/ugate => ../../../ugate
//replace github.com/costinm/ugate/auth => ../../../ugate/auth
//replace github.com/costinm/ugate/dns => ../../../ugate/dns

//replace github.com/costinm/tungate/lwip => ../../../tungate/lwip

//replace github.com/eycorsican/go-tun2socks => github.com/costinm/go-tun2socks v1.16.12-0.20210328172757-88f6d54235cb

require (
	github.com/costinm/go-tun2socks v1.17.0
	github.com/songgao/water v0.0.0-20200317203138-2b4b6d7c09d8
	gvisor.dev/gvisor v0.0.0-20240916094835-a174eb65023f
)

require (
	github.com/bazelbuild/rules_go v0.44.2 // indirect
	github.com/google/btree v1.1.2 // indirect
	golang.org/x/sys v0.17.0 // indirect
	golang.org/x/time v0.5.0 // indirect
	google.golang.org/protobuf v1.32.0 // indirect
)
