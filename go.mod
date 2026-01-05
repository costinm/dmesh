module github.com/costinm/dmesh

go 1.25

replace github.com/costinm/ssh-mesh => ../ssh-mesh

//replace github.com/costinm/ugate/auth => ../../../ugate/auth
//replace github.com/costinm/ugate/dns => ../../../ugate/dns

//replace github.com/costinm/tungate/lwip => ../../../tungate/lwip

//replace github.com/eycorsican/go-tun2socks => github.com/costinm/go-tun2socks v1.16.12-0.20210328172757-88f6d54235cb

require (
	github.com/costinm/go-tun2socks v1.17.0
	github.com/costinm/ssh-mesh v0.0.0-00010101000000-000000000000
	github.com/songgao/water v0.0.0-20200317203138-2b4b6d7c09d8
)

require (
	github.com/creack/pty v1.1.24 // indirect
	github.com/kr/pty v1.1.8 // indirect
	golang.org/x/crypto v0.43.0 // indirect
	golang.org/x/net v0.46.0 // indirect
	golang.org/x/sys v0.37.0 // indirect
)
