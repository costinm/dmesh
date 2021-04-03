module github.com/costinm/dmesh/android/wpgate

go 1.16

replace github.com/costinm/ugate => ../../../ugate

replace github.com/costinm/tungate/lwip => ../../../tungate/lwip

replace github.com/eycorsican/go-tun2socks => github.com/costinm/go-tun2socks v1.16.12-0.20210328172757-88f6d54235cb

require (
	github.com/costinm/tungate/lwip v0.0.0-20210328181250-b832f0735d5b
	github.com/costinm/ugate v0.0.0-20210328173325-afc113d007e8
	github.com/costinm/ugate/dns v0.0.0-20210329161419-fd5474ea74fe
	github.com/costinm/ugate/webpush v0.0.0-20210329161419-fd5474ea74fe
	golang.org/x/mobile v0.0.0-20210220033013-bdb1ca9a1e08 // indirect
	golang.org/x/sys v0.0.0-20201201145000-ef89a241ccb3 // indirect
)
