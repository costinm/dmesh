module github.com/costinm/dmesh

go 1.14

replace github.com/google/netstack => github.com/costinm/netstack v0.0.0-20190601172006-f6e50d4d2856

replace github.com/costinm/wpgate => ../wpgate
replace github.com/costinm/dmesh-l2 => ../dmesh-l2

require (
	github.com/costinm/dmesh-l2 v0.0.0-20201213175916-1b0cef9a6d59
	github.com/costinm/wpgate v0.0.0-20201213175739-35923cdd56a3
)
