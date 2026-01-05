
fix net.Interface() and net.InterfaceAddrs() in Android 11+

``` route ip+net: netlinkrib: permission denied ```


How to use :

``` go get github.com/hossinasaadi/anet@main ```

```go
import "github.com/hossinasaadi/anet"

anet.Interfaces() // work for android and other platforms
```

check:

https://github.com/golang/go/pull/61089

https://github.com/golang/go/issues/40569

https://github.com/holochain/tx5/issues/87

https://github.com/hsjoberg/blixt-wallet/issues/192

...
