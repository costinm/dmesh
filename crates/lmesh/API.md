# lmesh API pointers

`lmesh` is the experimental superset and launcher. Shared Wi-Fi ownership,
AP/STA/raw-NAN operations, object-store flashing, benchmark requests, and
their JSONL contract are defined by [`lmesh-wifi/API.md`](../lmesh-wifi/API.md).

Other component contracts remain authoritative in:

- [`lmesh-uart/API.md`](../lmesh-uart/API.md)
- [`uart-codec/API.md`](../uart-codec/API.md)
- [`rawnan/API.md`](../rawnan/API.md)
- [`dmesh-transport`](../dmesh-transport/)

BLE HCI is experimental and is implemented only by `lmesh`; it is not part of
the stable `lmesh-wifi` API. This file intentionally contains pointers only;
update the owning component API instead of duplicating method documentation.
