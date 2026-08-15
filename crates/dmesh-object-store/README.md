# dmesh-object-store

This crate is a transport-neutral object store. A client sends a compact CBOR
`GET` map containing binary parameters such as object name, CPU, and target.
The server returns a manifest record, blob records, and a completion
record on the stream supplied by the caller.

The crate has no UDP or socket implementation and does not parse QUIC packets.
TCP/SSH/QUIC/radio adapters own their bearer and flow-control integration; the
object store only resolves the request and produces or consumes stream records.
