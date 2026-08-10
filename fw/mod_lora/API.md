# LoRa module API

`mod_lora` owns the module-local radio ABI. Main owns loading, placement,
power, GPIO/SPI host primitives, and forwarding; this document owns radio
configuration, packet semantics, and module event tuples.

The module event tuple is `[event_id, value_type, flags, value]`. Current IDs
are `1=rx_started`, `2=rx_stopped`, `3=tx_done`, `4=reconfigured`,
`5=stats`, and `6=tx_error`. RX/TX operations are asynchronous; completion and
errors are events, not blocking command responses.

LoRa and FSK wire payloads are opaque to Main. Chip-specific IRQ, FIFO, BUSY,
reset, and continuous-RX behavior remain module-owned.

