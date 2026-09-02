# lmesh resources

`tools.json` is the generated public command catalog for `lmesh` and radio-adapter
control surfaces exposed through `tools/list`, `tools/call`, the ssh-mesh admin
web UI, and the `mesh lmesh tools` CLI command.

The generic ssh-mesh explorer requests `?view=default` and shows only tools
marked `"x-ui-visibility": "default"`. Its **Show all methods** control
requests `?view=all`, which returns every catalog entry, including legacy and
radio-laboratory methods. This is presentation metadata only: catalog methods
remain callable through normal policy-controlled record and named-call
endpoints. Omitted visibility is intentionally not default-visible; new tools
must explicitly choose `default` or remain masked until documented, tested, and
classified.

`firmware-tools.json` is the client-local catalog for direct ESP modem
services such as `lora1.lmesh`. `mesh FQDN help` reads it locally; firmware
does not carry or serve command help, so help remains available while a device
is sleeping or unreachable.

`../API.md` is the canonical specification for the managed host services.
Firmware operations are now dmesh-server stream handlers, not a generated
direct-command catalog. Do not add retired firmware command methods here.
