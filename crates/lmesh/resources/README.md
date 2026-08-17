# lmesh resources

`tools.json` is the generated public command catalog for `lmesh` and radio-adapter
control surfaces exposed through `tools/list`, `tools/call`, the ssh-mesh admin
web UI, and the `mesh lmesh tools` CLI command.

`firmware-tools.json` is the client-local catalog for direct ESP modem
services such as `lora1.lmesh`. `mesh FQDN help` reads it locally; firmware
does not carry or serve command help, so help remains available while a device
is sleeping or unreachable.

`../API.md` is the canonical specification for the managed host services.
Firmware operations are now dmesh-server stream handlers, not a generated
direct-command catalog. Do not add retired firmware command methods here.
