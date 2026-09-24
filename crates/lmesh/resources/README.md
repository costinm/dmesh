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

The [root API](../../../API.md) specifies the Linux radio and shared portable
handlers. `tools.json` is the one installed catalog used by `lmesh`,
`mesh`, and `dmesh-cli`; device method tags and legacy diagnostic labels are
kept in it so a second firmware schema is unnecessary.

Run `scripts/generate-lmesh-tools.py` after changing the Linux handler API.
