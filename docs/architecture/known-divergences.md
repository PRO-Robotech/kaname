# Known divergences — kacho-iam

Deliberate, reviewed deviations from a project-wide convention that are **not**
defects. Each entry states the convention, why kacho-iam diverges, why it is
safe, and what would be required to converge.

---

## 1. mTLS config loaded via `envconfig` struct-tags, not the viper/YAML path

**Convention** (evgeniy regime): service configuration is loaded via
`viper` + `mapstructure` from YAML — no `envconfig` struct-tags.
`internal/apps/kacho/config/load.go` follows this for the bulk of the config.

**Divergence**: `MTLSConfig` (`internal/apps/kacho/config/mtls.go`) is loaded by a
**separate** `envconfig`-based path (`LoadMTLS`), using `envconfig:"…"` struct
tags, so two config-parsing mechanisms coexist in the same package.

**Why (by design, not a defect)**: the per-edge mTLS server credentials are
carried by `grpcsrv.TLSServer`, a **horizontal value-struct owned by
`kacho-corelib`**. That corelib type intentionally exposes no `mapstructure`
tags (it is a plain cross-service value type), so it cannot be populated through
the viper/`mapstructure` decoder without either (a) adding `mapstructure` tags to
a corelib type — a workspace-wide change to a shared horizontal package, owned by
corelib's release cadence, out of scope for a single service — or (b) hand-writing
a parallel tagged mirror struct in kacho-iam and copying field-by-field (its own
drift risk). `envconfig` reads the corelib fields directly from the environment
with zero corelib change, and each mTLS edge is **default-off** (`Enable=false`
→ plaintext, byte-identical to prior behaviour), so the second mechanism governs
only an opt-in security hardening surface, isolated to this one struct.

**Safety**: the two mechanisms do not overlap — viper/YAML owns all functional
config; `envconfig` owns *only* the four opt-in mTLS server edges
(`KACHO_IAM_{PUBLIC,INTERNAL,HOOKS,METRICS}_SERVER_MTLS_*`). There is no field
whose value could be silently shadowed between the two. An operator setting an
mTLS parameter uses the documented `KACHO_IAM_*_MTLS_*` env vars; these are not
expressible under a YAML `config:` section by design.

**Convergence path (deferred)**: give `grpcsrv.TLSServer` `mapstructure` tags
upstream in `kacho-corelib` and load mTLS through the same viper path. This is a
corelib-wide migration (touches every service embedding `grpcsrv.TLSServer`) and
is intentionally **not** done as part of a single-service change. Tracked as a
convergence item for the next corelib config pass; no runtime impact until then.

_Reviewed 2026-07-05 (security-hardening audit)._
