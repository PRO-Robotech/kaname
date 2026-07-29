# Captured provider hook bodies

These three files are **verbatim captures**, not reconstructions. They were taken
by running the identity provider at the exact version this stand runs
(`oryd/hydra:v26.2.0`) with its token and refresh hooks pointed at a recording
endpoint, and driving three real exchanges through it:

| file | exchange driven |
|---|---|
| `provider-token-hook-client-credentials.json` | `grant_type=client_credentials` |
| `provider-token-hook-authorization-code.json` | interactive login (login+consent accepted, `acr=2`, `amr=[pwd,otp]`) then `grant_type=authorization_code` |
| `provider-refresh-hook.json` | `grant_type=refresh_token` on the session above |

They exist because the hook tests in this package stated the request in places
of the body the provider never fills, so the corpus asserted against a shape it
had invented and could stay green while the handler read nothing at all from a
live request.

Three facts settled by the capture and by nothing else:

- the session's authentication time, assurance level and methods are carried at
  `session.id_token.id_token_claims.{auth_time,acr,amr}` — **two** levels below
  the session, among the OIDC claims and not beside `subject` — and `auth_time`
  is an RFC3339 **string**, not a unix integer. A declaration one level up, or
  typed as a number, is empty on every real request;
- the two hooks do **not** share a body. The token hook carries `request`; the
  refresh hook carries `requester` plus a top-level `client_id` /
  `granted_scopes` / `granted_audience`, and a top-level `subject`;
- the refresh body carries **no token-claims object at all**.
  `access_token_claims` does not occur anywhere in the provider binary
  (`strings /usr/bin/hydra | grep -c access_token_claims` → `0`, against
  `id_token_claims` → `6`).

`client_credentials` has no refresh hook at all — the provider issues no refresh
token for it — so nothing minted through that grant is ever re-examined after
issuance. That is why a personal access token, which is minted through it, can
only be gated where it is minted.

When the provider is upgraded, re-capture rather than hand-edit: a body edited
to suit its reader is the very thing these files exist to stop.
