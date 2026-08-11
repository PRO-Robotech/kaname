# Subject-privileges visibility — account-admin sees member privileges (by-design)

By-design note for `AccessBindingService.ListSubjectPrivileges`.

## Decision (conscious, accepted)

An account-admin / owner who views the privileges of a member of **their own
Account** sees that member's `role_name`, `scope`, `granted_by_user_id` and
`created_at`. This is intentional **audit visibility** — "who has which roles
inside my Account" — not an information leak.

Rationale: the Account is the IAM tenancy boundary. An admin who is authorized to
**grant / revoke** roles on the account tree (the `requireGrantAuthority` set) is
equally authorized to **see** the roles already held by members. "Who may grant"
== "who may view", keeping the authz model minimal and consistent.

## Authorization gate

`ListSubjectPrivileges` allows the caller iff EITHER:

- `IsSelf(subject_id)` — the caller views their own privileges; OR
- the caller administers the **subject's home Account**
  (`user.account_id` / `serviceAccount.account_id`): owner of that Account
  (`accounts.owner_user_id`) OR FGA `admin` on `account:<homeAccountId>`.

Cross-account reads (caller has neither self nor admin on the subject's home
account) are rejected with `PERMISSION_DENIED` — no privilege data is returned
(cross-account isolation). The subject's home account is resolved via a
within-`kacho_iam` `Users().Get` / `ServiceAccounts().Get` (same-schema read,
**not** a new cross-domain edge).

## Scope-gated, not per-row filtered

The gate authorizes the caller for the **entire** set of the subject's
privileges, so no per-row `listauthz` result-filtering is applied (parity with
`ListBySubject` / `ListByAccount`). There is no heterogeneous per-row ownership
to filter.

## Distinction from `ListBySubject`

`ListBySubject` keeps its **strict self-list** contract (caller may only read
their own bindings; group → membership) and returns raw `AccessBinding` rows. It
is unchanged. `ListSubjectPrivileges` is a new, additive RPC with a broader
authz tier and an enriched response — the existing self-list contract is not
altered (no silent semantic break for current consumers).
