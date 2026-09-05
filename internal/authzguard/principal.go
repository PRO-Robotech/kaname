// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// principal.go — helper: principal-id-as-string for handlers that need to
// stamp `created_by` / `reviewer` / similar identity-derived fields from the
// authenticated caller — never from request-body.
//
// Anti-identity-spoofing: handlers must source these from
// PrincipalFromContext, not from request fields. PrincipalUserID is the
// canonical accessor used by sa_keys, jit_eligibility, jit_pending.
package authzguard

import (
	"context"
	"strings"

	"github.com/PRO-Robotech/kacho/pkg/operations"
)

// fgaReservedChars — characters that carry meaning inside an FGA subject string
// and therefore may never appear inside the id half of one: ':' moves the
// type/id boundary, '#' turns the token into a userset reference, '@' and
// whitespace are separators in the tuple grammar. Mirrors the set the shared
// subject formatter sanitises; here the id is refused outright instead, because
// a principal that cannot be named must not be checked.
const fgaReservedChars = ":#@ \t\n"

// HumanUserID returns the principal's id ONLY when the principal is a human
// user; "" for a service account, a system/bootstrap principal, an unknown type,
// anonymous, or an empty ctx.
//
// Use this — NOT PrincipalUserID — for a column that is a foreign key into
// `users(id)` (`users.invited_by` and anything like it). The distinction is not
// cosmetic: PrincipalUserID deliberately answers for machine and system
// principals too, so a caller that wants "the user" and reaches for the
// user-shaped name gets `sva…`/`bootstrap` back and writes it into a column
// where no such row can exist. That is a constraint violation at insert time,
// surfaced to the caller as the unmapped-FK fallback text, which names neither
// the column nor the cause.
//
// A non-user principal is not an error here and must not be turned into one: it
// is a legitimate actor with no inviting/creating USER to record. Callers leave
// the column NULL and rely on the Operation's `principalType`/`principalId` for
// attribution, which is where a non-user actor belongs.
func HumanUserID(ctx context.Context) string {
	if IsAnonymous(ctx) {
		return ""
	}
	if operations.PrincipalFromContext(ctx).Type != "user" {
		return ""
	}
	return operations.PrincipalFromContext(ctx).ID
}

// PrincipalUserID returns the principal's user-id for user / service-account
// / system-bootstrap principals; empty string for anonymous or empty ctx.
//
// Use this when writing DB rows or audit-log entries that must carry the
// authenticated caller's id. Never trust a request-body field for these.
//
// NOTE the name is wider than it reads: the returned id is NOT necessarily a
// `users(id)`. For a foreign key into that table use HumanUserID above.
//
// Bootstrap-principal (system/bootstrap) is treated as a legitimate identity
// so internal seeds / migrations / fixtures continue to work; the audit row
// carries `created_by="bootstrap"` which is correct.
func PrincipalUserID(ctx context.Context) string {
	if IsAnonymous(ctx) {
		return ""
	}
	p := operations.PrincipalFromContext(ctx)
	switch p.Type {
	case "user", "service_account", "system":
		return p.ID
	default:
		return ""
	}
}

// SubjectFromPrincipal builds the FGA subject string for a principal:
// `user:<id>` for users, `service_account:<id>` for service accounts. It is the
// single source of truth consolidating the previously-inline
// (`subjType:="user"; if p.Type=="service_account" {…}; subject:=t+":"+id`) copies
// scattered across the authz call-sites (#10).
//
// Fail-closed: an unknown principal type, or an empty id, yields ("", false). This
// is STRICTLY SAFER than the inline copies it replaces, which defaulted unknown
// types to "user:" (a latent over-grant). Callers must treat ok=false as "no
// resolvable subject → deny".
func SubjectFromPrincipal(p operations.Principal) (string, bool) {
	if p.ID == "" || strings.ContainsAny(p.ID, fgaReservedChars) {
		// An id carrying a separator would change what the subject string MEANS
		// rather than who it names: `usr#member` reads as a userset reference and
		// `a:b` moves the type boundary. Refuse rather than sanitise — a caller
		// that cannot be named must not be checked.
		return "", false
	}
	switch p.Type {
	case "user":
		return "user:" + p.ID, true
	case "service_account":
		return "service_account:" + p.ID, true
	default:
		return "", false
	}
}

// PrincipalSubject is the ctx variant of SubjectFromPrincipal: it reads the
// principal from ctx and returns its FGA subject. Anonymous / empty ctx → ("",
// false) — fail-closed, the same posture as the FGA Check guards that consume it.
func PrincipalSubject(ctx context.Context) (string, bool) {
	if IsAnonymous(ctx) {
		return "", false
	}
	return SubjectFromPrincipal(operations.PrincipalFromContext(ctx))
}
