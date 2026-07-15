// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

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

	"github.com/PRO-Robotech/kacho/pkg/operations"
)

// PrincipalUserID returns the principal's user-id for user / service-account
// / system-bootstrap principals; empty string for anonymous or empty ctx.
//
// Use this when writing DB rows or audit-log entries that must carry the
// authenticated caller's id. Never trust a request-body field for these.
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
	if p.ID == "" {
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
