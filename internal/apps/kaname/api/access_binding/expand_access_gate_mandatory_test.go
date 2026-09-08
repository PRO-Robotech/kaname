// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// expand_access_gate_mandatory_test.go — the authority gate on ExpandAccess must
// be UNCONDITIONAL, not "applied when the ports happen to be wired".
//
// ExpandAccess answers "who can do <relation> on <object>", resolving group
// usersets down to concrete people and machine accounts. Its catalog entry asks
// `viewer` on the cluster singleton — a relation the cluster bootstrap
// deliberately grants to `user:*` so the global reference catalog (regions,
// zones, disk types) is readable by anyone authenticated. That question is
// therefore answered by EVERY authenticated subject, and this use-case's own
// gate is the only thing standing between a tenant and the cluster's
// authorization graph.
//
// A gate that runs only "if a port is wired" is not that thing: a composition
// that forgets a setter hands the whole graph to anyone with a token, silently
// and without a single failing check. The same shape was caught on kacho-vpc's
// internal NIC listing during self-review — the empty-subject cut-off there was
// made unconditional for exactly this reason.
//
// Observable asserted here: what a stranger RECEIVES (no principals) and what
// the service DOES (the userset is never walked), not merely the status code.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestExpandAccess_UnwiredAuthority_FailsClosed — with NO authority ports wired
// the use-case must DENY, not answer. Unwired means "authority is unresolvable",
// which is "no" — never "yes".
func TestExpandAccess_UnwiredAuthority_FailsClosed(t *testing.T) {
	exp := &fakeLister{byNode: map[string][]string{
		"account:acc_foreign#viewer": {"user:usr_secret_member", "service_account:sva_secret"},
	}}
	// Deliberately NOT calling WithGrantAuthority — the degraded composition.
	uc := NewExpandAccessUseCase(exp)

	res, truncated, err := uc.Execute(foreignCtx(), "account", "acc_foreign", "viewer", 0)

	// The disclosure comes first: assert what the stranger RECEIVED before
	// asserting the status, so a regression reports the leak itself rather than
	// only a missing error.
	assert.Empty(t, res, "no principal may be disclosed when authority is unresolvable")
	assert.Equal(t, 0, exp.calls, "the userset must not be walked at all")
	assert.False(t, truncated)
	require.Error(t, err, "an unresolvable authority must deny, never answer")
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// TestExpandAccess_OnlyRelationsWired_StillGated — the repo half unwired must not
// weaken the gate either: a leaf object authorizes purely through the relation
// store, and a caller the store denies stays denied.
func TestExpandAccess_OnlyRelationsWired_StillGated(t *testing.T) {
	// Тип назван так, как его знает МОДЕЛЬ (`compute_instance`). Прежде здесь
	// стояла точечная форма каталога (`compute.instance`), которую модель не
	// объявляет вовсе: с ней вход отвергается раньше стража, и проба утверждала бы
	// про порядок отказов, а не про то, что страж безусловен (#1290).
	exp := &fakeLister{byNode: map[string][]string{
		"compute_instance:inst_x#v_delete": {"user:usr_secret_member"},
	}}
	uc := NewExpandAccessUseCase(exp).WithGrantAuthority(nil, &denyingFGA{}, nil)

	res, _, err := uc.Execute(foreignCtx(), "compute_instance", "inst_x", "v_delete", 0)

	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Empty(t, res)
	assert.Equal(t, 0, exp.calls, "the userset must not be walked at all")
}

// TestExpandAccess_AbsentObject_IndistinguishableFromForeign — the denial must
// not double as an existence oracle.
//
// The authority gate resolves the owning account through the database, so an
// object that does not exist produced NOT_FOUND while an object that exists but
// belongs to someone else produced PERMISSION_DENIED. Any authenticated subject
// could therefore ask this RPC whether a given account id is real — the front
// door does not narrow that, since its catalog question is answered by everyone.
// A caller with no authority over an object must not learn whether the object is
// there, so both answers must be the SAME code and the SAME text.
func TestExpandAccess_AbsentObject_IndistinguishableFromForeign(t *testing.T) {
	const existingForeign = "acc_foreign"
	// The fake resolves `acc_foreign` (owned by usr_owner) and reports every other
	// id as absent.
	repo := newStrictDupFakeRepo("usr_owner", existingForeign)
	exp := &fakeLister{byNode: map[string][]string{
		"account:" + existingForeign + "#viewer": {"user:usr_secret_member"},
	}}
	uc := NewExpandAccessUseCase(exp).WithGrantAuthority(repo, &denyingFGA{}, nil)

	_, _, errForeign := uc.Execute(foreignCtx(), "account", existingForeign, "viewer", 0)
	_, _, errAbsent := uc.Execute(foreignCtx(), "account", "acc_no_such_thing", "viewer", 0)

	require.Error(t, errForeign)
	require.Error(t, errAbsent)
	assert.Equal(t, status.Code(errForeign), status.Code(errAbsent),
		"an absent object and a foreign one must answer with the same code")
	assert.Equal(t, status.Convert(errForeign).Message(), status.Convert(errAbsent).Message(),
		"an absent object and a foreign one must answer with the same text")
	assert.Equal(t, codes.PermissionDenied, status.Code(errAbsent))
	assert.Equal(t, 0, exp.calls)
}
