// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/testsupport/publicreadfixture"
)

// Та же настоящая TLS/roster/account-authority дверь AW, без посева fga_writer.
func TestAccountWriter_NamedPointerRequiresEveryCanonicalAccount(t *testing.T) {
	w := newAWWorld(t)
	doc, err := publicreadfixture.Read(publicreadfixture.PriorEditionFile)
	require.NoError(t, err)
	doc, err = publicreadfixture.WithWrites(doc)
	require.NoError(t, err)
	doc, err = publicreadfixture.WithRegistriesParents(doc, "    parents: [{name: box, type: project}]")
	require.NoError(t, err)
	doc, err = publicreadfixture.WithRevision(doc, 2)
	require.NoError(t, err)
	m, err := manifest.Load(doc)
	require.NoError(t, err)
	w.applyDelivered("именованный указатель проекта", m)
	snapshot := func() string {
		var claims string
		require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text),'[]'::jsonb)::text FROM kaname.resource_registration_pointer x`).Scan(&claims))
		return w.snapshot() + claims
	}
	own := w.regIn("named-account-a", w.prjA, w.accA)
	own.Relation = "box"
	require.NoError(t, w.call("registry", own))
	foreign := w.regIn("named-account-b", w.prjC, w.accB)
	foreign.Relation = "box"
	before := snapshot()
	require.Error(t, w.call("registry", foreign))
	require.Equal(t, before, snapshot(), "чужой account не оставляет named claim или журнал")
	before = snapshot()
	require.Error(t, w.call("vpc", own))
	require.Equal(t, before, snapshot(), "account authority не заменяет владение типом")
	w.withRegistryB("named-b-allowed", func() { require.NoError(t, w.call("registry", foreign)) })
	// Два точных pointer-факта одного объекта: owner обязан получить authority
	// обоих аккаунтов, а не выбрать первый account по присланной цепи.
	sharedA := w.regIn("named-two-accounts", w.prjA, w.accA)
	sharedA.Relation = "box"
	sharedB := w.regIn("named-two-accounts", w.prjC, w.accB)
	sharedB.Relation = "box"
	require.NoError(t, w.call("registry", sharedA))
	w.withRegistryB("named-b-second", func() { require.NoError(t, w.call("registry", sharedB)) })
	owner := ownerOn("user:"+string(w.usrA), sharedA.Object, "", "")
	before = snapshot()
	require.Error(t, w.call("registry", owner))
	require.Equal(t, before, snapshot(), "named pointers не сужают множество выведенных accounts")
	w.withRegistryB("named-b-owner", func() { require.NoError(t, w.call("registry", owner)) })
}
