// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Отдельно арендованная проба протокола использует настоящий установленный удостоверяющий материал издателя
// и тот же допустимый вход ACT RID03. Родитель завершает процесс только после подтверждения Node
// полного закрытого входа, до выдачи разрешения HTTP.
// Это доказывает очистку секретов при внезапном завершении, а не публичную приёмку RID.
func TestRIDNewmanProtocolIssuer(t *testing.T) {
	ridNewmanProtocolEnabled(t)
	for _, tc := range []struct{ name, mode string }{
		{"NodeKillIssuer", "node-kill"},
		{"GroupKillIssuer", "group-kill"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newRIDLifecycleWorld(t, "S1", false)
			f := w.f
			// Сохраняем нативную подготовку GRANT штатного публичного случая.
			nativeSubject := f.ridSA(t, f.tenantID, "rid-grantee")
			g := w.grant(t, w.bindingInput("service_account", nativeSubject, w.pull, "registry.registries", w.object))
			require.Equal(t, w.gd.Id, g.DelegationId)
			subject := f.ridSA(t, f.tenantID, "rid03-newman-grantee")
			request := w.bindingInput("service_account", subject, w.pull, "registry.registries", w.object)
			token := f.ridToken(t, w.issuer)
			before := rid03StableNewmanSnapshot(t, w)
			rid03RequirePremise(t, w, before, "GRANT")
			id := "registry-installation-rid03-S1-GRANT-ACT"
			expected := rid03NewmanExpectation{
				CaseID: id, Mode: "S1", Scenario: "GRANT", Phase: "ACT",
				Actor: w.issuer.ID, Operator: string(f.given.user), Issuer: w.issuer.ID,
				Creator: f.creator.ID, System: f.baseline.SystemID, Tenant: f.tenantID,
				InstallationGD: w.gd.Id, Request: request, Path: "/iam/v1/accessBindings",
				Snapshot: before,
			}
			label := ridNewmanProbeLabel(tc.mode) + "-issuer"
			ridRunNewmanPhaseMode(t, f, "registry-installation-rid03", id, label,
				map[string]any{"rid03Expected": expected, "jwtRIDIssuer": token}, tc.mode)
			after := rid03StableNewmanSnapshot(t, w)
			rid03RequireReadOnly(t, before, after)
			rid08Write(t, f.session.Root, label+"-issuer-primary-bracket", map[string]any{
				"caseId": id, "probe": tc.mode, "credentialKind": "installed-issuer",
				"fullPrimarySnapshotUnchanged": rid03SnapshotEqual(before, after),
				"beforePrimarySHA256":          ridWholeDigest(t, before.Raw),
				"afterPrimarySHA256":           ridWholeDigest(t, after.Raw),
				"publicAcceptance":             false, "wholeDoDAccepted": false,
			})
		})
	}
}
