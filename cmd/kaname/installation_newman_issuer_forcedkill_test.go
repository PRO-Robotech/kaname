// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// A separately leased protocol probe uses the real installed issuer credential
// and the same lawful RID03 ACT input. The parent kills only after Node has
// acknowledged the complete private input, before HTTP permission is released.
// This proves secret cleanup on abrupt termination, not public RID acceptance.
func TestRIDNewmanProtocolIssuer(t *testing.T) {
	ridNewmanProtocolEnabled(t)
	for _, tc := range []struct{ name, mode string }{
		{"NodeKillIssuer", "node-kill"},
		{"GroupKillIssuer", "group-kill"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newRIDLifecycleWorld(t, "S1", false)
			f := w.f
			// Preserve the native GRANT setup used by the ordinary public case.
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
