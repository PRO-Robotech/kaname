// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func ridNewmanProtocolEnabled(t *testing.T) {
	t.Helper()
	if os.Getenv("KANAME_RID_NEWMAN_PROTOCOL_PROBES") != "1" {
		t.Skip("NOT_EXECUTED: separately leased Newman ACK/forced-kill protocol probes")
	}
	require.Equal(t, "1", os.Getenv("KANAME_RID_ACCEPTANCE"))
	require.Equal(t, "1", os.Getenv("KANAME_RID_NEWMAN"))
	require.True(t, strings.HasPrefix(os.Getenv("KANAME_RID_RUN_ID"), "newman-protocol-"), "probe invocation requires its own protocol-only run ID")
	require.NotEmpty(t, os.Getenv("KANAME_RID_EXPECTED_IDENTITIES_FILE"), "one externally frozen collection identity FILE per probe invocation")
	require.Empty(t, os.Getenv("KANAME_RID_EXPECTED_IDENTITIES_DIR"), "no fabricated twelve-collection identity DIR for protocol probes")
}

// Каждый подтест владеет настоящей штатной фикстурой и внешне зафиксированной коллекцией RID01.
// Принятый случай выполняет только NormalPermit. Пробы завершения останавливаются после настоящего ACK Node,
// до разрешения/HTTP, и не могут попасть в знаменатель публичной приёмки RID.
func ridNewmanProtocolFixture(t *testing.T, mode string, assertion bool) {
	t.Helper()
	ridNewmanProtocolEnabled(t)
	f := newInstallationNativeWorld(t)
	initial := rid01Baseline(t, f)
	requireNativeOK(t, f.apply(t, nativeSingleDelivery(f)), 1)
	f.requireDeliveredPairs(t, "ridfirst")
	if !assertion {
		// Настоящий точный повторный вход предшествует случаю создателя; пробы протокола
		// не претендуют на отдельное обязательство RID обновления токена по настоящим часам.
		requireNativeOK(t, f.apply(t, nativeSingleDelivery(f)), 1)
		f.requireDeliveredPairs(t, "ridfirst")
	}
	snapshot := rid01Baseline(t, f)
	phase := "RENEWAL-AFTER"
	if assertion {
		phase = "EXPIRED-KEY-REFUSAL"
	}
	id := "registry-installation-rid01-" + phase
	expected := rid01PublicExpectation{CaseID: id, Phase: phase, Operator: string(f.given.user), Creator: f.creator.ID, System: f.baseline.SystemID, Tenant: f.tenantID, Modules: []string{"ridfirst"}, Issuers: map[string]string{}, Snapshot: snapshot, Previous: &snapshot.Projection}
	rid01RequirePremise(t, &rid01PublicContext{f: f, Kind: "renewal", Initial: initial}, &expected)
	variables := map[string]any{}
	if assertion {
		require.True(t, time.Now().Before(f.creator.ExpiresAt), "protocol-only assertion probe uses real live protected key; it is NOT expired-key authn/public acceptance")
		proof, end := rid01FreshAssertion(t, f)
		variables["rid01ClientAssertion"] = proof
		variables["rid01IssuanceOrigin"] = f.wire.IssuanceURL
		expected.AssertionExpiresAt = end.Format(time.RFC3339)
		require.Contains(t, []string{"node-kill", "group-kill"}, mode, "assertion protocol probe never permits token HTTP")
	} else {
		variables["jwtRIDCreator"] = f.ridToken(t, f.creator)
	}
	variables["rid01Expected"] = expected
	label := ridNewmanProbeLabel(mode)
	if assertion {
		label += "-assertion"
	} else {
		label += "-creator"
	}
	ridRunNewmanPhaseMode(t, f, "registry-installation-rid01", id, label, variables, mode)
}
func TestRIDNewmanProtocolCreator(t *testing.T) {
	ridNewmanProtocolEnabled(t)
	for _, tc := range []struct{ name, mode string }{{"NormalPermit", "normal-permit"}, {"RejectMissingPermit", "reject-missing-permit"}, {"NodeKillCreator", "node-kill"}, {"GroupKillCreator", "group-kill"}} {
		t.Run(tc.name, func(t *testing.T) { ridNewmanProtocolFixture(t, tc.mode, false) })
	}
}
func TestRIDNewmanProtocolAssertion(t *testing.T) {
	ridNewmanProtocolEnabled(t)
	for _, tc := range []struct{ name, mode string }{{"NodeKillAssertion", "node-kill"}, {"GroupKillAssertion", "group-kill"}} {
		t.Run(tc.name, func(t *testing.T) { ridNewmanProtocolFixture(t, tc.mode, true) })
	}
}
