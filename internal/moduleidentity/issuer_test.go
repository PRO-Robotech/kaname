// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package moduleidentity_test

import (
	"crypto/tls"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/moduleidentity"
	"github.com/PRO-Robotech/kaname/internal/testsupport/moduleroster"
)

// bound — перечень с личностью края, привязанной к центру края, и двумя
// доверенными центрами (kaname#988).
func bound(t *testing.T) (moduleidentity.Roster, *moduleroster.CA, *moduleroster.CA) {
	t.Helper()
	edge, internal := moduleroster.NewCA(t, "edge-ca"), moduleroster.NewCA(t, "internal-ca")
	r, err := moduleidentity.ParseWithIssuers(moduleroster.NameForm(), []string{"kacho/kacho-api-gateway=edge@edge"},
		moduleidentity.IssuerSet{"edge": {edge.Cert()}, "internal": {internal.Cert()}})
	require.NoError(t, err)
	return r, edge, internal
}

const edgeSAN = "spiffe://" + moduleroster.DomainName + "/ns/kacho/sa/kacho-api-gateway"

// TestFromTLSState_BindsTheLeafToItsIssuer — лист своего центра признаётся,
// лист чужого доверенного центра — нет; цепочки нет — нет.
func TestFromTLSState_BindsTheLeafToItsIssuer(t *testing.T) {
	r, edge, internal := bound(t)
	d := moduleroster.Domain()

	id, ok := r.FromTLSState(d, edge.ConnectionState(t, edgeSAN))
	require.True(t, ok)
	require.Equal(t, "edge", id.Issuer)

	_, ok = r.FromTLSState(d, internal.ConnectionState(t, edgeSAN))
	require.False(t, ok, "лист чужого доверенного центра признан")

	_, ok = r.FromTLSState(d, &tls.ConnectionState{})
	require.False(t, ok, "рукопожатие без проверенной цепочки признано")
	_, ok = r.FromTLSState(d, nil)
	require.False(t, ok)
}

// TestFromContext_BindsTheLeafToItsIssuer — тот же суд на пире gRPC-вызова.
func TestFromContext_BindsTheLeafToItsIssuer(t *testing.T) {
	r, edge, internal := bound(t)
	_, ok := r.FromContext(edge.PeerContext(t, edgeSAN))
	require.True(t, ok)
	_, ok = r.FromContext(internal.PeerContext(t, edgeSAN))
	require.False(t, ok, "лист чужого доверенного центра признан")
	_, ok = r.FromContext(moduleroster.IdentityContext(edgeSAN))
	require.False(t, ok, "привязанная личность признана без проверенной цепочки")
}

// TestLookup_RefusesABoundIdentity — по одному имени привязанная личность не
// признаётся: цепочки, которой доказать выпустившего, у этого пути нет.
func TestLookup_RefusesABoundIdentity(t *testing.T) {
	r, _, _ := bound(t)
	_, ok := r.Lookup(moduleroster.Domain(), edgeSAN)
	require.False(t, ok)
}

// TestParse_RefusesAnUndeclaredIssuer — центр, названный записью, обязан быть
// объявлен и нести якорь; по именам — без якорей — его судит страж настройки.
func TestParse_RefusesAnUndeclaredIssuer(t *testing.T) {
	_, err := moduleidentity.Parse(moduleroster.NameForm(), []string{"kacho/kacho-vpc=module-writer@internal"})
	require.ErrorContains(t, err, `names the issuer "internal"`)

	_, err = moduleidentity.ParseWithIssuers(moduleroster.NameForm(), []string{"kacho/kacho-vpc=module-writer@internal"},
		moduleidentity.IssuerSet{"internal": {}})
	require.ErrorContains(t, err, "without a single certificate")

	_, err = moduleidentity.ParseDeclared(moduleroster.NameForm(), []string{"kacho/kacho-vpc=module-writer@internal"}, []string{"edge"})
	require.ErrorContains(t, err, `names the issuer "internal"`)
	_, err = moduleidentity.ParseDeclared(moduleroster.NameForm(), []string{"kacho/kacho-vpc=module-writer@internal"}, []string{"internal"})
	require.NoError(t, err, "близнец: центр объявлен по имени")

	_, err = moduleidentity.ParseDeclared(moduleroster.NameForm(), []string{"kacho/kacho-vpc=module-writer@Bad_Name"}, []string{"Bad_Name"})
	require.ErrorContains(t, err, "is not a name")
}

// TestRequireIssuerBinding_NamesEveryUnboundIdentity — страж боевой посадки:
// непривязанная личность — отказ с её парой; все привязаны — проход.
func TestRequireIssuerBinding_NamesEveryUnboundIdentity(t *testing.T) {
	g := moduleidentity.Gate{Knob: "authn.module-identities"}
	r, err := moduleidentity.ParseDeclared(moduleroster.NameForm(), []string{
		"kacho/kacho-api-gateway=edge@edge", "kacho/kacho-vpc=module-writer",
	}, []string{"edge"})
	require.NoError(t, err)
	err = r.RequireIssuerBinding(g)
	require.ErrorContains(t, err, "kacho/kacho-vpc")
	require.NotContains(t, err.Error(), "kacho/kacho-api-gateway")

	r, err = moduleidentity.ParseDeclared(moduleroster.NameForm(), []string{"kacho/kacho-api-gateway=edge@edge"}, []string{"edge"})
	require.NoError(t, err)
	require.NoError(t, r.RequireIssuerBinding(g))
}

// TestIssuerSet_ComparesTheAnchorByBytesNotByName — якорь сравнивается
// побайтово: центр с тем же именем субъекта, но другим ключом — чужой.
func TestIssuerSet_ComparesTheAnchorByBytesNotByName(t *testing.T) {
	edge := moduleroster.NewCA(t, "edge-ca")
	impostor := moduleroster.NewCA(t, "edge-ca")
	r, err := moduleidentity.ParseWithIssuers(moduleroster.NameForm(), []string{"kacho/kacho-api-gateway=edge@edge"},
		moduleidentity.IssuerSet{"edge": []*x509.Certificate{edge.Cert()}})
	require.NoError(t, err)
	_, ok := r.FromTLSState(moduleroster.Domain(), impostor.ConnectionState(t, edgeSAN))
	require.False(t, ok, "центр с тем же именем субъекта признан за якорь")
}
