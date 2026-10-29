// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package moduleidentity

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/grpcsrv"

	"github.com/PRO-Robotech/kaname/internal/servicesan"
)

// domain — домен доверия проб.
var domain = grpcsrv.NewTrustDomain("kaname.test")

// probeForm — форма имени службы проб (kaname#308): учётки записей названы ею.
var probeForm = servicesan.NewForm("kacho-{service}")

// TestParse_DeclaredPairIsRecognizedWithItsProfile — объявленная пара
// признаётся, и признание несёт профиль и имя службы, выведенное из учётки.
func TestParse_DeclaredPairIsRecognizedWithItsProfile(t *testing.T) {
	r, err := Parse(probeForm, []string{" kacho/kacho-vpc=module-writer ", "", "edge-ns/kacho-api-gateway=edge"})
	require.NoError(t, err)
	require.Len(t, r.Identities(), 2, "пустая запись записью не становится")

	id, ok := r.Lookup(domain, "spiffe://kaname.test/ns/kacho/sa/kacho-vpc")
	require.True(t, ok)
	require.Equal(t, Identity{Namespace: "kacho", Account: "kacho-vpc", Service: "vpc", Profile: ProfileModuleWriter}, id)

	id, ok = r.Lookup(domain, "spiffe://kaname.test/ns/edge-ns/sa/kacho-api-gateway")
	require.True(t, ok)
	require.Equal(t, "api-gateway", id.Service)
	require.Equal(t, ProfileEdge, id.Profile)
}

// TestLookup_OnlyTheDeclaredPairIsAModule — признание по ПАРЕ: та же учётка в
// другом пространстве, другая учётка в том же пространстве, чужой домен и
// идентификатор не той формы — не модуль.
func TestLookup_OnlyTheDeclaredPairIsAModule(t *testing.T) {
	r, err := Parse(probeForm, []string{"kacho/kacho-vpc=module-writer"})
	require.NoError(t, err)

	for name, san := range map[string]string{
		"учётка в необъявленном пространстве": "spiffe://kaname.test/ns/intruder/sa/kacho-vpc",
		"необъявленная учётка":                "spiffe://kaname.test/ns/kacho/sa/kacho-compute",
		"чужой домен":                         "spiffe://other.test/ns/kacho/sa/kacho-vpc",
		"лишний сегмент пространства":         "spiffe://kaname.test/ns/x/kacho/sa/kacho-vpc",
		"лишний сегмент учётки":               "spiffe://kaname.test/ns/kacho/sa/kacho-vpc/extra",
		"пустое пространство":                 "spiffe://kaname.test/ns//sa/kacho-vpc",
		"пустая строка":                       "",
	} {
		t.Run(name, func(t *testing.T) {
			_, ok := r.Lookup(domain, san)
			require.False(t, ok, "%q признан модулем", san)
		})
	}
}

// TestLookup_UndeclaredDomainRecognizesNobody — необъявленный домен не узнаёт
// никого, и пустой перечень — тоже.
func TestLookup_UndeclaredDomainRecognizesNobody(t *testing.T) {
	r, err := Parse(probeForm, []string{"kacho/kacho-vpc=module-writer"})
	require.NoError(t, err)
	_, ok := r.Lookup(grpcsrv.TrustDomain{}, "spiffe://kaname.test/ns/kacho/sa/kacho-vpc")
	require.False(t, ok)

	_, ok = Roster{}.Lookup(domain, "spiffe://kaname.test/ns/kacho/sa/kacho-vpc")
	require.False(t, ok)
}

// TestFromContext_OnlyAVerifiedLeafIsRecognized — признание вызывающего
// gRPC-слушателя требует проверенного листа.
func TestFromContext_OnlyAVerifiedLeafIsRecognized(t *testing.T) {
	r, err := Parse(probeForm, []string{"kacho/kacho-vpc=module-writer"})
	require.NoError(t, err)
	san := "spiffe://kaname.test/ns/kacho/sa/kacho-vpc"

	_, ok := r.FromContext(grpcsrv.WithCertIdentityIn(context.Background(), domain, san, true))
	require.True(t, ok)
	_, ok = r.FromContext(grpcsrv.WithCertIdentityIn(context.Background(), domain, san, false))
	require.False(t, ok, "непроверенный лист признан")
	_, ok = r.FromContext(context.Background())
	require.False(t, ok, "вызов без листа признан")
}

// TestParse_RefusesEveryMalformedEntryNamingIt — неисправная запись — ошибка,
// называющая запись, а не молча меньший перечень.
func TestParse_RefusesEveryMalformedEntryNamingIt(t *testing.T) {
	for name, entry := range map[string]string{
		"нет профиля":              "kacho/kacho-vpc",
		"нет пространства":         "kacho-vpc=module-writer",
		"неизвестный профиль":      "kacho/kacho-vpc=root",
		"нет приставки модулей":    "kacho/vpc=module-writer",
		"пустое имя службы":        "kacho/kacho-=module-writer",
		"пространство не имя":      "Kacho/kacho-vpc=module-writer",
		"учётка не имя":            "kacho/kacho_vpc=module-writer",
		"пространство с сегментом": "kacho/x/kacho-vpc=module-writer",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(probeForm, []string{"kacho/kacho-api-gateway=edge", entry})
			require.Error(t, err)
			require.Contains(t, err.Error(), entry)
		})
	}
}

// TestParse_DuplicatePairIsRefused — одна пара — одна личность.
func TestParse_DuplicatePairIsRefused(t *testing.T) {
	_, err := Parse(probeForm, []string{"kacho/kacho-vpc=module-writer", "kacho/kacho-vpc=data-plane"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "declared twice")
}

// TestRequire_EmptyRosterRefusesNamingTheKnob — страж боевой посадки: пустой
// перечень — отказ, называющий ручку; непустой — проход.
func TestRequire_EmptyRosterRefusesNamingTheKnob(t *testing.T) {
	err := Roster{}.Require(Gate{Knob: "authn.module-identities"})
	require.Error(t, err)
	require.True(t, strings.HasPrefix(err.Error(), "authn.module-identities is empty"), err.Error())

	r, perr := Parse(probeForm, []string{"kacho/kacho-vpc=module-writer"})
	require.NoError(t, perr)
	require.NoError(t, r.Require(Gate{Knob: "authn.module-identities"}))
}
