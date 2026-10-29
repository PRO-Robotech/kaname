// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzguard

// front_admission_test.go — кого пускает собственный внутренний REST-фронт
// (SEC-1017-1). Сквозная проба через настоящий фронт и слушатель —
// `internal/restfront/internal_front_check_lane_test.go`; здесь — таблица допуска
// по каждому профилю словаря и связь допуска с объявлением сужений.

import (
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/moduleidentity"
	"github.com/PRO-Robotech/kaname/internal/testsupport/moduleroster"
)

// TestHopAdmits_RefusesWhomTheHopCannotNarrow — край и модуль-владелец пущены;
// плоскость данных, лист вне перечня и непроверенный предъявитель — нет.
func TestHopAdmits_RefusesWhomTheHopCannotNarrow(t *testing.T) {
	ca := moduleroster.NewCA(t, "internal")
	d := moduleroster.Domain()
	roster := moduleroster.Roster(t)
	for name, tc := range map[string]struct {
		st    *tls.ConnectionState
		admit bool
	}{
		"край":                    {st: ca.ConnectionState(t, "spiffe://kacho.cloud/ns/kacho/sa/kacho-api-gateway"), admit: true},
		"модуль-владелец vpc":     {st: ca.ConnectionState(t, moduleroster.DeclaredVPC), admit: true},
		"плоскость данных":        {st: ca.ConnectionState(t, "spiffe://kacho.cloud/ns/registry/sa/kacho-registry-dp")},
		"лист вне перечня":        {st: ca.ConnectionState(t, "spiffe://kacho.cloud/ns/intruder/sa/kacho-vpc")},
		"непроверенный лист":      {st: &tls.ConnectionState{PeerCertificates: ca.ConnectionState(t, moduleroster.DeclaredVPC).PeerCertificates}},
		"без рукопожатия (стенд)": {st: nil},
	} {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, tc.admit, HopAdmits(roster, d, tc.st))
			require.Equal(t, tc.admit, InternalFrontAdmission(true, roster, d)(tc.st), "боевой допуск фронта")
			require.True(t, InternalFrontAdmission(false, roster, d)(tc.st), "вне боевого режима допуск вырождается")
		})
	}
}

// TestHopAdmits_FollowsTheNarrowingDeclaration — допуск выведен из объявления
// сужений, а не выписан: профиль отвергнут ровно тогда, когда какой-либо метод
// хопа сужается для него по личности. Объявление без единого метода хопа
// означало бы, что фронт не сужает никого, и предмет допуска исчез бы молча.
func TestHopAdmits_FollowsTheNarrowingDeclaration(t *testing.T) {
	hop := hopMethodSet(profileMethodSets())
	narrowedOnHop := 0
	for m := range callerNarrowedArguments {
		if _, ok := hop[m]; ok {
			narrowedOnHop++
		}
	}
	t.Logf("методов хопа %d, из них сужаемых по личности %d; профилей словаря %d",
		len(hop), narrowedOnHop, len(moduleidentity.Profiles()))
	require.NotZero(t, narrowedOnHop, "ни один метод хопа не сужается по личности: допуск фронта судить не по чему")
	require.True(t, NarrowsCallerArgument(internalCheckMethod, moduleidentity.ProfileDataPlane))
	for _, p := range []moduleidentity.Profile{moduleidentity.ProfileEdge, moduleidentity.ProfileModuleWriter} {
		require.Falsef(t, NarrowsCallerArgument(internalCheckMethod, p), "Check сужается для профиля %s", p)
	}
}
