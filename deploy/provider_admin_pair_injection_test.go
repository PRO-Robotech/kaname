// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// provider_admin_pair_injection_test.go — доказательство того, что перепись
// соседнего файла СПОСОБНА упасть и падает на своём предмете.
//
// Инъекция зовёт ТО ЖЕ ТЕЛО (`judgeProviderAdminPair`) и ТОТ ЖЕ распознаватель
// (`leafNames`/`namesAnyOf`), что исполняется на дереве.
package deploy_test

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestProviderAdminPair_DecidedProfileIsSilent(t *testing.T) {
	// КОНТРОЛЬ: адрес назван, выбор объявлен — перепись молчит.
	findings := judgeProviderAdminPair(
		map[string]bool{"chart/values.prod.yaml": true},
		map[string]bool{"chart/values.prod.yaml": true},
		map[string]string{})
	if len(findings) != 0 {
		t.Fatalf("перепись покраснела на целом дереве: %v", findings)
	}
}

func TestProviderAdminPair_HalfAPairIsAFinding(t *testing.T) {
	// ИНЪЕКЦИЯ, ОДИН ФАКТ против контроля: выбор не объявлен.
	findings := judgeProviderAdminPair(
		map[string]bool{"chart/values.prod.yaml": true},
		map[string]bool{},
		map[string]string{})
	if len(findings) != 1 || !strings.Contains(findings[0], "chart/values.prod.yaml") {
		t.Fatalf("половина пары не найдена: %v", findings)
	}
}

func TestProviderAdminPair_ExcusedStandProfileIsSilent(t *testing.T) {
	// ЗАКОННЫЙ БЛИЗНЕЦ инъекции выше: тот же профиль, но НАЗВАН в ведомости.
	findings := judgeProviderAdminPair(
		map[string]bool{"umbrella/values.prod.yaml": true},
		map[string]bool{},
		map[string]string{"umbrella/values.prod.yaml": "профиль нашего стенда"})
	if len(findings) != 0 {
		t.Fatalf("названный в ведомости профиль дал находку: %v", findings)
	}
}

func TestProviderAdminPair_StaleLedgerEntryIsAFinding(t *testing.T) {
	// САМОИСТЕЧЕНИЕ: запись, чей профиль адреса больше не называет.
	findings := judgeProviderAdminPair(
		map[string]bool{"chart/values.prod.yaml": true},
		map[string]bool{"chart/values.prod.yaml": true},
		map[string]string{"umbrella/values.gone.yaml": "причина без предмета"})
	if len(findings) != 1 || !strings.Contains(findings[0], "values.gone.yaml") {
		t.Fatalf("протухшая запись не найдена: %v", findings)
	}
}

// TestProviderAdminPair_RecognizerReadsLeavesBehindAnyPrefix — распознаватель
// судит ЛИСТ дерева значений, поэтому алиас подчарта его не сбивает.
//
// Без этого свойства перепись читала бы зонт (где служба стоит за алиасом
// `kaname`) как «адреса не называет» — то есть молчала бы ровно на пяти
// профилях из шести.
func TestProviderAdminPair_RecognizerReadsLeavesBehindAnyPrefix(t *testing.T) {
	var behindAlias any
	if err := yaml.Unmarshal([]byte(
		"kaname:\n  platform:\n    iam:\n      hydraAdminUrl: https://x.invalid\n"), &behindAlias); err != nil {
		t.Fatalf("синтетика не разбирается: %v", err)
	}
	leaves := map[string]bool{}
	leafNames(behindAlias, leaves)
	if !namesAnyOf(leaves, adminAddressLeaves) {
		t.Fatal("адрес за алиасом подчарта не распознан")
	}

	// ЗАКОННЫЙ БЛИЗНЕЦ: профиль без этой ручки не должен опознаваться.
	var without any
	if err := yaml.Unmarshal([]byte("kaname:\n  platform:\n    iam:\n      hydraIssuer: https://x.invalid\n"), &without); err != nil {
		t.Fatalf("синтетика не разбирается: %v", err)
	}
	leaves = map[string]bool{}
	leafNames(without, leaves)
	if namesAnyOf(leaves, adminAddressLeaves) {
		t.Fatal("соседняя ручка сосчитана адресом административного контура")
	}

	// ВЫБОР узнаётся тем же порядком, и его близнец — тоже.
	var decided any
	if err := yaml.Unmarshal([]byte("authn:\n  providerAdminAuth: none\n"), &decided); err != nil {
		t.Fatalf("синтетика не разбирается: %v", err)
	}
	leaves = map[string]bool{}
	leafNames(decided, leaves)
	if !namesAnyOf(leaves, adminAuthLeaves) {
		t.Fatal("объявленный выбор не распознан")
	}
}
