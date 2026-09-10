// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// outbound_lane_has_an_operator_knob_injection_test.go — доказательство того,
// что соседний гейт СПОСОБЕН упасть и падает на своём предмете.
//
// Инъекция зовёт ТО ЖЕ ТЕЛО ВЕРДИКТА (`judgeOutboundLanes`) и ТЕ ЖЕ
// распознаватели (`dialCoordinateLeaf`, `canonicalEnvName`, `declaredEnvNames`,
// `configLeafPaths`), что исполняются на дереве.
//
// ПОДМЕНЯЕТСЯ ОДИН ФАКТ на случай, и у каждого отрицания рядом законный близнец.
package deploy_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

func boolSet(xs ...string) map[string]bool {
	m := map[string]bool{}
	for _, x := range xs {
		m[x] = true
	}
	return m
}

func TestOutboundLaneInjection_LaneRenderedByTheChartIsSilent(t *testing.T) {
	// КОНТРОЛЬ: полоса объявлена ключом, который чарт рендерит.
	f := judgeOutboundLanes([]string{"repository.postgres.url"},
		boolSet("repository.postgres.url"), boolSet(), declaredEnvNames)
	if len(f) != 0 {
		t.Fatalf("вердикт покраснел на полосе, которую чарт рендерит: %v", f)
	}
}

func TestOutboundLaneInjection_LaneNamedByAProfileIsSilent(t *testing.T) {
	// ВТОРАЯ ЗАКОННАЯ ФОРМА РУЧКИ: ключ рендером не отдаётся, но профиль
	// НАЗЫВАЕТ его переменную. Так объявлены три дороги к поставщику личности.
	f := judgeOutboundLanes([]string{"authn.hydra-admin-url"},
		boolSet(), boolSet("KANAME_HYDRA_ADMIN_URL"), declaredEnvNames)
	if len(f) != 0 {
		t.Fatalf("вердикт покраснел на полосе, названной профилем: %v", f)
	}
}

func TestOutboundLaneInjection_LaneWithNoKnobIsAFinding(t *testing.T) {
	// ИНЪЕКЦИЯ, ОДИН ФАКТ против контроля: у полосы нет ни рендера, ни имени в
	// профиле. Это и есть состояние почтовой полосы до фикса #2474.
	f := judgeOutboundLanes([]string{"invite-mail.relay"},
		boolSet(), boolSet(), declaredEnvNames)
	if len(f) != 1 || !strings.Contains(f[0], "invite-mail.relay") {
		t.Fatalf("полоса без ручки не найдена: %v", f)
	}
	// Находка обязана НАЗЫВАТЬ переменную, которой ключ подаётся: находка,
	// называющая симптом, посылает читателя искать не там.
	if !strings.Contains(f[0], "KANAME_INVITE_MAIL__RELAY") {
		t.Fatalf("находка не называет переменной подачи: %s", f[0])
	}
}

// TestOutboundLaneInjection_CanonicalEnvNameIsNotEnoughAlone — распознаватель
// знает ОБЕ формы имени переменной.
//
// У части ключей есть СВОЯ привязка, и профиль называет именно её. Знай
// распознаватель одну каноническую форму — он объявил бы находкой три дороги к
// поставщику, которые объявлены верно; знай он только объявленную — молчал бы о
// ключах, которых в таблице обязательных величин нет вовсе.
func TestOutboundLaneInjection_KnowsBothEnvWritings(t *testing.T) {
	if got := canonicalEnvName("invite-mail.relay"); got != "KANAME_INVITE_MAIL__RELAY" {
		t.Fatalf("каноническая форма имени выведена неверно: %s", got)
	}
	names := declaredEnvNames("authn.hydra-admin-url")
	var sawDeclared bool
	for _, n := range names {
		if n == "KANAME_HYDRA_ADMIN_URL" {
			sawDeclared = true
		}
	}
	if !sawDeclared {
		t.Fatalf("объявленная владельцем форма имени не найдена среди %v", names)
	}
	// ЗАКОННЫЙ БЛИЗНЕЦ: у ключа без своей привязки формы ровно одна, и вторая
	// не выдумывается.
	if got := declaredEnvNames("invite-mail.relay"); len(got) != 1 {
		t.Fatalf("для ключа без привязки выдумана вторая форма: %v", got)
	}
}

// TestOutboundLaneInjection_VocabularyKnowsItsFormsAndOnlyThem — словарь
// исходящих координат: обе стороны.
func TestOutboundLaneInjection_VocabularyKnowsItsFormsAndOnlyThem(t *testing.T) {
	for _, yes := range []string{
		"repository.postgres.url", "repository.postgres.slave-url",
		"authn.hydra-admin-url", "invite-mail.relay", "invite-mail.login-url",
	} {
		if !dialCoordinateLeaf(yes) {
			t.Fatalf("координата чужого узла %q не опознана", yes)
		}
	}
	// ЗАКОННЫЙ БЛИЗНЕЦ: соседние ключи той же секции координатами не являются, и
	// словарь, который их захватит, сделает гейт красным на верном дереве.
	for _, no := range []string{
		"authn.hydra-issuer", "invite-mail.from", "invite-mail.tls-mode",
		"api-server.graceful-shutdown", "logger.level",
	} {
		if dialCoordinateLeaf(no) {
			t.Fatalf("ключ %q ошибочно сосчитан координатой чужого узла", no)
		}
	}
}

// TestOutboundLaneInjection_PopulationComesFromTheDeclaration — популяция
// выводится из объявления настроек, а не выписывается: новое поле входит в неё
// САМО.
//
// Предпосылка проверяется на месте: разбор обязан находить ключи ТРЁХ разных
// секций, иначе «ноль полос» означало бы «отражение ничего не прочло».
func TestOutboundLaneInjection_PopulationComesFromTheDeclaration(t *testing.T) {
	leaves := configLeafPaths()
	if len(leaves) < 50 {
		t.Fatalf("отражение прочло %d листьев — объявление настроек так не выглядит", len(leaves))
	}
	want := map[string]bool{
		"invite-mail.relay":             false,
		"repository.postgres.slave-url": false,
		"authn.hydra-token-url":         false,
	}
	for _, l := range leaves {
		if _, ok := want[l]; ok {
			want[l] = true
		}
	}
	for k, seen := range want {
		if !seen {
			t.Fatalf("ключ %q не найден отражением — популяция читает не то объявление", k)
		}
	}
	// Таблица обязательных величин — ЖИВОЙ источник второй формы имени: пустая
	// означала бы, что вторая форма не проверяется ничем.
	if len(config.RequiredSettings) == 0 {
		t.Fatal("таблица обязательных величин пуста — вторая форма имени переменной беспредметна")
	}
}
