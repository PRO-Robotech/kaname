// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// acr_floor_level_two_enrollment_test.go — способ, чьё предъявление одно даёт
// уровень «2», заводится и снимается только сессией уровня «2» (задача
// kaname#747; приёмка
// `docs/engineering/acceptance/level-two-is-enrolled-at-level-two.md`,
// отпечаток 711609ce…, Р1, Р3, §7 инвариант 1, §8 первая строка; сценарии
// KN747-01…04, -09…11, -13…16).
//
// # ЧТО УТВЕРЖДАЕТСЯ
//
// Две вещи над НАСТОЯЩИМ встроенным каталогом прав службы — тем, который край
// и второй замок читают на каждом запросе:
//
//	(1) ОТНОШЕНИЕ (инвариант 1): пол `AccessKeyService/BeginRegistration`,
//	    `FinishRegistration`, `Revoke` не ниже пола `UserTokenService/Issue`
//	    и не ниже «2» (инвариант 2). Отношение, а не литерал: поднятый пол
//	    выпуска токена поднимает и их.
//	(2) ИСХОД ПРАВИЛА ПОВЫШЕНИЯ (`grpcsrv.EvaluateStepUp`, одно на оба замка):
//	    субъект-человек с уровнем «1» получает на трёх глаголах отказ по
//	    уровню, с уровнем «2» — проход.
//
// # ЧЕГО ЗДЕСЬ НЕТ
//
// Ответ края на недостаток уровня (`401`, `code` 16, вызов с `acr_values`) —
// дом платформы: его производит край до пересылки службе. Порядок «уровень
// раньше свежести» (KN747-16) — свойство механизма: пол судят край и второй
// замок ДО обращения к службе, где живёт окно свежести; проба судит вход этого
// механизма — пол каталога и вердикт общего правила над ним. Сквозной исход
// каждого сценария — кейсы края (§9 п. 4).
//
// # СПОСОБНОСТЬ ПАДАТЬ
//
// Предикат отношения вынесен функцией; инъекция ниже зовёт ТОТ ЖЕ предикат с
// законным близнецом и с каждым видом дефекта.
package authzguard

import (
	"fmt"
	"sort"
	"testing"

	"github.com/PRO-Robotech/corelib/acrlevel"
	"github.com/PRO-Robotech/corelib/grpcsrv"
)

const (
	kn747BeginRegistration  = "kaname.cloud.iam.v1.AccessKeyService/BeginRegistration"
	kn747FinishRegistration = "kaname.cloud.iam.v1.AccessKeyService/FinishRegistration"
	kn747Revoke             = "kaname.cloud.iam.v1.AccessKeyService/Revoke"
	// kn747Anchor — пол, относительно которого судится отношение (инвариант 1).
	kn747Anchor = "kaname.cloud.iam.v1.UserTokenService/Issue"
	// kn747LevelTwo — ступень, которую даёт одно предъявление ключа (Ф11 Р2).
	kn747LevelTwo = "2"
)

// kn747Guarded — глаголы, заводящие либо снимающие способ, чьё предъявление
// одно даёт «2» (§1.2: П1, П3).
var kn747Guarded = []string{kn747BeginRegistration, kn747FinishRegistration, kn747Revoke}

// levelTwoEnrollmentFindings — предикат отношения по ОДНОМУ каталогу.
func levelTwoEnrollmentFindings(lookup ACRRequirementLookup) []string {
	var out []string
	anchor := lookup.RequiredACRMin(kn747Anchor)
	if acrlevel.Rank(anchor) == 0 {
		out = append(out, fmt.Sprintf("%s: пола нет (%q) — отношение сказано ни о чём", kn747Anchor, anchor))
	}
	for _, fqn := range kn747Guarded {
		floor := lookup.RequiredACRMin(fqn)
		if acrlevel.Rank(floor) < acrlevel.Rank(kn747LevelTwo) {
			out = append(out, fmt.Sprintf("%s требует %q: способ, дающий «2» одним предъявлением, "+
				"заводится или снимается сессией ниже «2»", fqn, floor))
		}
		if acrlevel.Rank(anchor) > 0 && acrlevel.Rank(floor) < acrlevel.Rank(anchor) {
			out = append(out, fmt.Sprintf("%s требует %q, %s — %q: заведение способа дешевле "+
				"выпуска, который этот способ открывает", fqn, floor, kn747Anchor, anchor))
		}
	}
	sort.Strings(out)
	return out
}

// TestKN747_FloorOfKeyVerbsIsNotBelowLevelTwo — Р3, инварианты 1 и 2.
func TestKN747_FloorOfKeyVerbsIsNotBelowLevelTwo(t *testing.T) {
	reg := loadRealACRCatalog(t)
	// Фикстура проверяется ДО предмета: якорь отношения обязан быть в каталоге,
	// иначе красное значило бы «каталог не тот», а не «пол не тот».
	anchor := reg.RequiredACRMin(kn747Anchor)
	if acrlevel.Rank(anchor) == 0 {
		t.Fatalf("НЕ ВЫПОЛНИЛОСЬ: у якоря %s в каталоге нет пола (%q)", kn747Anchor, anchor)
	}
	t.Logf("перепись: якорь %s → required_acr_min=%q", kn747Anchor, anchor)
	for _, fqn := range kn747Guarded {
		if _, ok := reg.LookupFQN(fqn); !ok {
			t.Fatalf("НЕ ВЫПОЛНИЛОСЬ: глагола %s нет в каталоге", fqn)
		}
		t.Logf("перепись: %s → required_acr_min=%q", fqn, reg.RequiredACRMin(fqn))
	}
	if f := levelTwoEnrollmentFindings(reg); len(f) > 0 {
		t.Fatalf("способ, дающий «2», заводится дешевле «2» — %d находк(и):\n  %v\n\n"+
			"Пол объявляет контракт (`required_acr_min` у трёх глаголов "+
			"proto/kaname/cloud/iam/v1/access_key_service.proto); каталог службы и копия края "+
			"порождаются из него (kaname#747, Р3).", len(f), f)
	}
}

// TestKN747_StepUpVerdictOnKeyVerbs — исход общего правила повышения над полом
// каталога по каждому сценарию полосы ключа.
func TestKN747_StepUpVerdictOnKeyVerbs(t *testing.T) {
	reg := loadRealACRCatalog(t)
	cases := []struct {
		id, fqn, acr string
		want         grpcsrv.StepUpVerdict
		what         string
	}{
		{"KN747-01", kn747BeginRegistration, "2", grpcsrv.StepUpAllow, "регистрация сессией «2» (пароль и код) — проход"},
		{"KN747-01/finish", kn747FinishRegistration, "2", grpcsrv.StepUpAllow, "приём результата сессией «2» — проход"},
		{"KN747-01/issue", kn747Anchor, "2", grpcsrv.StepUpAllow, "выпуск личного токена сессией «2» — проход"},
		{"KN747-02", kn747BeginRegistration, "1", grpcsrv.StepUpDenyACR, "запрос испытания сессией «1» (код заведён, не предъявлен)"},
		{"KN747-03", kn747FinishRegistration, "1", grpcsrv.StepUpDenyACR, "результат церемонии из сессии «1»"},
		{"KN747-04", kn747BeginRegistration, "1", grpcsrv.StepUpDenyACR, "запрос испытания сессией «1» (кода нет)"},
		{"KN747-09", kn747Revoke, "1", grpcsrv.StepUpDenyACR, "снятие ключа сессией «1»"},
		{"KN747-10", kn747Revoke, "2", grpcsrv.StepUpAllow, "снятие ключа сессией «2» — проход"},
		{"KN747-11", kn747Anchor, "2", grpcsrv.StepUpAllow, "сессия входа ключом («2») выпускает личный токен"},
		{"KN747-13", kn747BeginRegistration, "1", grpcsrv.StepUpDenyACR, "запрос испытания сессией восстановления «1»"},
		{"KN747-14", kn747BeginRegistration, "2", grpcsrv.StepUpAllow, "сессия восстановления с кодом («2») — проход"},
		{"KN747-15", kn747BeginRegistration, "2", grpcsrv.StepUpAllow, "пол пройден сессией «2»; отказ свежести — у службы после пола"},
		{"KN747-16", kn747BeginRegistration, "1", grpcsrv.StepUpDenyACR, "сессия «1» с истёкшим окном — отказ по уровню на замке до службы"},
	}
	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			required := reg.RequiredACRMin(c.fqn)
			got := grpcsrv.EvaluateStepUp(grpcsrv.StepUpInput{
				PrincipalType: "user", PresentedACR: c.acr, RequiredACR: required,
			})
			if got != c.want {
				t.Errorf("%s: %s сессией уровня %q при поле каталога %q — вердикт %d, ожидался %d (%s)",
					c.id, c.fqn, c.acr, required, got, c.want, c.what)
			}
		})
	}
}

// TestKN747_FloorPredicateCanFail — инъекция с законным близнецом.
func TestKN747_FloorPredicateCanFail(t *testing.T) {
	legal := fakeACRCatalog{kn747Anchor: "2"}
	for _, fqn := range kn747Guarded {
		legal[fqn] = "2"
	}
	if f := levelTwoEnrollmentFindings(legal); len(f) != 0 {
		t.Fatalf("законное решение объявлено находкой: %v", f)
	}
	clone := func() fakeACRCatalog {
		c := fakeACRCatalog{}
		for k, v := range legal {
			c[k] = v
		}
		return c
	}
	for _, fqn := range kn747Guarded {
		t.Run("пол «1» у "+fqn, func(t *testing.T) {
			bad := clone()
			bad[fqn] = "1"
			// одна находка «ниже «2»» и одна «ниже якоря»
			if f := levelTwoEnrollmentFindings(bad); len(f) != 2 {
				t.Fatalf("ожидалось 2 находки, получено %d: %v", len(f), f)
			}
		})
	}
	t.Run("якорь поднят до «3» — отношение, а не литерал", func(t *testing.T) {
		bad := clone()
		bad[kn747Anchor] = "3"
		if f := levelTwoEnrollmentFindings(bad); len(f) != len(kn747Guarded) {
			t.Fatalf("ожидалось %d находки (по одной на глагол), получено %d: %v", len(kn747Guarded), len(f), f)
		}
	})
	t.Run("якорь без пола", func(t *testing.T) {
		bad := clone()
		bad[kn747Anchor] = ""
		if f := levelTwoEnrollmentFindings(bad); len(f) != 1 {
			t.Fatalf("ожидалась одна находка, получено %d: %v", len(f), f)
		}
	})
}
