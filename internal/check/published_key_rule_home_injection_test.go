// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// published_key_rule_home_injection_test.go — доказательство способности
// гейта упасть И смолчать.
//
// Инъекция подаёт настоящий вход — тот, из которого гейт и выведен: до
// сведения (задача PRO-Robotech/kaname#396) выбор ключа из публикуемого набора
// был написан ТРИ раза — читатель предъявленного, интроспекция и опознание
// токена доступа церемонии, — и каждая копия звала правило критичных
// параметров сама. Законные близнецы — дом правила и упоминание имени в
// тексте.
package check_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// publishedKeyRuleInjectionSrc — выбор ключа своей рукой: форма, которой были
// три копии до сведения.
const publishedKeyRuleInjectionSrc = `package reader

import (
	"github.com/golang-jwt/jwt/v5"

	"github.com/PRO-Robotech/corelib/tokenpolicy"
)

func keyfunc(t *jwt.Token) (any, error) {
	if ok, _ := tokenpolicy.CriticalHeadersUnderstood(critHeaders(t.Header)); !ok {
		return nil, errNotOurs
	}
	return lookup(t)
}
`

// publishedKeyRuleTwinSrc — законный близнец: имя правила названо в
// комментарии и в строке, а обращения нет. Гейт судит узел разбора, а не
// подстроку.
const publishedKeyRuleTwinSrc = `package reader

import "github.com/PRO-Robotech/corelib/tokenpolicy"

// Выбор ключа — publishedkey.Parse; tokenpolicy.CriticalHeadersUnderstood здесь только назван.
const why = "tokenpolicy.CriticalHeadersUnderstood живёт в доме правила"

var _ = tokenpolicy.ClockSkew
`

// TestPublishedKeyRuleGateRedsOnASecondCopy — инъекция обязана краснеть И
// называть координату и предмет.
func TestPublishedKeyRuleGateRedsOnASecondCopy(t *testing.T) {
	const rel = "internal/presentedcred/reader.go"
	sites, census, err := check.ScanCriticalHeaderRule(rel, []byte(publishedKeyRuleInjectionSrc))
	if err != nil {
		t.Fatalf("разбор инъекции: %v", err)
	}
	if census.Selectors == 0 || census.PolicyImports != 1 {
		t.Fatalf("перепись инъекции неполна — разбор ничего не прочитал: %+v", census)
	}
	findings := publishedKeyRuleFindings(sites, publishedKeyRuleHome)
	if len(findings) != 1 {
		t.Fatalf("вторая копия выбора ключа НЕ стала находкой: находок %d при переписи %+v", len(findings), census)
	}
	for _, want := range []string{rel + ":10", check.CriticalHeaderRuleFunc} {
		if !strings.Contains(findings[0], want) {
			t.Errorf("находка не называет %q: %q", want, findings[0])
		}
	}
}

// TestPublishedKeyRuleGateStaysSilentOnLegalTwins — законные близнецы, каждый
// своей осью.
func TestPublishedKeyRuleGateStaysSilentOnLegalTwins(t *testing.T) {
	t.Run("имя названо в тексте, обращения нет", func(t *testing.T) {
		sites, census, err := check.ScanCriticalHeaderRule("internal/presentedcred/reader.go",
			[]byte(publishedKeyRuleTwinSrc))
		if err != nil {
			t.Fatalf("разбор близнеца: %v", err)
		}
		if census.Selectors == 0 {
			t.Fatalf("близнец несёт выражение выбора (tokenpolicy.ClockSkew), а перепись его не прочла: %+v", census)
		}
		if f := publishedKeyRuleFindings(sites, publishedKeyRuleHome); len(f) != 0 {
			t.Fatalf("гейт судит подстроку, а не узел разбора: %v", f)
		}
	})

	t.Run("то же обращение в пробе", func(t *testing.T) {
		if publishedKeyRuleWalkable("internal/presentedcred/reader_test.go") {
			t.Fatal("отбор гейта берёт пробу — законная сверка правила в пробе стала бы находкой")
		}
		if !publishedKeyRuleWalkable("internal/presentedcred/reader.go") {
			t.Fatal("отбор гейта не берёт прод-файл — тогда осматривать нечего")
		}
	})

	t.Run("сам дом правила", func(t *testing.T) {
		const home = publishedKeyRuleHome + "rule.go"
		sites, _, err := check.ScanCriticalHeaderRule(home, []byte(publishedKeyRuleInjectionSrc))
		if err != nil {
			t.Fatalf("разбор дома: %v", err)
		}
		if len(sites) != 1 {
			t.Fatalf("обращение в доме не опознано (%d) — предпосылка «дом существует» не проверяема", len(sites))
		}
		if f := publishedKeyRuleFindings(sites, publishedKeyRuleHome); len(f) != 0 {
			t.Fatalf("единственный дом объявлен находкой: %v", f)
		}
	})

	t.Run("одноимённый метод и поле чужого типа при точечном импорте", func(t *testing.T) {
		const src = `package p

import . "github.com/PRO-Robotech/corelib/tokenpolicy"

var _ = ClockSkew

type policy struct{ CriticalHeadersUnderstood bool }

func (policy) CriticalHeadersUnderstood([]string) (bool, string) { return true, "" }

func f(p policy) { _, _ = p.CriticalHeadersUnderstood(nil) }
`
		sites, _, err := check.ScanCriticalHeaderRule("internal/x/p.go", []byte(src))
		if err != nil {
			t.Fatalf("разбор: %v", err)
		}
		if len(sites) != 0 {
			t.Fatalf("метод либо поле чужого типа приняты за правило платформы: %v", sites)
		}
	})
}

// TestCriticalHeaderRuleScannerKnowsEveryForm — распознаватель знает ВСЕ
// законные формы обращения: вызов и значение функции, через обычный импорт,
// псевдоним и точечный импорт. Незнакомая форма дала бы МОЛЧАНИЕ.
func TestCriticalHeaderRuleScannerKnowsEveryForm(t *testing.T) {
	const src = `package p

import (
	"github.com/PRO-Robotech/corelib/tokenpolicy"
	tp "github.com/PRO-Robotech/corelib/tokenpolicy"
	. "github.com/PRO-Robotech/corelib/tokenpolicy"
	_ "github.com/PRO-Robotech/corelib/tokenpolicy"
)

func a() { _, _ = tokenpolicy.CriticalHeadersUnderstood(nil) }

var b = tp.CriticalHeadersUnderstood

func c() { _, _ = CriticalHeadersUnderstood(nil) }
`
	sites, census, err := check.ScanCriticalHeaderRule("internal/x/a.go", []byte(src))
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if census.PolicyImports != 4 {
		t.Fatalf("прочитано %d импортов правила из четырёх", census.PolicyImports)
	}
	got := map[string]int{}
	for _, s := range sites {
		got[s.Form]++
	}
	for form, want := range map[string]int{"plain": 1, "alias": 1, "dot": 1} {
		if got[form] != want {
			t.Errorf("форма %q опознана %d раз(а), ожидается %d: %v", form, got[form], want, sites)
		}
	}
	if len(sites) != 3 {
		t.Errorf("опознано %d обращений из трёх: %v", len(sites), sites)
	}
}
