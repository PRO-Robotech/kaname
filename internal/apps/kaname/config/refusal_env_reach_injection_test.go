// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// refusal_env_reach_injection_test.go — доказательство того, что гейт «названная
// отказом переменная доезжает до поля» СПОСОБЕН УПАСТЬ и молчит на законном
// близнеце.
//
// Разбор, который не роняли, свойства не измеряет: на целом дереве зелёный
// разбор и зелёный МЁРТВЫЙ разбор выглядят одинаково. Здесь разбору подаётся
// подставной мир — по одной оси на случай, — и требуется красное С ИМЕНЕМ
// переменной; рядом стоит законный близнец той же формы, на котором разбор
// обязан смолчать.
//
// ИНЪЕКЦИЯ РОНЯЕТ ТОЛЬКО ПРОВЕРЯЕМОЕ. Каждый случай меняет ОДИН факт против
// своего близнеца: «названа и инертна» против «названа и доезжает» отличаются
// исходом опыта и НИЧЕМ больше; «названа отказом» против «названа не отказом» —
// только тем, в какой текст попало имя.
//
// ФИКСТУРЫ ЗДЕСЬ СИНТЕТИЧЕСКИЕ И НЕ ЗАВИСЯТ ОТ ЖИВОГО ДЕРЕВА — намеренно.
// Инъекция, опирающаяся на живой дефект, истекает вместе с его починкой и уносит
// доказательство (ровно это случилось в соседнем файле, см. его шапку). Имена
// вида `KANAME_INJECTED__*` не привязаны ничем и не будут привязаны никогда.
//
// ЧЕГО ЭТОТ ФАЙЛ НЕ ДОКАЗЫВАЕТ: что предметом гейта служат отказы ЖИВОГО стража,
// а не текст исходников. Подставной мир об этом не утверждает ничего by
// construction — он и есть подстановка. Половину эту держит проба живого мира
// `TestRefusalEnvGate_SaysNothingAboutNamesMentionedOnlyInProse`.
package config_test

import (
	"strings"
	"testing"
)

const (
	injectedInert  = "KANAME_INJECTED__INERT_KNOB"
	injectedLive   = "KANAME_INJECTED__LIVE_KNOB"
	injectedInProf = "KANAME_INJECTED__NAMED_OUTSIDE_A_REFUSAL"
)

// staticWorld — подставной мир: заданные тексты отказов и заданный исход опыта.
func staticWorld(texts map[string][]string, reaching map[string]bool) refusalWorld {
	return refusalWorld{
		Refusals: func(prof refusalProfile) []string { return texts[prof.Name] },
		Reaches: func(_ refusalProfile, env string) (bool, string) {
			if reaching[env] {
				return true, "подставной мир: значение изменило исход"
			}
			return false, "подставной мир: исход не изменился ни на одном значении"
		},
	}
}

func TestRefusalEnvAudit_CanFailAndStaysSilent(t *testing.T) {
	// Положительный близнец всех случаев ниже: один профиль, один отказ,
	// названная им переменная доезжает.
	twinProfiles := []refusalProfile{{Name: "подставной профиль"}}
	twinTexts := map[string][]string{
		"подставной профиль": {
			"production mode: authn.injected-knob is not declared (env " + injectedLive + ")",
		},
	}
	twinReaching := map[string]bool{injectedLive: true}

	cases := []struct {
		name        string
		profiles    []refusalProfile
		texts       map[string][]string
		reaching    map[string]bool
		wantFinding bool
		// mustName — что находка обязана назвать. Пусто — не проверяется.
		mustName string
		why      string
	}{
		{
			name:        "законный близнец: названа отказом и доезжает",
			profiles:    twinProfiles,
			texts:       twinTexts,
			reaching:    twinReaching,
			wantFinding: false,
			why: "положительный контроль. Без него всякое красное ниже могло бы приходить " +
				"от самого разбора, а не от инъекции",
		},
		{
			name:     "названа отказом и ДО ПОЛЯ НЕ ДОЕЗЖАЕТ",
			profiles: twinProfiles,
			texts: map[string][]string{
				"подставной профиль": {
					"production mode: authn.injected-knob is not declared (env " + injectedInert + ")",
				},
			},
			reaching:    map[string]bool{}, // один факт против близнеца: исход опыта
			wantFinding: true,
			mustName:    injectedInert,
			why: "НЕСУЩИЙ случай: оператор делает ровно то, что говорит отказ, и получает тот же " +
				"отказ. Находка обязана назвать переменную — иначе читатель пойдёт чинить не туда",
		},
		{
			name:     "имя стоит НЕ В ОТКАЗЕ, а рядом — разбор о нём молчит",
			profiles: []refusalProfile{{Name: "профиль про " + injectedInProf}},
			texts: map[string][]string{
				"профиль про " + injectedInProf: {
					"production mode: authn.injected-knob is not declared (env " + injectedLive + ")",
				},
			},
			reaching:    twinReaching,
			wantFinding: false,
			why: "ОБЛАСТЬ: предмет гейта — то, что названо ОТКАЗОМ, а не всякая строка, попавшая " +
				"разбору на глаза. Инертное имя здесь стоит в имени профиля, и разбор его не судит. " +
				"Разбор, судящий любой поданный текст, объявил бы находкой шесть десятков имён, " +
				"читаемых другими механизмами, — и его отключили бы первым",
		},
		{
			name:        "профилей не дали вовсе",
			profiles:    nil,
			texts:       twinTexts,
			reaching:    twinReaching,
			wantFinding: true,
			mustName:    "обход пуст",
			why: "«ноль находок» обязано быть отличимо от «ноль прочитанного»: разбор, которому " +
				"не дали профилей, о дереве не утверждает ничего и зелёным быть не вправе",
		},
		{
			name:        "страж не отказал ни на одном профиле",
			profiles:    twinProfiles,
			texts:       map[string][]string{},
			reaching:    twinReaching,
			wantFinding: true,
			mustName:    "обход пуст",
			why: "профиль есть, отказов нет — предмета у разбора нет. Молчание здесь читалось бы " +
				"как «всё сходится», а сошлось ничто",
		},
		{
			name:     "отказы есть, но ни один не назвал переменной",
			profiles: twinProfiles,
			texts: map[string][]string{
				"подставной профиль": {"production mode: authn.injected-knob is not declared"},
			},
			reaching:    twinReaching,
			wantFinding: true,
			mustName:    "обход пуст",
			why: "предпосылка гейта — что отказы называют переменные. Перестали называть — гейт " +
				"измеряет пустоту, и сказать об этом обязан он сам, а не следующий читатель",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings, census := auditRefusalNamedEnv(tc.profiles, staticWorld(tc.texts, tc.reaching))

			switch {
			case tc.wantFinding && len(findings) == 0:
				t.Fatalf("разбор смолчал на инъекции — он НЕ СПОСОБЕН упасть по этой оси.\n"+
					"Что должно было ловиться: %s\nперепись: %s", tc.why, census)
			case !tc.wantFinding && len(findings) != 0:
				t.Fatalf("разбор нашёл на законном близнеце то, чего в нём нет — первое же ложное "+
					"срабатывание снимает гейт целиком.\nПочему случай законен: %s\nнаходки:\n  %s",
					tc.why, strings.Join(findings, "\n  "))
			}

			if tc.wantFinding && tc.mustName != "" {
				named := false
				for _, f := range findings {
					if strings.Contains(f, tc.mustName) {
						named = true
						break
					}
				}
				if !named {
					t.Fatalf("находка есть, а %q в ней не названо — читатель пойдёт чинить не туда.\n"+
						"находки:\n  %s", tc.mustName, strings.Join(findings, "\n  "))
				}
			}

			t.Logf("находок %d · %s", len(findings), census)
		})
	}
}
