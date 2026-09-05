// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// required_settings_injection_test.go — доказательство того, что разбор таблицы
// СПОСОБЕН УПАСТЬ, и что он молчит на законном близнеце.
//
// Разбор, который не роняли, свойства не измеряет: на целом дереве зелёный
// разбор и зелёный МЁРТВЫЙ разбор выглядят одинаково. Здесь ему подаются битые
// таблицы — по одной оси на случай — и требуется красное С КООРДИНАТОЙ; рядом
// стоит законный близнец той же формы, на котором разбор обязан смолчать.
//
// ИНЪЕКЦИЯ РОНЯЕТ ТОЛЬКО ПРОВЕРЯЕМОЕ. Каждый случай меняет ОДИН факт против
// своего положительного близнеца — иначе красное пришло бы от соседней оси, и
// про инъецированную нельзя было бы утверждать ничего.
//
// ФИКСТУРА НЕ ОПИРАЕТСЯ НА ЖИВОЙ ДЕФЕКТ (задача #2040). Несущий случай ниже
// прежде объявлял окружением ключ, у которого окружение НЕ РАБОТАЛО, — и
// доказательство способности падать держалось на том самом дефекте, ради
// которого гейт и стоит. Дефект починен, ключ доехал обоими путями, и случай
// СМОЛЧАЛ: фикстура истекла вместе со своим предметом, унеся доказательство.
// Теперь тот же один факт вносится ИМЕНЕМ переменной, которой не привязано
// ничто и не будет: оно не зависит от того, какие ключи привязаны сегодня.
package config_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/config"
)

// cloneTable — копия действующей таблицы. Инъекция правит копию: правка
// глобальной утекла бы в соседние пробы пакета.
func cloneTable() []config.RequiredSetting {
	out := make([]config.RequiredSetting, len(config.RequiredSettings))
	copy(out, config.RequiredSettings)
	return out
}

// dropKey убирает строку по координате.
func dropKey(table []config.RequiredSetting, key string) []config.RequiredSetting {
	out := make([]config.RequiredSetting, 0, len(table))
	for _, s := range table {
		if s.Key != key {
			out = append(out, s)
		}
	}
	return out
}

// mutate правит одну строку по координате.
func mutate(table []config.RequiredSetting, key string, f func(*config.RequiredSetting)) []config.RequiredSetting {
	out := cloneOf(table)
	for i := range out {
		if out[i].Key == key {
			f(&out[i])
		}
	}
	return out
}

func cloneOf(table []config.RequiredSetting) []config.RequiredSetting {
	out := make([]config.RequiredSetting, len(table))
	copy(out, table)
	return out
}

func TestRequiredSettingsAudit_CanFailAndStaysSilent(t *testing.T) {
	cases := []struct {
		name string
		// table — подаваемая разбору таблица.
		table []config.RequiredSetting
		// wantFinding — ожидается ли находка.
		wantFinding bool
		// coordinate — что находка обязана назвать. Пусто — координата не
		// проверяется (для законного близнеца).
		coordinate string
		// why — что именно доказывает случай.
		why string
	}{
		{
			name:        "законный близнец: действующая таблица",
			table:       cloneTable(),
			wantFinding: false,
			why: "положительный контроль. Без него всякое красное ниже могло бы приходить " +
				"от самого разбора, а не от инъекции",
		},
		{
			name: "строка, которой страж НЕ требует",
			table: append(cloneTable(), config.RequiredSetting{
				Key:     "authn.nonexistent-knob",
				Env:     "KACHO_IAM_AUTHN__NONEXISTENT_KNOB",
				Supply:  config.SupplyEnv,
				Sample:  "value",
				Why:     "выдуманное требование",
				Refusal: "authn.nonexistent-knob",
			}),
			wantFinding: true,
			coordinate:  "authn.nonexistent-knob",
			why: "документ потребовал бы от оператора величину, без которой служба поднимается. " +
				"Ловится Т1: снятая величина обязана ронять старт",
		},
		{
			name:        "снятая строка: страж требует, таблица молчит",
			table:       dropKey(cloneTable(), "authn.hook-shared-secret"),
			wantFinding: true,
			coordinate:  "authn.hook-shared-secret",
			why: "документ не назвал бы обязательную величину, и оператор упёрся бы в неё на стенде. " +
				"Ловится Т3: отказ пустого профиля, не принадлежащий ни одной строке",
		},
		{
			name: "путь подачи объявлен ОКРУЖЕНИЕМ, а названная переменная до поля НЕ ДОЕЗЖАЕТ",
			table: mutate(cloneTable(), "authn.trusted-forwarder-sans", func(s *config.RequiredSetting) {
				s.Supply = config.SupplyEnv
				s.Env = "KACHO_IAM_AUTHN__TRUSTED_FORWARDER_SANS_THAT_NOBODY_BINDS"
			}),
			wantFinding: true,
			coordinate:  "authn.trusted-forwarder-sans",
			why: "НЕСУЩИЙ случай этого файла: документ назвал бы способ задать величину, её не задающий, " +
				"и оператор ходил бы по кругу, выполняя ровно то, что говорит текст отказа. " +
				"Ловится Т2: полный профиль перестаёт проходить стража",
		},
		{
			name: "путь подачи объявлен ФАЙЛОМ там, где работает и окружение",
			table: mutate(cloneTable(), "authn.hook-shared-secret", func(s *config.RequiredSetting) {
				s.Supply = config.SupplyFile
			}),
			wantFinding: false,
			why: "ГРАНИЦА, названная честно, и она АСИММЕТРИЧНА — как асимметричен риск.\n" +
				"Разбор утверждает «объявленный путь РАБОТАЕТ», а не «объявленный путь ЕДИНСТВЕННЫЙ». " +
				"Этот ключ доезжает обоими путями, поэтому объявление файлового находки не даёт: " +
				"профиль собирается и стража проходит.\n" +
				"Почему это верная граница, а не пропуск. Опасное направление — объявить ОКРУЖЕНИЕ там, " +
				"где оно не работает: оператор выполняет ровно то, что сказано, и получает тот же отказ " +
				"снова (случай выше, он краснеет). Обратное направление стоит оператору лишней строки " +
				"в файле настроек и ничего не ломает.\n" +
				"Случай стоит здесь, чтобы область разбора не выводил читатель: ожидание «покраснеет» " +
				"было моим, и его опроверг прогон",
		},
		{
			name: "безусловная строка объявлена условной",
			table: mutate(cloneTable(), "authn.hydra-jwks-url", func(s *config.RequiredSetting) {
				s.Conditional = true
			}),
			wantFinding: false,
			why: "ГРАНИЦА, названная честно: пометка «условная» из обратного направления Т3 строку " +
				"исключает, поэтому лишняя пометка находки НЕ даёт. Ловит такое Т1 только если строка " +
				"перестала быть настоящей; здесь она настоящая. Случай стоит здесь, чтобы область разбора " +
				"не выводил читатель",
		},
		{
			name:        "пустая таблица",
			table:       nil,
			wantFinding: true,
			coordinate:  "пуста",
			why:         "порождённый перечень был бы пуст, а документ — зелен: «ноль находок» против «ноль прочитанного»",
		},
		{
			name: "строка без объяснения",
			table: mutate(cloneTable(), "authn.jwks-encryption-key-hex", func(s *config.RequiredSetting) {
				s.Why = ""
			}),
			wantFinding: true,
			coordinate:  "authn.jwks-encryption-key-hex",
			why:         "порождённая таблица получила бы пустую клетку, и оператор прочёл бы её как «здесь ничего не нужно»",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings, census := auditRequiredSettings(t.TempDir(), tc.table)

			switch {
			case tc.wantFinding && len(findings) == 0:
				t.Fatalf("разбор смолчал на инъекции — он НЕ СПОСОБЕН упасть по этой оси.\n"+
					"Что должно было ловиться: %s\nперепись: %s", tc.why, census)
			case !tc.wantFinding && len(findings) != 0:
				t.Fatalf("разбор нашёл на законной таблице то, чего в ней нет — первое же ложное срабатывание "+
					"снимает гейт целиком.\nПочему случай законен: %s\nнаходки:\n  %s",
					tc.why, strings.Join(findings, "\n  "))
			}

			if tc.wantFinding && tc.coordinate != "" {
				named := false
				for _, f := range findings {
					if strings.Contains(f, tc.coordinate) {
						named = true
						break
					}
				}
				if !named {
					t.Fatalf("находка есть, а КООРДИНАТЫ %q в ней нет — читатель пойдёт чинить не туда.\n"+
						"находки:\n  %s", tc.coordinate, strings.Join(findings, "\n  "))
				}
			}

			t.Logf("находок %d · %s", len(findings), census)
		})
	}
}
