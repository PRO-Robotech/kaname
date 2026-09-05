// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// posture_env_reach_injection_test.go — способность гейта самоотчёта упасть и
// СМОЛЧАТЬ, по каждой оси отдельно и с законным близнецом.
//
// Инъекция подменяет МИР (исходник и опыт досягаемости), а не разбор: разбор,
// обращающийся к `*testing.T`, инъекции не поддаётся, и его «зелёное» ничего не
// доказывало бы.

import (
	"strings"
	"testing"
)

// reachAll — опыт, на котором доезжает всё. С ним красное может прийти ТОЛЬКО
// от разбора, а не от неполноты подставного мира.
func reachAll(string) (bool, string) { return true, "подставной мир: доезжает" }

// reachNothing — опыт, на котором не доезжает ничто.
func reachNothing(string) (bool, string) { return false, "подставной мир: инертна" }

// axisAt — ось с готовым текстом.
func axisAt(text string) axisText { return axisText{File: "injected.go", Line: 1, Text: text} }

func TestPostureEnvGate_CanFailAndStaysSilent(t *testing.T) {
	live := axisAt("KACHO_IAM_API_SERVER__METRICS_ENDPOINT не задан профилем: скрейпа нет")
	dead := axisAt("KACHO_IAM_METRICS_ADDR не задан профилем: скрейпа нет")
	mute := axisAt("снята осознанно: на проводе только счётчики процесса")

	cases := []struct {
		name    string
		files   int
		axes    []axisText
		reaches func(string) (bool, string)
		want    string
		why     string
	}{
		{
			name:  "законный близнец: названное доезжает",
			files: 1, axes: []axisText{live}, reaches: reachAll,
			why: "положительный контроль: без него всякое красное ниже могло бы приходить от самого разбора",
		},
		{
			name:  "названное не доезжает",
			files: 1, axes: []axisText{dead}, reaches: reachNothing,
			want: "KACHO_IAM_METRICS_ADDR названа текстом самоотчёта об оси",
			why:  "ровно предмет #2042: оператор задаёт названное и не меняет ничего",
		},
		{
			name:  "находка называет ИМЯ и КООРДИНАТУ",
			files: 1, axes: []axisText{{File: "serve.go", Line: 920, Text: dead.Text}}, reaches: reachNothing,
			want: "serve.go:920",
			why:  "находка, называющая симптом без координаты, посылает читателя искать глазами",
		},
		{
			name:  "ось без имени переменной — не находка",
			files: 1, axes: []axisText{mute, live}, reaches: reachAll,
			why: "не всякая ось обязана называть ручку: у снятой осознанно её нет вовсе, " +
				"и краснеть на ней значило бы требовать имени там, где предмета нет",
		},
		{
			name:  "исходников не прочитано ни одного",
			files: 0, axes: nil, reaches: reachAll,
			want: "обход пуст: исходников композиционного корня прочитано 0",
			why:  "«находок 0» обязано быть отличимо от «прочитано 0»",
		},
		{
			name:  "файлы есть, осей нет",
			files: 32, axes: nil, reaches: reachAll,
			want: "ни одна ось самоотчёта не объявлена текстом",
			why:  "разбор, потерявший форму объявления оси, зеленел бы на любом дереве",
		},
		{
			name:  "оси есть, имён нет",
			files: 32, axes: []axisText{mute}, reaches: reachAll,
			want: "ни одна ось не назвала переменной окружения",
			why:  "самоотчёт, переставший называть ручку, оставляет оператора без следующего шага",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings, census := auditPostureNamedEnv(tc.files, tc.axes, tc.reaches)
			if tc.want == "" {
				if len(findings) != 0 {
					t.Fatalf("разбор нашёл на законном близнеце то, чего в нём нет — первое же ложное "+
						"срабатывание снимает гейт.\nперепись: %s\nнаходки:\n  %s",
						census, strings.Join(findings, "\n  "))
				}
				return
			}
			if len(findings) == 0 {
				t.Fatalf("разбор смолчал на инъекции — он НЕ способен упасть по этой оси.\n"+
					"что должно было ловиться: %s\nперепись: %s", tc.why, census)
			}
			if !strings.Contains(strings.Join(findings, "\n"), tc.want) {
				t.Fatalf("разбор покраснел не на том: ждали %q\nнаходки:\n  %s",
					tc.want, strings.Join(findings, "\n  "))
			}
		})
	}
}

// TestPostureAxisReader_JudgesTheNodeNotTheText — распознаватель осей судит УЗЕЛ
// разбора, а не подстроку.
//
// Половина эта несущая: имя переменной встречается в комментариях, в отказах
// стража и в шапках функций. Разбор по тексту объявил бы осью каждое такое
// место — и гейт выдал бы десятки находок, из которых верны единицы.
func TestPostureAxisReader_JudgesTheNodeNotTheText(t *testing.T) {
	const src = `package main

import "example.test/servicecontract"

// Комментарий называет KACHO_IAM_COMMENT_ONLY и осью не является.
func build(addr string) {
	// Ось первая: текст стоит аргументом.
	_ = addrAxis(addr, "KACHO_IAM_AXIS_ONE не задан профилем развёртывания")
	// Ось вторая: текст склеен из двух литералов — форма законная и обычная.
	_ = servicecontract.NotApplicable[string]("KACHO_IAM_AXIS_TWO " +
		"не задан профилем развёртывания")
	// Не ось: аргумент не константа. Это механизм передачи, а не место самоотчёта.
	_ = servicecontract.NotApplicable[string](reason())
	// Не ось: отказ. У него свой производитель и свой гейт.
	_ = refuse("задайте KACHO_IAM_REFUSAL_ONLY=true")
}

func reason() string { return "KACHO_IAM_INDIRECT" }
func refuse(s string) error { return nil }
`
	axes, err := postureAxisTexts("injected.go", []byte(src))
	if err != nil {
		t.Fatalf("инъекция не разобрана: %v", err)
	}
	if len(axes) != 2 {
		t.Fatalf("осей с текстом найдено %d, ждали 2 (аргумент addrAxis и склейка у NotApplicable):\n%v",
			len(axes), axes)
	}

	_, census := auditPostureNamedEnv(1, axes, reachAll)
	got := strings.Join(census.NamedList, ",")
	if got != "KACHO_IAM_AXIS_ONE,KACHO_IAM_AXIS_TWO" {
		t.Fatalf("перечень названных осями = %q; ждали ровно два имени осей.\n"+
			"имя из комментария, из отказа и из непрямого аргумента предметом гейта не являются", got)
	}
}
