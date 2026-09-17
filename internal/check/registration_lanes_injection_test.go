// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// registration_lanes_injection_test.go — доказательство способности гейта полос
// регистрации упасть И смолчать (Ф4-07, Ф4-08, Ф4-09; «Дано» Ф4-10 —
// синтетическое дерево БЕЗ прежнего объявления).
//
// Инъекция герметична: синтетический исходник подаётся прямо в разбор, и потому
// роняет ТОЛЬКО проверяемое. Оси — по одной на каждую форму записи полосы
// (ключевая · позиционная · литерал · константа · преобразование типа), плюс
// границы, на которых гейт обязан молчать.
package check_test

import (
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

const injectionSessionValue = "session"

// declarationWith — файл объявления с данным телом перечня.
func declarationWith(body string) string {
	return `package registration

type Consequence string

const (
	ConsequenceMirror  Consequence = "mirror"
	ConsequenceAddress Consequence = "address"
	ConsequenceSession Consequence = "session"
)

const (
	LanePassword = "password"
	LanePasskey  = "passkey"
)

type Lane struct {
	Name         string
	Consequences []Consequence
}

var Lanes = []Lane{
` + body + `}
`
}

func scanLanesInjection(t *testing.T, src string) ([]check.RegistrationLane, check.RegistrationLanesCensus) {
	t.Helper()
	lanes, census, err := check.ScanRegistrationLanes(check.RegistrationLanesFileRel, []byte(src), injectionSessionValue)
	if err != nil {
		t.Fatalf("разбор инъекции: %v", err)
	}
	if census.Declarations != 1 {
		t.Fatalf("объявление инъекции не найдено: %+v", census)
	}
	return lanes, census
}

// TestRegistrationLanesGateRedsOnALaneWithoutASession — Ф4-07: полоса без выдачи
// сессии — красное С ИМЕНЕМ, по каждой форме записи.
func TestRegistrationLanesGateRedsOnALaneWithoutASession(t *testing.T) {
	t.Parallel()
	cases := []struct{ name, body, lane string }{
		{"ключевая форма, константы",
			`	{Name: LanePassword, Consequences: []Consequence{ConsequenceMirror, ConsequenceAddress, ConsequenceSession}},
	{Name: LanePasskey, Consequences: []Consequence{ConsequenceMirror, ConsequenceAddress}},
`, "passkey"},
		{"позиционная форма, литералы",
			`	{"password", []Consequence{"mirror", "address", "session"}},
	{"passkey", []Consequence{"mirror", "address"}},
`, "passkey"},
		{"преобразование типа над литералом",
			`	{Name: "password", Consequences: []Consequence{Consequence("mirror"), Consequence("address")}},
`, "password"},
		{"полоса без единого следствия",
			`	{Name: LanePassword, Consequences: []Consequence{}},
`, "password"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lanes, census := scanLanesInjection(t, declarationWith(tc.body))
			if census.Lanes == 0 {
				t.Fatalf("разбор не прочитал ни одной полосы в форме %q: %+v", tc.name, census)
			}
			var found bool
			for _, l := range lanes {
				if l.Name == tc.lane && !l.IssuesSession {
					found = true
				}
			}
			if !found {
				t.Fatalf("гейт СЛЕП к форме %q: полоса %q без выдачи сессии не найдена (%+v)", tc.name, tc.lane, lanes)
			}
			if census.IssuingSession >= census.Lanes {
				t.Fatalf("перепись не отличает полосу без сессии: полос %d · выдают %d", census.Lanes, census.IssuingSession)
			}
		})
	}
}

// TestRegistrationLanesGateStaysSilentOnTheLawfulTwin — Ф4-08: у всех полос
// выдача сессии на месте — молчание. Без этой пары гейт, краснеющий на чём
// угодно, был бы зелёным доказательством.
func TestRegistrationLanesGateStaysSilentOnTheLawfulTwin(t *testing.T) {
	t.Parallel()
	cases := []struct{ name, body string }{
		{"ключевая форма, константы",
			`	{Name: LanePassword, Consequences: []Consequence{ConsequenceMirror, ConsequenceAddress, ConsequenceSession}},
	{Name: LanePasskey, Consequences: []Consequence{ConsequenceMirror, ConsequenceAddress, ConsequenceSession}},
`},
		{"позиционная форма, литералы",
			`	{"password", []Consequence{"mirror", "address", "session"}},
`},
		{"сессия — не последнее следствие",
			`	{Name: LanePassword, Consequences: []Consequence{ConsequenceSession, ConsequenceMirror, ConsequenceAddress}},
`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lanes, census := scanLanesInjection(t, declarationWith(tc.body))
			if census.Lanes == 0 || census.Lanes != census.IssuingSession {
				t.Fatalf("законный близнец дал находку: полос %d · выдают %d (%+v)", census.Lanes, census.IssuingSession, lanes)
			}
			for _, l := range lanes {
				if l.Name == "" || l.Name[0] == '?' {
					t.Fatalf("имя полосы не разрешилось на законном близнеце: %+v", l)
				}
			}
		})
	}
}

// TestRegistrationLanesGateRefusesOnAnEmptyDeclaration — Ф4-09: пустой разбор —
// отказ, а не успех: перепись даёт ноль полос, и читатель обязан назвать это
// «вердикта нет», а не «находок ноль».
func TestRegistrationLanesGateRefusesOnAnEmptyDeclaration(t *testing.T) {
	t.Parallel()
	lanes, census := scanLanesInjection(t, declarationWith(""))
	if len(lanes) != 0 || census.Lanes != 0 {
		t.Fatalf("пустое объявление прочитано как непустое: %+v", census)
	}
	// Объявление, которого в файле НЕТ вовсе, — та же третья категория.
	_, census, err := check.ScanRegistrationLanes(check.RegistrationLanesFileRel,
		[]byte("package registration\n\ntype Lane struct{ Name string }\n"), injectionSessionValue)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if census.Declarations != 0 || census.Lanes != 0 {
		t.Fatalf("файл без объявления прочитан как объявление: %+v", census)
	}
}

// TestRegistrationLanesGateRedsOnASecondDeclaration — Ф4-06: составной литерал
// полосы вне файла объявления — находка с координатой; законный близнец —
// чтение перечня (`for _, l := range registration.Lanes`) — молчит.
func TestRegistrationLanesGateRedsOnASecondDeclaration(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		src    string
		wantN  int
		wantLn []int
	}{
		{"литерал своего пакета", `package registration

var extra = Lane{Name: "passkey"}
`, 1, []int{3}},
		{"литерал из чужого пакета", `package main

import "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/registration"

var extra = []registration.Lane{{Name: "passkey"}}
`, 1, []int{5}},
		{"законный близнец — чтение перечня", `package main

import "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/registration"

func names() []string {
	var out []string
	for _, l := range registration.Lanes {
		out = append(out, l.Name)
	}
	return out
}
`, 0, nil},
		{"законный близнец — слово в комментарии и в строке", `package main

// Lane{Name: "passkey"} — так выглядит полоса; здесь её нет.
var note = "Lane{Name: \"passkey\"}"
`, 0, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sites, err := check.ScanRegistrationLaneLiterals("internal/apps/kaname/api/registration/other.go", []byte(tc.src))
			if err != nil {
				t.Fatalf("разбор: %v", err)
			}
			if len(sites) != tc.wantN {
				t.Fatalf("литералов полосы найдено %d, ожидалось %d: %v", len(sites), tc.wantN, sites)
			}
			for i, ln := range tc.wantLn {
				if sites[i].Line != ln {
					t.Fatalf("находка обязана называть строку %d, названа %d", ln, sites[i].Line)
				}
			}
		})
	}
}
