// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

// login_verifier_containment_injection_test.go — способность гейта
// `TestLoginVerifierStaysInside` упасть и смолчать.
//
// Каждая сцена — синтетический корпус, отличающийся от законного ОДНИМ фактом.
// Законный корпус сам по себе — положительный контроль: на нём гейт молчит, и
// значит красное в сцене принадлежит внесённому факту, а не корпусу.

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// lawfulLoginVerifierCorpus — минимальное законное дерево: объявление выхода,
// адаптер, пользующийся им и называющий таблицу, и сосед, не делающий ни того,
// ни другого.
func lawfulLoginVerifierCorpus() check.TreeCorpus {
	return check.TreeCorpus{
		"internal/domain/login_method.go": `package domain

type LoginVerifier struct{ box *box }
type box struct{ material string }

// Reveal — единственный выход. Слово "Reveal" в комментарии и в строке не есть обращение.
func (v LoginVerifier) Reveal() string { return v.box.material }

func (v LoginVerifier) String() string { return "Reveal is not called here" }
`,
		"internal/repo/kaname/pg/login_method_repo.go": `package pg

const loginMethodsTable = "user_login_methods"

func write(v interface{ Reveal() string }) string {
	return "INSERT INTO user_login_methods (verifier) VALUES ('" + v.Reveal() + "')"
}
`,
		"internal/repo/kaname/pg/pgmaperr.go": `package pg

func texts(c string) bool {
	return c == "user_login_methods_pkey" || c == "user_login_methods_user_fk"
}
`,
		"internal/dto/toproto/user.go": `package toproto

func noop() {}
`,
	}
}

func auditInjected(t *testing.T, corpus check.TreeCorpus) ([]string, check.LoginVerifierCensus, error) {
	t.Helper()
	return check.AuditLoginVerifierContainment(corpus, loginVerifierSpec())
}

func TestLoginVerifierGate_LawfulCorpusIsSilent(t *testing.T) {
	findings, census, err := auditInjected(t, lawfulLoginVerifierCorpus())
	require.NoError(t, err)
	t.Log(census)
	require.Empty(t, findings, "законный корпус обязан молчать — иначе красное в сценах ниже ничего не доказывает")
	require.Equal(t, 1, census.AccessorDecls)
	require.Equal(t, 1, census.AllowedUses["internal/repo/kaname/pg"])
	require.Equal(t, 2, census.OwnerTableLiterals, "константа и оператор у владельца — два литерала")
	require.Equal(t, 2, census.TableLiterals, "имена ограничений (`…_pkey`) таблицей не считаются")
}

func TestLoginVerifierGate_Injection(t *testing.T) {
	type scene struct {
		name string
		edit func(check.TreeCorpus)
		// wantFinding — подстрока, которая обязана стоять в находке; пусто —
		// сцена законна и гейт обязан смолчать.
		wantFinding string
		// wantPremise — подстрока отказа премисы.
		wantPremise string
	}
	scenes := []scene{
		{
			name: "вызов выхода в слое контракта",
			edit: func(c check.TreeCorpus) {
				c["internal/dto/toproto/user.go"] = `package toproto

func leak(v interface{ Reveal() string }) string { return v.Reveal() }
`
			},
			wantFinding: "internal/dto/toproto/user.go:3: материал способа входа выведен",
		},
		{
			name: "значение метода без вызова — та же форма",
			edit: func(c check.TreeCorpus) {
				c["internal/apps/kaname/api/audit/payload.go"] = `package audit

func leak(v interface{ Reveal() string }) func() string { return v.Reveal }
`
			},
			wantFinding: "internal/apps/kaname/api/audit/payload.go:3",
		},
		{
			name: "второй читатель колонки мимо адаптера",
			edit: func(c check.TreeCorpus) {
				c["internal/handler/login.go"] = "package handler\n\nconst q = `SELECT verifier FROM kaname.user_login_methods WHERE user_id = $1`\n"
			},
			wantFinding: "internal/handler/login.go:3: таблица секрета",
		},
		{
			name: "законный близнец: имя ограничения таблицы вне адаптера",
			edit: func(c check.TreeCorpus) {
				c["internal/dto/toproto/user.go"] = `package toproto

var names = []string{"user_login_methods_pkey", "user_login_methods_kind_check"}
`
			},
		},
		{
			name: "законный близнец: выход назван в комментарии и строке",
			edit: func(c check.TreeCorpus) {
				c["internal/dto/toproto/user.go"] = `package toproto

// Reveal здесь не зовётся: материал в контракт не попадает.
var doc = "v.Reveal() запрещён в этом слое"
`
			},
		},
		{
			name: "разрешение без предмета истекает",
			edit: func(c check.TreeCorpus) {
				c["internal/repo/kaname/pg/login_method_repo.go"] = `package pg

const loginMethodsTable = "user_login_methods"
`
			},
			wantFinding: "разрешение пакету internal/repo/kaname/pg",
		},
		{
			name: "премиса: выход объявлен дважды",
			edit: func(c check.TreeCorpus) {
				c["internal/clients/other.go"] = `package clients

type T struct{}

func (T) Reveal() string { return "" }
`
			},
			wantPremise: "объявлен 2 раз",
		},
		{
			name: "премиса: выход объявлен не на том типе",
			edit: func(c check.TreeCorpus) {
				c["internal/domain/login_method.go"] = strings.ReplaceAll(
					c["internal/domain/login_method.go"], "func (v LoginVerifier) Reveal", "func (v Other) Reveal")
			},
			wantPremise: "объявлен не там",
		},
		{
			name: "премиса: владелец таблицы её не называет",
			edit: func(c check.TreeCorpus) {
				c["internal/repo/kaname/pg/login_method_repo.go"] = `package pg

func write(v interface{ Reveal() string }) string { return v.Reveal() }
`
			},
			wantPremise: "правило второго читателя ослепло",
		},
	}
	for _, sc := range scenes {
		t.Run(sc.name, func(t *testing.T) {
			corpus := lawfulLoginVerifierCorpus()
			sc.edit(corpus)
			findings, census, err := auditInjected(t, corpus)
			t.Log(census)
			switch {
			case sc.wantPremise != "":
				require.Error(t, err, "премиса обязана отказать, а не смолчать")
				require.Contains(t, err.Error(), sc.wantPremise)
			case sc.wantFinding != "":
				require.NoError(t, err)
				require.NotEmpty(t, findings, "внесённый дефект обязан быть найден")
				require.Contains(t, strings.Join(findings, "\n"), sc.wantFinding, "находка обязана называть координату")
			default:
				require.NoError(t, err)
				require.Empty(t, findings, "законный близнец обязан молчать")
			}
		})
	}
}

// TestLoginVerifierGate_EmptyCorpusIsNotClean — пустой обход не зелёный.
func TestLoginVerifierGate_EmptyCorpusIsNotClean(t *testing.T) {
	_, _, err := auditInjected(t, check.TreeCorpus{})
	require.ErrorIs(t, err, check.ErrEmptyTraversal)
}
