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

// lawfulLoginVerifierCorpus — минимальное законное дерево той же ФОРМЫ, что
// настоящее: объявление выхода; адаптер, который зовёт выход аргументом запроса
// и строит запросы константой имени таблицы; переводчик отказов, сверяющий имя
// таблицы из отказа предикатом владельца; сосед, не делающий ничего из этого.
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

type execer interface{ Exec(q string, args ...any) error }

func write(db execer, v interface{ Reveal() string }) error {
	q := "INSERT INTO " + loginMethodsTable + " (verifier) VALUES ($1)"
	return db.Exec(q, v.Reveal())
}

func isLoginMethodsTable(name string) bool { return name == loginMethodsTable }
`,
		"internal/repo/kaname/pg/pgmaperr.go": `package pg

func texts(c, table string) bool {
	return (c == "user_login_methods_pkey" || c == "user_login_methods_user_fk") && isLoginMethodsTable(table)
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
	require.Equal(t, 1, census.OwnerTableLiterals, "у владельца один литерал — объявление константы")
	require.Equal(t, 1, census.TableLiterals, "имена ограничений (`…_pkey`) таблицей не считаются")
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
			// Б2 п.1: разрешение стояло на КАТАЛОГЕ пакета адаптера (70 не-тестовых
			// файлов), а шапка владельца и тело PR обещали «единственное место».
			name: "вызов выхода в соседнем файле того же пакета адаптера",
			edit: func(c check.TreeCorpus) {
				c["internal/repo/kaname/pg/audit_outbox_emitter.go"] = `package pg

func payload(v interface{ Reveal() string }) map[string]string {
	return map[string]string{"verifier": v.Reveal()}
}
`
			},
			wantFinding: "internal/repo/kaname/pg/audit_outbox_emitter.go:4: материал способа входа выведен",
		},
		{
			// Опыт, который ревьюер разобрал только чтением: уведомление из пакета
			// адаптера уносит материал к слушателю мимо таблиц — гейт схемы его не
			// видит by construction, значит держать обязан гейт дерева.
			name: "уведомление с материалом из соседнего файла пакета адаптера",
			edit: func(c check.TreeCorpus) {
				c["internal/repo/kaname/pg/notify.go"] = `package pg

func announce(db execer, v interface{ Reveal() string }) error {
	return db.Exec("SELECT pg_notify('lm_probe', $1)", v.Reveal())
}
`
			},
			wantFinding: "internal/repo/kaname/pg/notify.go:4: материал способа входа выведен",
		},
		{
			// Б2 п.2: распознаватель второго читателя знал только литерал, а владелец
			// строит оба своих запроса КОНСТАНТОЙ — и константа видна всему пакету.
			name: "второй читатель через константу владельца в соседнем файле",
			edit: func(c check.TreeCorpus) {
				c["internal/repo/kaname/pg/login_reader.go"] = "package pg\n\nfunc q() string { return `SELECT verifier FROM ` + loginMethodsTable }\n"
			},
			wantFinding: "internal/repo/kaname/pg/login_reader.go:3: таблица секрета",
		},
		{
			name: "второй читатель через склейку имени из литералов",
			edit: func(c check.TreeCorpus) {
				c["internal/handler/login.go"] = "package handler\n\nconst q = `SELECT verifier FROM kaname.user_login_` + `methods`\n"
			},
			wantFinding: "internal/handler/login.go:3: таблица секрета",
		},
		{
			name: "второй читатель через экспортированную константу в другом пакете",
			edit: func(c check.TreeCorpus) {
				c["internal/repo/kaname/pg/login_method_repo.go"] += "\nconst LoginMethodsTable = loginMethodsTable\n"
				c["internal/handler/login.go"] = `package handler

import "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"

var q = "SELECT verifier FROM " + pg.LoginMethodsTable
`
			},
			wantFinding: "internal/handler/login.go:5: таблица секрета",
		},
		{
			name: "владелец отдаёт имя таблицы наружу функцией",
			edit: func(c check.TreeCorpus) {
				c["internal/repo/kaname/pg/login_method_repo.go"] += "\nfunc loginMethodsTableName() string { return loginMethodsTable }\n"
			},
			wantFinding: "loginMethodsTableName",
		},
		{
			name: "владелец отдаёт материал наружу функцией",
			edit: func(c check.TreeCorpus) {
				c["internal/repo/kaname/pg/login_method_repo.go"] += "\nfunc material(v interface{ Reveal() string }) string { return v.Reveal() }\n"
			},
			wantFinding: "material",
		},
		{
			name: "владелец отдаёт выход наружу переменной пакета",
			edit: func(c check.TreeCorpus) {
				c["internal/repo/kaname/pg/login_method_repo.go"] += "\nvar reveal = func(v interface{ Reveal() string }) string { return v.Reveal() }\n"
			},
			wantFinding: "reveal",
		},
		{
			name: "законный близнец: локальная переменная с именем константы в чужом файле",
			edit: func(c check.TreeCorpus) {
				c["internal/repo/kaname/pg/shadow.go"] = `package pg

func other() string {
	loginMethodsTable := "users"
	return loginMethodsTable
}
`
			},
		},
		{
			name: "законный близнец: склейка, дающая имя ограничения, а не таблицы",
			edit: func(c check.TreeCorpus) {
				c["internal/handler/login.go"] = "package handler\n\nconst c = `user_login_` + `methods_pkey`\n"
			},
		},
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
