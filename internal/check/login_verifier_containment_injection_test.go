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
	"fmt"
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

func NewLoginVerifier(material string) (LoginVerifier, error) { return LoginVerifier{box: &box{material}}, nil }
`,
		lvOwner: `package pg

import "github.com/PRO-Robotech/kaname/internal/domain"

const loginMethodsTable = "user_login_methods"

type row interface{ Scan(dest ...any) error }

type pooler interface{ QueryRow(q string, args ...any) row }

type LoginMethodRepo struct{ pool pooler }

func (r *LoginMethodRepo) Create(user string, v interface{ Reveal() string }) error {
	q := "INSERT INTO " + loginMethodsTable + " (user_id, verifier) VALUES ($1, $2)"
	return r.pool.QueryRow(q, user, v.Reveal()).Scan()
}

func (r *LoginMethodRepo) Get(user string) (domain.LoginVerifier, error) {
	q := "SELECT verifier FROM " + loginMethodsTable + " WHERE user_id = $1"
	var material string
	if err := r.pool.QueryRow(q, user).Scan(&material); err != nil {
		return domain.LoginVerifier{}, err
	}
	return domain.NewLoginVerifier(material)
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

// lvOwner — файл-владелец таблицы и единственный разрешённый файл выхода.
const lvOwner = "internal/repo/kaname/pg/login_method_repo.go"

// lvGo — текст файла пакета pkg с телом body: тело начинается со строки 3.
func lvGo(pkg, body string) string { return "package " + pkg + "\n\n" + body + "\n" }

// lawfulLoginVerifierSpec — объявление предмета ДЛЯ СИНТЕТИКИ: та же форма, что
// у настоящего (`loginVerifierSpec`), но разрешения и потребители названы по
// файлам синтетического корпуса.
//
// # Почему не настоящее объявление
//
// Гейт требует, чтобы у каждого разрешения и каждого потребителя был ПРЕДМЕТ:
// объявление, которому нечего разрешать, он называет находкой — и правильно.
// Подай синтетике настоящую ведомость, и всякая её запись о файле, которого в
// синтетике нет, становилась бы находкой на ЗАКОННОМ корпусе: «законный корпус
// молчит» краснело бы от каждого нового разрешения в дереве, то есть
// самопроверка зависела бы от содержимого живой ведомости и ломалась бы ровно
// тогда, когда ведомость правильно растёт вместе с кодом.
//
// Живую ведомость судит сам гейт на живом дереве (`TestLoginVerifierStaysInside`):
// разделение не ослабляет ничего — оно разводит два разных вопроса, «умеет ли
// гейт падать» и «согласована ли ведомость с деревом».
func lawfulLoginVerifierSpec() check.LoginVerifierSpec {
	spec := loginVerifierSpec()
	spec.AllowedFiles = map[string]string{
		lvOwner: "адаптер хранилища кладёт материал в базу аргументом оператора",
	}
	spec.OpaqueConsumers = map[string]check.LoginVerifierConsumer{
		"LoginMethodRepo.Create → r.pool.QueryRow": absorbing("оператор вставки строки способа: материал и запрос с именем таблицы — его аргументы"),
		"LoginMethodRepo.Get → r.pool.QueryRow":    absorbing("оператор чтения строки способа: запрос с именем таблицы — его аргумент"),
	}
	return spec
}

func auditInjected(t *testing.T, corpus check.TreeCorpus) ([]string, check.LoginVerifierCensus, error) {
	t.Helper()
	return check.AuditLoginVerifierContainment(corpus, lawfulLoginVerifierSpec())
}

func TestLoginVerifierGate_LawfulCorpusIsSilent(t *testing.T) {
	findings, census, err := auditInjected(t, lawfulLoginVerifierCorpus())
	require.NoError(t, err)
	t.Log(census)
	require.Empty(t, findings, "законный корпус обязан молчать — иначе красное в сценах ниже ничего не доказывает")
	require.Equal(t, 1, census.AccessorDecls)
	require.Equal(t, 1, census.AllowedUses["internal/repo/kaname/pg/login_method_repo.go"])
	// У владельца: объявление константы (литерал), две склейки запросов с ней
	// (вставка и чтение) и сравнение в предикате (связанное имя). Имена
	// ограничений у переводчика отказов таблицей не считаются — вне владельца
	// упоминаний ноль.
	require.Equal(t, map[string]int{"литерал": 1, "склейка": 2, "связанное имя": 1}, census.TableNamings)
	require.Equal(t, 4, census.OwnerTableNamings)
	require.Equal(t, []string{"internal/repo/kaname/pg.loginMethodsTable"}, census.Bindings,
		"перепись связанных имён обязана назвать константу владельца")
	// Потоки: материал уходит одному потребителю (вставка), запрос с именем
	// таблицы — обоим. Перепись обязана это назвать: «ноль необъявленных» без
	// числа объявленных было бы верно и о разборе, не прочитавшем ни одного вызова.
	require.Equal(t, map[string]int{
		"LoginMethodRepo.Create → r.pool.QueryRow": 2,
		"LoginMethodRepo.Get → r.pool.QueryRow":    1,
	}, census.ConsumerUses)
	require.Equal(t, 1, census.Material.ToConsumer)
	require.Equal(t, 2, census.Name.ToConsumer)
	// Виды потребителей (kaname#139): оба оператора базы — поглощающие, и ни
	// один результат не прослежен — «потребителей 2» и «результатов 0» названы
	// порознь.
	require.Equal(t, 2, census.ConsumersAbsorbing)
	require.Zero(t, census.ConsumersTransforming)
	require.Equal(t, 1, census.Material.Absorbed)
	require.Zero(t, census.Material.Transformed+census.Material.ReturnsInFile+census.Material.IntoType)
	require.Zero(t, census.Material.Undeclared+census.Name.Undeclared+census.Material.ToCorpus+census.Name.ToCorpus)
}

func TestLoginVerifierGate_Injection(t *testing.T) {
	type scene struct {
		name string
		edit func(check.TreeCorpus)
		// spec — правка объявления предмета; пусто — объявление пробы дерева.
		spec func(*check.LoginVerifierSpec)
		// wantFinding — подстрока, которая обязана стоять в находке; пусто —
		// сцена законна и гейт обязан смолчать.
		wantFinding string
		// wantPremise — подстрока отказа премисы.
		wantPremise string
		// at — строка кода в файле-владельце, на которую находка обязана
		// указать координатой «файл:строка»: красное от соседней строки — не
		// красное этой сцены.
		at string
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
			name: "владелец присваивает материал переменной пакета",
			edit: func(c check.TreeCorpus) {
				c["internal/repo/kaname/pg/login_method_repo.go"] += "\nvar last string\n\nfunc remember(v interface{ Reveal() string }) { last = v.Reveal() }\n"
			},
			wantFinding: "переменной пакета `last`",
		},
		{
			name: "владелец отправляет материал в канал",
			edit: func(c check.TreeCorpus) {
				c["internal/repo/kaname/pg/login_method_repo.go"] += "\nfunc stream(ch chan<- string, v interface{ Reveal() string }) { ch <- v.Reveal() }\n"
			},
			wantFinding: "материал отправлен в канал",
		},
		{
			name: "законный близнец: владелец отдаёт результат сверки, а не материал",
			edit: func(c check.TreeCorpus) {
				c["internal/repo/kaname/pg/login_method_repo.go"] += "\nfunc compare(h, p []byte) error { return nil }\n\nfunc check(v interface{ Reveal() string }, p []byte) error { return compare([]byte(v.Reveal()), p) }\n"
			},
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
			name: "имя ограничения, собранное из константы владельца в соседнем файле",
			edit: func(c check.TreeCorpus) {
				c["internal/repo/kaname/pg/pgmaperr.go"] += "\nconst pkeyName = loginMethodsTable + \"_pkey\"\n"
			},
			wantFinding: "internal/repo/kaname/pg/pgmaperr.go:7: таблица секрета",
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
			wantFinding: "разрешение файлу internal/repo/kaname/pg/login_method_repo.go",
		},
		// ── ИМЯ ТАБЛИЦЫ: написания внутри литерала (грамматика SQL) ─────────────
		// Postgres приводит имя без кавычек к нижнему регистру, имя в кавычках
		// сравнивает побайтово, `U&"…"` раскрывает экранирование; внутри строки
		// SQL имя живёт ещё раз — `'…'::regclass`, `EXECUTE '…'`, аргумент
		// `format`. Каждое написание — своя сцена; у каждой различающей оси —
		// законный близнец, называющий ДРУГОЕ отношение.
		{
			name: "литерал: имя без кавычек в верхнем регистре со схемой",
			edit: func(c check.TreeCorpus) {
				c["internal/handler/login.go"] = lvGo("handler", `const q = "SELECT verifier FROM kaname.USER_LOGIN_METHODS WHERE user_id = $1"`)
			},
			wantFinding: "internal/handler/login.go:3: таблица секрета",
		},
		{
			name: "литерал: имя без кавычек в смешанном регистре без схемы",
			edit: func(c check.TreeCorpus) {
				c["internal/handler/login.go"] = lvGo("handler", `const q = "SELECT verifier FROM User_Login_Methods"`)
			},
			wantFinding: "internal/handler/login.go:3: таблица секрета",
		},
		{
			name: "литерал в обратных кавычках, верхний регистр",
			edit: func(c check.TreeCorpus) {
				c["internal/handler/login.go"] = lvGo("handler", "const q = `SELECT verifier FROM ONLY KANAME.USER_LOGIN_METHODS AS m`")
			},
			wantFinding: "internal/handler/login.go:3: таблица секрета",
		},
		{
			name: "литерал: имя в кавычках точно, со схемой в кавычках",
			edit: func(c check.TreeCorpus) {
				c["internal/handler/login.go"] = lvGo("handler", `const q = "SELECT verifier FROM \"kaname\".\"user_login_methods\""`)
			},
			wantFinding: "internal/handler/login.go:3: таблица секрета",
		},
		{
			name: "литерал: экранирование Go внутри литерала",
			edit: func(c check.TreeCorpus) {
				c["internal/handler/login.go"] = lvGo("handler", `const q = "SELECT verifier FROM kaname.user\x5flogin_methods"`)
			},
			wantFinding: "internal/handler/login.go:3: таблица секрета",
		},
		{
			name: "литерал: имя U&\"…\" с экранированием Юникода",
			edit: func(c check.TreeCorpus) {
				c["internal/handler/login.go"] = lvGo("handler", `const q = "SELECT verifier FROM kaname.U&\"user\\005flogin_methods\""`)
			},
			wantFinding: "internal/handler/login.go:3: таблица секрета",
		},
		{
			name: "литерал: имя U&\"…\" со своим знаком экранирования UESCAPE",
			edit: func(c check.TreeCorpus) {
				c["internal/handler/login.go"] = lvGo("handler", `const q = "SELECT verifier FROM kaname.U&\"user!005flogin_methods\" UESCAPE '!'"`)
			},
			wantFinding: "internal/handler/login.go:3: таблица секрета",
		},
		{
			name: "литерал: имя внутри строки SQL, приводимой к regclass",
			edit: func(c check.TreeCorpus) {
				c["internal/handler/login.go"] = lvGo("handler", `const q = "SELECT 'KANAME.USER_LOGIN_METHODS'::regclass"`)
			},
			wantFinding: "internal/handler/login.go:3: таблица секрета",
		},
		{
			name: "литерал: имя внутри E-строки SQL с экранированием",
			edit: func(c check.TreeCorpus) {
				c["internal/handler/login.go"] = lvGo("handler", `const q = "SELECT E'kaname.user\\x5flogin_methods'::regclass"`)
			},
			wantFinding: "internal/handler/login.go:3: таблица секрета",
		},
		{
			name: "литерал: строка SQL, продолженная через перевод строки",
			edit: func(c check.TreeCorpus) {
				c["internal/handler/login.go"] = lvGo("handler", `const q = "SELECT 'kaname.user_login_'\n  'methods'::regclass"`)
			},
			wantFinding: "internal/handler/login.go:3: таблица секрета",
		},
		{
			name: "литерал: строки SQL, склеенные оператором ||",
			edit: func(c check.TreeCorpus) {
				c["internal/handler/login.go"] = lvGo("handler", `const q = "EXECUTE 'SELECT verifier FROM kaname.user_login_' || 'methods'"`)
			},
			wantFinding: "internal/handler/login.go:3: таблица секрета",
		},
		{
			name: "литерал: имя внутри строки SQL в долларах, верхний регистр",
			edit: func(c check.TreeCorpus) {
				c["internal/handler/login.go"] = lvGo("handler", `const q = "EXECUTE $q$SELECT verifier FROM KANAME.USER_LOGIN_METHODS$q$"`)
			},
			wantFinding: "internal/handler/login.go:3: таблица секрета",
		},
		{
			name: "законный близнец: имя в кавычках в другом регистре — другое отношение",
			edit: func(c check.TreeCorpus) {
				c["internal/handler/login.go"] = lvGo("handler", `const q = "SELECT verifier FROM kaname.\"USER_LOGIN_METHODS\""`)
			},
		},
		{
			name: "законный близнец: имя в кавычках внутри строки regclass — другое отношение",
			edit: func(c check.TreeCorpus) {
				c["internal/handler/login.go"] = lvGo("handler", `const q = "SELECT '\"USER_LOGIN_METHODS\"'::regclass"`)
			},
		},
		{
			name: "законный близнец: зеркало с общей частью имени",
			edit: func(c check.TreeCorpus) {
				c["internal/handler/login.go"] = lvGo("handler", `const q = "SELECT verifier FROM kaname.w6_user_login_methods_mirror"`)
			},
		},
		{
			name: "законный близнец: имя, продолженное знаком доллара, — другой идентификатор",
			edit: func(c check.TreeCorpus) {
				c["internal/handler/login.go"] = lvGo("handler", `const q = "SELECT verifier FROM kaname.user_login_methods$x"`)
			},
		},
		{
			name: "законный близнец: имя, продолженное буквой вне ASCII, — другой идентификатор",
			edit: func(c check.TreeCorpus) {
				c["internal/handler/login.go"] = lvGo("handler", `const q = "SELECT verifier FROM kaname.user_login_methodsé"`)
			},
		},
		{
			name: "законный близнец: имя в комментарии SQL внутри литерала",
			edit: func(c check.TreeCorpus) {
				c["internal/handler/login.go"] = lvGo("handler", `const q = "SELECT 1 -- user_login_methods читает только адаптер"`)
			},
		},

		// ── ИМЯ ТАБЛИЦЫ: написания склейки и связанного имени (грамматика Go) ────
		{
			name: "склейка Go в верхнем регистре",
			edit: func(c check.TreeCorpus) {
				c["internal/handler/login.go"] = lvGo("handler", `const q = "SELECT verifier FROM KANAME.USER_" + "LOGIN_METHODS"`)
			},
			wantFinding: "internal/handler/login.go:3: таблица секрета",
		},
		{
			name: "склейка через приведение к string",
			edit: func(c check.TreeCorpus) {
				c["internal/handler/login.go"] = lvGo("handler", `const q = string("SELECT verifier FROM kaname.user_login_") + "methods"`)
			},
			wantFinding: "internal/handler/login.go:3: таблица секрета",
		},
		{
			name: "склейка через приведение к строковому типу своего пакета",
			edit: func(c check.TreeCorpus) {
				c["internal/handler/types.go"] = lvGo("handler", `type sqlText string`)
				c["internal/handler/login.go"] = lvGo("handler", `const q = sqlText("SELECT verifier FROM kaname.user_login_") + sqlText("methods")`)
			},
			wantFinding: "internal/handler/login.go:3: таблица секрета",
		},
		{
			name: "склейка локальных констант функции",
			edit: func(c check.TreeCorpus) {
				c["internal/handler/login.go"] = lvGo("handler", "func q() string {\n\tconst a = \"user_login_\"\n\tconst b = \"methods\"\n\treturn \"SELECT verifier FROM \" + a + b\n}")
			},
			wantFinding: "internal/handler/login.go:6: таблица секрета",
		},
		{
			name: "константа владельца, повторённая неявно в его группе, в соседнем файле",
			edit: func(c check.TreeCorpus) {
				c[lvOwner] = strings.Replace(c[lvOwner], `const loginMethodsTable = "user_login_methods"`,
					"const (\n\tloginMethodsTable = \"user_login_methods\"\n\tsecondName\n)", 1)
				c["internal/repo/kaname/pg/reader.go"] = lvGo("pg", `func q() string { return "SELECT verifier FROM " + secondName }`)
			},
			wantFinding: "internal/repo/kaname/pg/reader.go:3: таблица секрета",
		},
		{
			name: "константа другого пакета через импорт с точкой",
			edit: func(c check.TreeCorpus) {
				c[lvOwner] += "\nconst LoginMethodsTable = loginMethodsTable\n"
				c["internal/handler/login.go"] = lvGo("handler", "import . \"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg\"\n\nvar q = \"SELECT verifier FROM \" + LoginMethodsTable")
			},
			wantFinding: "internal/handler/login.go:5: таблица секрета",
		},
		{
			name: "константа другого пакета через псевдоним импорта",
			edit: func(c check.TreeCorpus) {
				c[lvOwner] += "\nconst LoginMethodsTable = loginMethodsTable\n"
				c["internal/handler/login.go"] = lvGo("handler", "import store \"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg\"\n\nvar q = \"SELECT verifier FROM \" + store.LoginMethodsTable")
			},
			wantFinding: "internal/handler/login.go:5: таблица секрета",
		},

		// ── ИМЯ ТАБЛИЦЫ: вынос владельцем — те же написания, что у материала ─────
		{
			name: "владелец отдаёт имя таблицы именованным результатом",
			edit: func(c check.TreeCorpus) {
				c[lvOwner] += "\nfunc tableNamed() (s string) {\n\ts = loginMethodsTable\n\treturn\n}\n"
			},
			wantFinding: "присвоено именованному результату `s` — он уходит вызывающему (функция tableNamed)",
		},
		{
			name: "владелец отдаёт имя таблицы возвратом локальной переменной",
			edit: func(c check.TreeCorpus) {
				c[lvOwner] += "\nfunc tableLocal() string {\n\tn := loginMethodsTable\n\treturn n\n}\n"
			},
			wantFinding: "выносится возвратом из разрешённого файла — вызывающий получает его мимо гейта (функция tableLocal)",
		},
		{
			name: "владелец кладёт имя таблицы в переменную пакета, читаемую соседом",
			edit: func(c check.TreeCorpus) {
				c[lvOwner] += "\nvar exportedName string\n\nfunc init() { exportedName = loginMethodsTable }\n"
				c["internal/repo/kaname/pg/reader.go"] = lvGo("pg", `func q() string { return "SELECT verifier FROM " + exportedName }`)
			},
			wantFinding: "присвоено переменной пакета `exportedName`",
		},
		{
			name: "владелец передаёт запрос с именем таблицы функции соседнего файла",
			edit: func(c check.TreeCorpus) {
				c["internal/repo/kaname/pg/runner.go"] = lvGo("pg", `func runSQL(q string) {}`)
				c[lvOwner] += "\nfunc (r *LoginMethodRepo) purge() { runSQL(\"DELETE FROM \" + loginMethodsTable) }\n"
			},
			wantFinding: "объявленной в internal/repo/kaname/pg/runner.go, — дальше путь идёт вне разрешённого файла (функция purge)",
		},

		// ── МАТЕРИАЛ: вынос из разрешённого файла — все написания ────────────────
		{
			name: "возврат локальной переменной с материалом",
			edit: func(c check.TreeCorpus) {
				c[lvOwner] += "\nfunc leakLocal(v interface{ Reveal() string }) string {\n\tm := v.Reveal()\n\treturn m\n}\n"
			},
			wantFinding: "выносится возвратом из разрешённого файла — вызывающий получает его мимо гейта (функция leakLocal)",
		},
		{
			name: "именованный результат с пустым возвратом",
			edit: func(c check.TreeCorpus) {
				c[lvOwner] += "\nfunc leakNamed(v interface{ Reveal() string }) (s string) {\n\ts = v.Reveal()\n\treturn\n}\n"
			},
			wantFinding: "присвоен именованному результату `s` — он уходит вызывающему (функция leakNamed)",
		},
		{
			name: "именованный результат, заполненный отложенным замыканием",
			edit: func(c check.TreeCorpus) {
				c[lvOwner] += "\nfunc leakDeferred(v interface{ Reveal() string }) (s string) {\n\tdefer func() { s = v.Reveal() }()\n\treturn \"\"\n}\n"
			},
			wantFinding: "присвоен именованному результату `s` — он уходит вызывающему (функция leakDeferred)",
		},
		{
			name: "именованный результат, дописанный составным присваиванием",
			edit: func(c check.TreeCorpus) {
				c[lvOwner] += "\nfunc leakAppended(v interface{ Reveal() string }) (s string) {\n\ts += v.Reveal()\n\treturn\n}\n"
			},
			wantFinding: "присвоен именованному результату `s` — он уходит вызывающему (функция leakAppended)",
		},
		{
			name: "поле возвращаемой структуры, заполненное присваиванием",
			edit: func(c check.TreeCorpus) {
				c[lvOwner] += "\ntype pair struct{ m string }\n\nfunc leakField(v interface{ Reveal() string }) pair {\n\tvar out pair\n\tout.m = v.Reveal()\n\treturn out\n}\n"
			},
			wantFinding: "выносится возвратом из разрешённого файла — вызывающий получает его мимо гейта (функция leakField)",
		},
		{
			name: "поле возвращаемой структуры в составном литерале по указателю",
			edit: func(c check.TreeCorpus) {
				c[lvOwner] += "\ntype pair struct{ m string }\n\nfunc leakLiteral(v interface{ Reveal() string }) *pair { return &pair{m: v.Reveal()} }\n"
			},
			wantFinding: "выносится возвратом из разрешённого файла — вызывающий получает его мимо гейта (функция leakLiteral)",
		},
		{
			name: "замыкание, захватившее материал",
			edit: func(c check.TreeCorpus) {
				c[lvOwner] += "\nfunc leakClosure(v interface{ Reveal() string }) func() string {\n\tm := v.Reveal()\n\treturn func() string { return m }\n}\n"
			},
			wantFinding: "выносится возвратом из разрешённого файла — вызывающий получает его мимо гейта (функция leakClosure)",
		},
		{
			name: "замыкание, зовущее выход",
			edit: func(c check.TreeCorpus) {
				c[lvOwner] += "\nfunc leakThunk(v interface{ Reveal() string }) func() string {\n\treturn func() string { return v.Reveal() }\n}\n"
			},
			wantFinding: "выносится возвратом из разрешённого файла — вызывающий получает его мимо гейта (функция leakThunk)",
		},
		{
			name: "присваивание полю переменной пакета",
			edit: func(c check.TreeCorpus) {
				c[lvOwner] += "\nvar st struct{ m string }\n\nfunc leakPkgField(v interface{ Reveal() string }) { st.m = v.Reveal() }\n"
			},
			wantFinding: "присвоен переменной пакета `st`",
		},
		{
			name: "присваивание в карту пакета",
			edit: func(c check.TreeCorpus) {
				c[lvOwner] += "\nvar cache = map[string]string{}\n\nfunc leakMap(k string, v interface{ Reveal() string }) { cache[k] = v.Reveal() }\n"
			},
			wantFinding: "присвоен переменной пакета `cache`",
		},
		{
			name: "материал ключом карты пакета",
			edit: func(c check.TreeCorpus) {
				c[lvOwner] += "\nvar seen = map[string]bool{}\n\nfunc leakKey(v interface{ Reveal() string }) { seen[v.Reveal()] = true }\n"
			},
			wantFinding: "присвоен переменной пакета `seen`",
		},
		{
			name: "присваивание переменной пакета через локальную",
			edit: func(c check.TreeCorpus) {
				c[lvOwner] += "\nvar last string\n\nfunc leakViaLocal(v interface{ Reveal() string }) {\n\tm := v.Reveal()\n\tlast = m\n}\n"
			},
			wantFinding: "присвоен переменной пакета `last` — её читатели получают его мимо разрешённого файла (функция leakViaLocal)",
		},
		{
			name: "присваивание переменной другого пакета",
			edit: func(c check.TreeCorpus) {
				c["internal/audit/sink.go"] = lvGo("audit", "var Last string\n\nfunc Emit(s string) {}")
				c[lvOwner] = strings.Replace(c[lvOwner], `import "github.com/PRO-Robotech/kaname/internal/domain"`,
					"import (\n\t\"github.com/PRO-Robotech/kaname/internal/audit\"\n\t\"github.com/PRO-Robotech/kaname/internal/domain\"\n)", 1)
				c[lvOwner] += "\nfunc leakForeignVar(v interface{ Reveal() string }) { audit.Last = v.Reveal() }\n"
			},
			wantFinding: "присвоен переменной другого пакета `audit.Last`",
		},
		{
			name: "запись через параметр-указатель",
			edit: func(c check.TreeCorpus) {
				c[lvOwner] += "\nfunc leakPointer(v interface{ Reveal() string }, dst *string) { *dst = v.Reveal() }\n"
			},
			wantFinding: "записан в память параметра либо получателя `dst`",
		},
		{
			name: "запись в поле получателя",
			edit: func(c check.TreeCorpus) {
				c[lvOwner] += "\nfunc (r *LoginMethodRepo) leakReceiver(v interface{ Reveal() string }) { r.last = v.Reveal() }\n"
			},
			wantFinding: "записан в память параметра либо получателя `r`",
		},
		{
			name: "копирование материала в срез-параметр",
			edit: func(c check.TreeCorpus) {
				c[lvOwner] += "\nfunc leakCopy(v interface{ Reveal() string }, buf []byte) { copy(buf, v.Reveal()) }\n"
			},
			wantFinding: "записан в память параметра либо получателя `buf`",
		},
		{
			name: "отправка локальной переменной в канал",
			edit: func(c check.TreeCorpus) {
				c[lvOwner] += "\nfunc leakChan(ch chan<- string, v interface{ Reveal() string }) {\n\tm := v.Reveal()\n\tch <- m\n}\n"
			},
			wantFinding: "отправлен в канал — получатель берёт его мимо разрешённого файла (функция leakChan)",
		},
		{
			name: "аргумент функции соседнего файла",
			edit: func(c check.TreeCorpus) {
				c["internal/repo/kaname/pg/stash.go"] = lvGo("pg", `func stash(m string) {}`)
				c[lvOwner] += "\nfunc leakArg(v interface{ Reveal() string }) { stash(v.Reveal()) }\n"
			},
			wantFinding: "объявленной в internal/repo/kaname/pg/stash.go, — дальше путь идёт вне разрешённого файла (функция leakArg)",
		},
		{
			name: "локальная переменная с материалом — аргумент функции соседнего файла",
			edit: func(c check.TreeCorpus) {
				c["internal/repo/kaname/pg/stash.go"] = lvGo("pg", `func stash(m string) {}`)
				c[lvOwner] += "\nfunc leakArgLocal(v interface{ Reveal() string }) {\n\tm := v.Reveal()\n\tstash(m)\n}\n"
			},
			wantFinding: "объявленной в internal/repo/kaname/pg/stash.go, — дальше путь идёт вне разрешённого файла (функция leakArgLocal)",
		},
		{
			name: "аргумент метода получателя, объявленного в соседнем файле",
			edit: func(c check.TreeCorpus) {
				c["internal/repo/kaname/pg/remember.go"] = lvGo("pg", `func (r *LoginMethodRepo) remember(m string) {}`)
				c[lvOwner] += "\nfunc (r *LoginMethodRepo) leakMethod(v interface{ Reveal() string }) { r.remember(v.Reveal()) }\n"
			},
			wantFinding: "передан `r.remember`, объявленной в internal/repo/kaname/pg/remember.go",
		},
		{
			name: "аргумент функции другого пакета корпуса",
			edit: func(c check.TreeCorpus) {
				c["internal/audit/sink.go"] = lvGo("audit", "var Last string\n\nfunc Emit(s string) {}")
				c[lvOwner] = strings.Replace(c[lvOwner], `import "github.com/PRO-Robotech/kaname/internal/domain"`,
					"import (\n\t\"github.com/PRO-Robotech/kaname/internal/audit\"\n\t\"github.com/PRO-Robotech/kaname/internal/domain\"\n)", 1)
				c[lvOwner] += "\nfunc leakPkgFunc(v interface{ Reveal() string }) { audit.Emit(v.Reveal()) }\n"
			},
			wantFinding: "передан `audit.Emit`, объявленной в internal/audit/sink.go",
		},
		{
			name: "материал через функцию своего файла дальше в переменную пакета",
			edit: func(c check.TreeCorpus) {
				c[lvOwner] += "\nvar last string\n\nfunc leakRelay(v interface{ Reveal() string }) { keep(v.Reveal()) }\n\nfunc keep(m string) { last = m }\n"
			},
			wantFinding: "присвоен переменной пакета `last` — её читатели получают его мимо разрешённого файла (функция keep)",
		},
		{
			name: "материал вызову, внутрь которого гейт не видит, не объявленному потребителем",
			edit: func(c check.TreeCorpus) {
				c[lvOwner] = strings.Replace(c[lvOwner], `import "github.com/PRO-Robotech/kaname/internal/domain"`,
					"import (\n\t\"fmt\"\n\n\t\"github.com/PRO-Robotech/kaname/internal/domain\"\n)", 1)
				c[lvOwner] += "\nfunc leakFormat(v interface{ Reveal() string }) string { return fmt.Sprintf(\"%s\", v.Reveal()) }\n"
			},
			wantFinding: "ключ «leakFormat → fmt.Sprintf»",
		},
		{
			name: "материал строителю строк, не объявленному потребителем",
			edit: func(c check.TreeCorpus) {
				c[lvOwner] = strings.Replace(c[lvOwner], `import "github.com/PRO-Robotech/kaname/internal/domain"`,
					"import (\n\t\"strings\"\n\n\t\"github.com/PRO-Robotech/kaname/internal/domain\"\n)", 1)
				c[lvOwner] += "\nfunc leakBuilder(v interface{ Reveal() string }) string {\n\tvar b strings.Builder\n\tb.WriteString(v.Reveal())\n\treturn b.String()\n}\n"
			},
			wantFinding: "ключ «leakBuilder → b.WriteString»",
		},
		{
			name: "материал встроенной функции вывода",
			edit: func(c check.TreeCorpus) {
				c[lvOwner] += "\nfunc leakPrint(v interface{ Reveal() string }) { println(v.Reveal()) }\n"
			},
			wantFinding: "отдан встроенной функции `println`",
		},
		{
			name: "материал в оператор базы в функции, где этот оператор не объявлен потребителем",
			edit: func(c check.TreeCorpus) {
				c[lvOwner] += "\nfunc (r *LoginMethodRepo) Peek(v interface{ Reveal() string }) { _ = r.pool.QueryRow(\"SELECT 1\", v.Reveal()) }\n"
			},
			wantFinding: "ключ «LoginMethodRepo.Peek → r.pool.QueryRow»",
		},
		{
			name: "замыкание, исполненное на месте, отдаёт материал наружу возвратом",
			edit: func(c check.TreeCorpus) {
				c[lvOwner] += "\nfunc leakInPlace(v interface{ Reveal() string }) string {\n\tm := func() string { return v.Reveal() }()\n\treturn m\n}\n"
			},
			wantFinding: "выносится возвратом из разрешённого файла — вызывающий получает его мимо гейта (функция leakInPlace)",
		},
		{
			name: "срез, дополненный материалом, возвращается",
			edit: func(c check.TreeCorpus) {
				c[lvOwner] += "\nfunc leakAppendSlice(v interface{ Reveal() string }) []string {\n\tvar xs []string\n\txs = append(xs, v.Reveal())\n\treturn xs\n}\n"
			},
			wantFinding: "выносится возвратом из разрешённого файла — вызывающий получает его мимо гейта (функция leakAppendSlice)",
		},
		{
			name: "материал ключом возвращаемой карты",
			edit: func(c check.TreeCorpus) {
				c[lvOwner] += "\nfunc leakMapKey(v interface{ Reveal() string }) map[string]bool { return map[string]bool{v.Reveal(): true} }\n"
			},
			wantFinding: "выносится возвратом из разрешённого файла — вызывающий получает его мимо гейта (функция leakMapKey)",
		},
		{
			name: "значение с материалом — получатель непрозрачного вызова",
			edit: func(c check.TreeCorpus) {
				c[lvOwner] += "\ntype holder struct{ last string }\n\nfunc leakReceiverCall(v interface{ Reveal() string }) {\n\tvar h holder\n\th.last = v.Reveal()\n\th.flush()\n}\n"
			},
			wantFinding: "ключ «leakReceiverCall → h.flush»",
		},
		{
			name: "запись в поле результата вызова",
			edit: func(c check.TreeCorpus) {
				c[lvOwner] += "\nfunc leakCallResult(v interface{ Reveal() string }) { getHolder().last = v.Reveal() }\n"
			},
			wantFinding: "записан в память, чьего владельца синтаксис не называет",
		},
		{
			name: "аргумент обобщённой функции соседнего файла",
			edit: func(c check.TreeCorpus) {
				c["internal/repo/kaname/pg/stash.go"] = lvGo("pg", `func stashT[T any](m T) {}`)
				c[lvOwner] += "\nfunc leakGeneric(v interface{ Reveal() string }) { stashT[string](v.Reveal()) }\n"
			},
			wantFinding: "передан `stashT`, объявленной в internal/repo/kaname/pg/stash.go",
		},
		{
			name: "владелец отдаёт имя таблицы функции соседнего файла в инициализаторе переменной пакета",
			edit: func(c check.TreeCorpus) {
				c["internal/repo/kaname/pg/runner.go"] = lvGo("pg", `func prepare(q string) int { return 0 }`)
				c[lvOwner] += "\nvar prepared = prepare(\"SELECT verifier FROM \" + loginMethodsTable)\n"
			},
			wantFinding: "передано `prepare`, объявленной в internal/repo/kaname/pg/runner.go, — дальше путь идёт вне разрешённого файла (уровень пакета)",
		},
		{
			// Цепочка, где каждое звено необходимо: снятие любого несущего вида
			// (срез, приведение, адрес, разыменование, утверждение типа, индекс,
			// встроенный max) рвёт её, и возврат перестаёт нести материал.
			name: "материал через срез, приведение, адрес, разыменование, утверждение типа, индекс и max",
			edit: func(c check.TreeCorpus) {
				c[lvOwner] += "\nfunc leakChain(v interface{ Reveal() string }) byte {\n\tm := v.Reveal()\n\ts := m[1:]\n\tb := []byte(s)\n\tp := &b\n\tvar x any = *p\n\ty := x.([]byte)\n\tc := y[0]\n\treturn max(c, 0)\n}\n"
			},
			wantFinding: "выносится возвратом из разрешённого файла — вызывающий получает его мимо гейта (функция leakChain)",
		},
		{
			name: "обход range по материалу, значение — наружу",
			edit: func(c check.TreeCorpus) {
				c[lvOwner] += "\nvar lastRune rune\n\nfunc leakRange(v interface{ Reveal() string }) {\n\tfor _, r := range v.Reveal() {\n\t\tlastRune = r\n\t}\n}\n"
			},
			wantFinding: "присвоен переменной пакета `lastRune`",
		},
		{
			name: "запись через указатель на локальную, наружу — сама локальная",
			edit: func(c check.TreeCorpus) {
				c[lvOwner] += "\ntype pair struct{ m string }\n\nfunc leakAliasLocal(v interface{ Reveal() string }) pair {\n\tvar out pair\n\tp := &out\n\tp.m = v.Reveal()\n\treturn out\n}\n"
			},
			wantFinding: "выносится возвратом из разрешённого файла — вызывающий получает его мимо гейта (функция leakAliasLocal)",
		},
		{
			name: "запись через указатель на переменную пакета",
			edit: func(c check.TreeCorpus) {
				c[lvOwner] += "\nvar last string\n\nfunc leakAliasPkg(v interface{ Reveal() string }) {\n\tp := &last\n\t*p = v.Reveal()\n}\n"
			},
			wantFinding: "присвоен переменной пакета `last` — её читатели получают его мимо разрешённого файла (функция leakAliasPkg)",
		},
		{
			name: "запись через копию указателя на локальную",
			edit: func(c check.TreeCorpus) {
				c[lvOwner] += "\ntype pair struct{ m string }\n\nfunc leakAliasCopy(v interface{ Reveal() string }) pair {\n\tvar out pair\n\tp := &out\n\tq := p\n\tq.m = v.Reveal()\n\treturn out\n}\n"
			},
			wantFinding: "выносится возвратом из разрешённого файла — вызывающий получает его мимо гейта (функция leakAliasCopy)",
		},
		{
			name: "законный близнец: указатель на локальную с материалом, наружу — длина",
			edit: func(c check.TreeCorpus) {
				c[lvOwner] += "\ntype pair struct{ m string }\n\nfunc sizeViaPointer(v interface{ Reveal() string }) int {\n\tvar out pair\n\tp := &out\n\tp.m = v.Reveal()\n\treturn len(out.m)\n}\n"
			},
		},
		{
			name: "законный близнец: имя поля в литерале структуры совпадает с локальной переменной с материалом",
			edit: func(c check.TreeCorpus) {
				c[lvOwner] += "\ntype counted struct{ m int }\n\nfunc fieldName(v interface{ Reveal() string }) counted {\n\tm := v.Reveal()\n\t_ = len(m)\n\treturn counted{m: 1}\n}\n"
			},
		},
		{
			name: "законный близнец: локальная переменная с материалом отдана объявленному потребителю",
			edit: func(c check.TreeCorpus) {
				c[lvOwner] = strings.Replace(c[lvOwner], "return r.pool.QueryRow(q, user, v.Reveal()).Scan()",
					"m := v.Reveal()\n\treturn r.pool.QueryRow(q, user, m).Scan()", 1)
			},
		},
		{
			name: "законный близнец: материал сравнивается, наружу уходит булево",
			edit: func(c check.TreeCorpus) {
				c[lvOwner] += "\nfunc same(v interface{ Reveal() string }, p string) bool { return v.Reveal() == p }\n"
			},
		},
		{
			name: "законный близнец: замыкание, исполненное на месте, отдаёт материал функции своего файла",
			edit: func(c check.TreeCorpus) {
				c[lvOwner] += "\nfunc compare(h, p []byte) error { return nil }\n\nfunc checkInPlace(v interface{ Reveal() string }, p []byte) error {\n\tm := func() string { return v.Reveal() }()\n\treturn compare([]byte(m), p)\n}\n"
			},
		},
		{
			name: "законный близнец: локальная переменная с именем переменной пакета",
			edit: func(c check.TreeCorpus) {
				c[lvOwner] += "\nvar last string\n\nfunc shadowed(v interface{ Reveal() string }) {\n\tlast := v.Reveal()\n\t_ = last\n}\n"
			},
		},
		// ── kaname#139: РЕЗУЛЬТАТ ОБЪЯВЛЕННОГО ПОТРЕБИТЕЛЯ ──────────────────────
		// Строковая операция над материалом возвращает ЧАСТИ того же материала;
		// оператор базы — признак исхода. Сцены ниже различают эти два вида и
		// позиции результата: каждая меняет против законного корпуса один факт.
		{
			name: "результат преобразующего потребителя, взятый от материала, выносится возвратом",
			edit: func(c check.TreeCorpus) {
				lvImporting(c, "strings")
				c[lvOwner] += "\nfunc (r *LoginMethodRepo) Head(v interface{ Reveal() string }) string {\n\thead, _, _ := strings.Cut(v.Reveal(), \"$\")\n\treturn head\n}\n"
			},
			spec:        lvDeclareTransforming("LoginMethodRepo.Head → strings.Cut", 2),
			wantFinding: "материал выносится возвратом",
			at:          "return head",
		},
		{
			name: "вторая позиция преобразующего потребителя несёт предмет так же, как первая",
			edit: func(c check.TreeCorpus) {
				lvImporting(c, "strings")
				c[lvOwner] += "\nfunc (r *LoginMethodRepo) Tail(v interface{ Reveal() string }) string {\n\t_, rest, _ := strings.Cut(v.Reveal(), \"$\")\n\treturn rest\n}\n"
			},
			spec:        lvDeclareTransforming("LoginMethodRepo.Tail → strings.Cut", 2),
			wantFinding: "материал выносится возвратом",
			at:          "return rest",
		},
		{
			name: "позиция ошибки разборщика несёт вход и выносится возвратом",
			edit: func(c check.TreeCorpus) {
				lvImporting(c, "strconv")
				c[lvOwner] += "\nfunc (r *LoginMethodRepo) Cost(v interface{ Reveal() string }) error {\n\t_, err := strconv.ParseUint(v.Reveal(), 10, 32)\n\treturn err\n}\n"
			},
			spec:        lvDeclareTransforming("LoginMethodRepo.Cost → strconv.ParseUint", 0),
			wantFinding: "материал выносится возвратом",
			at:          "return err",
		},
		{
			name: "часть материала уходит по цепочке преобразующих и выносится элементом",
			edit: func(c check.TreeCorpus) {
				lvImporting(c, "strings")
				c[lvOwner] += "\nfunc (r *LoginMethodRepo) First(v interface{ Reveal() string }) string {\n\t_, rest, _ := strings.Cut(v.Reveal(), \"$\")\n\tparts := strings.Split(rest, \",\")\n\treturn parts[0]\n}\n"
			},
			spec: func(s *check.LoginVerifierSpec) {
				lvDeclareTransforming("LoginMethodRepo.First → strings.Cut", 2)(s)
				lvDeclareTransforming("LoginMethodRepo.First → strings.Split")(s)
			},
			wantFinding: "материал выносится возвратом",
			at:          "return parts[0]",
		},
		{
			name: "часть материала отдана необъявленному вызову — находка у вызова, а не молчание",
			edit: func(c check.TreeCorpus) {
				lvImporting(c, "strings")
				c[lvOwner] += "\nfunc (r *LoginMethodRepo) Fields(v interface{ Reveal() string }) int {\n\t_, rest, _ := strings.Cut(v.Reveal(), \"$\")\n\treturn len(strings.Fields(rest))\n}\n"
			},
			spec:        lvDeclareTransforming("LoginMethodRepo.Fields → strings.Cut", 2),
			wantFinding: "ключ «LoginMethodRepo.Fields → strings.Fields»",
			at:          "return len(strings.Fields(rest))",
		},
		{
			name: "помощник разрешённого файла возвращает часть и зовётся из соседнего файла пакета",
			edit: func(c check.TreeCorpus) {
				lvImporting(c, "strings")
				c[lvOwner] += "\nfunc head(m string) string {\n\th, _, _ := strings.Cut(m, \"$\")\n\treturn h\n}\n\nfunc (r *LoginMethodRepo) Size(v interface{ Reveal() string }) int { return len(head(v.Reveal())) }\n"
				c["internal/repo/kaname/pg/costclass.go"] = lvGo("pg", "func prefixOf(m string) string { return head(m) }")
			},
			spec:        lvDeclareTransforming("head → strings.Cut", 2),
			wantFinding: "материал выносится возвратом",
			at:          "return h",
		},
		{
			name: "помощник, зовущийся только своим файлом, отдаёт часть вызывающему, а тот выносит её возвратом",
			edit: func(c check.TreeCorpus) {
				lvImporting(c, "strings")
				c[lvOwner] += "\nfunc head(m string) string {\n\th, _, _ := strings.Cut(m, \"$\")\n\treturn h\n}\n\nfunc (r *LoginMethodRepo) Prefix(v interface{ Reveal() string }) string { return head(v.Reveal()) }\n"
			},
			spec:        lvDeclareTransforming("head → strings.Cut", 2),
			wantFinding: "материал выносится возвратом",
			at:          "return head(v.Reveal())",
		},
		{
			name: "кортеж объявлением переменных: вторая позиция преобразующего выносится возвратом",
			edit: func(c check.TreeCorpus) {
				lvImporting(c, "strings")
				c[lvOwner] += "\nfunc (r *LoginMethodRepo) Rest(v interface{ Reveal() string }) string {\n\tvar _, rest, _ = strings.Cut(v.Reveal(), \"$\")\n\treturn rest\n}\n"
			},
			spec:        lvDeclareTransforming("LoginMethodRepo.Rest → strings.Cut", 2),
			wantFinding: "материал выносится возвратом",
			at:          "return rest",
		},
		// Многозначный вызов вне присваивания (возврат ревью go-style #139): позиции
		// результата судятся и там, где вызов стоит аргументом (`g(f())`) либо
		// возвратом замыкания. Чистая позиция 0 у разборщика — ровно форма живой
		// ведомости; несущая — позиция 1 (ошибка несёт вход).
		{
			name: "возврат замыкания: многозначный разборщик отдаёт несущую позицию замыканию, оно уходит возвратом",
			edit: func(c check.TreeCorpus) {
				lvImporting(c, "strconv")
				c[lvOwner] += "\nfunc (r *LoginMethodRepo) CostFn(v interface{ Reveal() string }) func() (uint64, error) {\n\treturn func() (uint64, error) { return strconv.ParseUint(v.Reveal(), 10, 32) }\n}\n"
			},
			spec:        lvDeclareTransforming("LoginMethodRepo.CostFn → strconv.ParseUint", 0),
			wantFinding: "материал выносится возвратом",
			at:          "return func() (uint64, error)",
		},
		{
			name: "аргументом: многозначный разборщик отдаёт несущую позицию помощнику своего файла, тот — вызывающему",
			edit: func(c check.TreeCorpus) {
				lvImporting(c, "strconv")
				c[lvOwner] += "\nfunc pick(_ uint64, err error) error { return err }\n\nfunc (r *LoginMethodRepo) Check(v interface{ Reveal() string }) error {\n\treturn pick(strconv.ParseUint(v.Reveal(), 10, 32))\n}\n"
			},
			spec:        lvDeclareTransforming("LoginMethodRepo.Check → strconv.ParseUint", 0),
			wantFinding: "материал выносится возвратом",
			at:          "return pick(strconv.ParseUint",
		},
		{
			name: "аргументом: многозначный разборщик отдаёт несущую позицию функции соседнего файла",
			edit: func(c check.TreeCorpus) {
				lvImporting(c, "strconv")
				c[lvOwner] += "\nfunc (r *LoginMethodRepo) Send(v interface{ Reveal() string }) {\n\tsink(strconv.ParseUint(v.Reveal(), 10, 32))\n}\n"
				c["internal/repo/kaname/pg/costclass.go"] = lvGo("pg", "func sink(_ uint64, err error) { _ = err }")
			},
			spec:        lvDeclareTransforming("LoginMethodRepo.Send → strconv.ParseUint", 0),
			wantFinding: "передан `sink`, объявленной в internal/repo/kaname/pg/costclass.go",
			at:          "sink(strconv.ParseUint",
		},
		{
			name: "аргументом: позиция i результата — параметр i, и наружу уходит параметр чистой позиции",
			edit: func(c check.TreeCorpus) {
				lvImporting(c, "strings")
				c[lvOwner] += "\nfunc found(head, rest string, ok bool) bool { return ok }\n\nfunc (r *LoginMethodRepo) Has(v interface{ Reveal() string }) bool {\n\treturn found(strings.Cut(v.Reveal(), \"$\"))\n}\n"
			},
			spec: lvDeclareTransforming("LoginMethodRepo.Has → strings.Cut", 2),
		},
		{
			name: "аргументом: позиция i результата — параметр i, и наружу уходит параметр несущей позиции",
			edit: func(c check.TreeCorpus) {
				lvImporting(c, "strings")
				c[lvOwner] += "\nfunc second(head, rest string, ok bool) string { return rest }\n\nfunc (r *LoginMethodRepo) Rest(v interface{ Reveal() string }) string {\n\treturn second(strings.Cut(v.Reveal(), \"$\"))\n}\n"
			},
			spec:        lvDeclareTransforming("LoginMethodRepo.Rest → strings.Cut", 2),
			wantFinding: "материал выносится возвратом",
			at:          "return second(strings.Cut",
		},
		{
			name: "аргументом: число позиций не названо (непрозрачный вызов в вариадический помощник) — несущее получают все параметры",
			edit: func(c check.TreeCorpus) {
				lvImporting(c, "strings")
				c[lvOwner] += "\nfunc tail(head string, rest ...any) any { return rest[0] }\n\nfunc (r *LoginMethodRepo) Tail(v interface{ Reveal() string }) any {\n\treturn tail(strings.Cut(v.Reveal(), \"$\"))\n}\n"
			},
			spec:        lvDeclareTransforming("LoginMethodRepo.Tail → strings.Cut", 2),
			wantFinding: "материал выносится возвратом",
			at:          "return tail(strings.Cut",
		},
		{
			name: "законный близнец: возврат замыкания — многозначный помощник своего файла, ни одна позиция не несёт",
			edit: func(c check.TreeCorpus) {
				c[lvOwner] += "\nfunc lens(m string) (int, int) { return len(m), 1 }\n\nfunc (r *LoginMethodRepo) SizeFn(v interface{ Reveal() string }) func() (int, int) {\n\treturn func() (int, int) { return lens(v.Reveal()) }\n}\n"
			},
		},
		// Замыкание на месте аргументом (второй круг ревью #139): `g(func() (A, B)
		// {…}())` многозначно так же, как `g(f())`, но его результат судится
		// целиком — значит несущее получают ВСЕ параметры g, как все позиции
		// кортежа в присваивании, а не только параметр 0.
		{
			name: "аргументом: замыкание на месте отдаёт несущую позицию 1 помощнику своего файла, тот — вызывающему",
			edit: func(c check.TreeCorpus) {
				lvImporting(c, "strconv")
				c[lvOwner] += "\nfunc pick(_ uint64, err error) error { return err }\n\nfunc (r *LoginMethodRepo) Check(v interface{ Reveal() string }) error {\n\treturn pick(func() (uint64, error) { return strconv.ParseUint(v.Reveal(), 10, 32) }())\n}\n"
			},
			spec:        lvDeclareTransforming("LoginMethodRepo.Check → strconv.ParseUint", 0),
			wantFinding: "материал выносится возвратом",
			at:          "return pick(func()",
		},
		{
			name: "аргументом: замыкание на месте отдаёт несущую позицию 1 замыканию-получателю, оно — вызывающему",
			edit: func(c check.TreeCorpus) {
				lvImporting(c, "strconv")
				c[lvOwner] += "\nfunc (r *LoginMethodRepo) Pass(v interface{ Reveal() string }) error {\n\treturn func(_ uint64, err error) error { return err }(func() (uint64, error) { return strconv.ParseUint(v.Reveal(), 10, 32) }())\n}\n"
			},
			spec:        lvDeclareTransforming("LoginMethodRepo.Pass → strconv.ParseUint", 0),
			wantFinding: "материал выносится возвратом",
			at:          "return func(_ uint64, err error)",
		},
		{
			name: "законный близнец: замыкание на месте несёт материал, а помощник своего файла не отдаёт ни одного параметра",
			edit: func(c check.TreeCorpus) {
				lvImporting(c, "strconv")
				c[lvOwner] += "\nfunc drop(_ uint64, _ error) bool { return true }\n\nfunc (r *LoginMethodRepo) Drop(v interface{ Reveal() string }) bool {\n\treturn drop(func() (uint64, error) { return strconv.ParseUint(v.Reveal(), 10, 32) }())\n}\n"
			},
			spec: lvDeclareTransforming("LoginMethodRepo.Drop → strconv.ParseUint", 0),
		},
		{
			name: "законный близнец: замыкание на месте материала не несёт, помощник отдаёт параметр 1",
			edit: func(c check.TreeCorpus) {
				c[lvOwner] += "\nfunc pick(_ uint64, err error) error { return err }\n\nfunc (r *LoginMethodRepo) Plain() error {\n\treturn pick(func() (uint64, error) { return 1, nil }())\n}\n"
			},
		},
		{
			name: "чистая позиция вне результата вызова истекает: ей нечего разрешать",
			edit: func(c check.TreeCorpus) {
				lvImporting(c, "strings")
				c[lvOwner] += "\nfunc (r *LoginMethodRepo) Head(v interface{ Reveal() string }) int {\n\thead, _, _ := strings.Cut(v.Reveal(), \"$\")\n\treturn len(head)\n}\n"
			},
			spec:        lvDeclareTransforming("LoginMethodRepo.Head → strings.Cut", 2, 7),
			wantFinding: "«LoginMethodRepo.Head → strings.Cut»: чистая позиция 7 вне результата вызова (позиций 3)",
		},
		{
			name: "приведение части к числу не очищает её: байт материала выносится возвратом",
			edit: func(c check.TreeCorpus) {
				lvImporting(c, "strings")
				c[lvOwner] += "\nfunc (r *LoginMethodRepo) Lead(v interface{ Reveal() string }) uint8 {\n\thead, _, _ := strings.Cut(v.Reveal(), \"$\")\n\treturn uint8(head[0])\n}\n"
			},
			spec:        lvDeclareTransforming("LoginMethodRepo.Lead → strings.Cut", 2),
			wantFinding: "материал выносится возвратом",
			at:          "return uint8(head[0])",
		},
		{
			name: "помощник, взятый значением, а не вызовом, — его возврат судится как вынос",
			edit: func(c check.TreeCorpus) {
				lvImporting(c, "strings")
				c[lvOwner] += "\nfunc head(m string) string {\n\th, _, _ := strings.Cut(m, \"$\")\n\treturn h\n}\n\nfunc (r *LoginMethodRepo) Size(v interface{ Reveal() string }) int { return len(head(v.Reveal())) }\n\nvar headOf = head\n"
			},
			spec:        lvDeclareTransforming("head → strings.Cut", 2),
			wantFinding: "материал выносится возвратом",
			at:          "return h",
		},
		{
			name: "часть материала передана функции файла объявления, которая не конструирует тип",
			edit: func(c check.TreeCorpus) {
				lvImporting(c, "strings")
				c["internal/domain/login_method.go"] += "\nfunc Describe(m string) string { return m }\n"
				c[lvOwner] += "\nfunc (r *LoginMethodRepo) Label(v interface{ Reveal() string }) string {\n\thead, _, _ := strings.Cut(v.Reveal(), \"$\")\n\treturn domain.Describe(head)\n}\n"
			},
			spec:        lvDeclareTransforming("LoginMethodRepo.Label → strings.Cut", 2),
			wantFinding: "передан `domain.Describe`, объявленной в internal/domain/login_method.go",
			at:          "return domain.Describe(head)",
		},
		{
			name: "законный близнец: преобразованный материал возвращается в свой тип конструктором",
			edit: func(c check.TreeCorpus) {
				lvImporting(c, "strings")
				c[lvOwner] += "\nfunc (r *LoginMethodRepo) Trimmed(v interface{ Reveal() string }) (domain.LoginVerifier, error) {\n\treturn domain.NewLoginVerifier(strings.TrimSpace(v.Reveal()))\n}\n"
			},
			spec: lvDeclareTransforming("LoginMethodRepo.Trimmed → strings.TrimSpace"),
		},
		{
			name: "законный близнец: из части преобразующего наружу уходит длина",
			edit: func(c check.TreeCorpus) {
				lvImporting(c, "strings")
				c[lvOwner] += "\nfunc (r *LoginMethodRepo) Head(v interface{ Reveal() string }) int {\n\thead, _, _ := strings.Cut(v.Reveal(), \"$\")\n\treturn len(head)\n}\n"
			},
			spec: lvDeclareTransforming("LoginMethodRepo.Head → strings.Cut", 2),
		},
		{
			name: "законный близнец: наружу уходит признак «разделитель найден» — чистая позиция",
			edit: func(c check.TreeCorpus) {
				lvImporting(c, "strings")
				c[lvOwner] += "\nfunc (r *LoginMethodRepo) Marked(v interface{ Reveal() string }) bool {\n\t_, _, found := strings.Cut(v.Reveal(), \"$\")\n\treturn found\n}\n"
			},
			spec: lvDeclareTransforming("LoginMethodRepo.Marked → strings.Cut", 2),
		},
		{
			name: "законный близнец: оператор базы возвращает признак исхода",
			edit: func(c check.TreeCorpus) {
				c[lvOwner] += "\nfunc (r *LoginMethodRepo) Put(user string, v interface{ Reveal() string }) (bool, error) {\n\tvar created bool\n\terr := r.pool.QueryRow(\"INSERT INTO \"+loginMethodsTable+\" (user_id, verifier) VALUES ($1, $2) RETURNING true\", user, v.Reveal()).Scan(&created)\n\treturn created, err\n}\n"
			},
			spec: lvDeclareAbsorbing("LoginMethodRepo.Put → r.pool.QueryRow"),
		},
		{
			name: "законный близнец: помощник, зовущийся только своим файлом, отдаёт часть вызывающему, тот — длину",
			edit: func(c check.TreeCorpus) {
				lvImporting(c, "strings")
				c[lvOwner] += "\nfunc head(m string) string {\n\th, _, _ := strings.Cut(m, \"$\")\n\treturn h\n}\n\nfunc (r *LoginMethodRepo) Size(v interface{ Reveal() string }) int { return len(head(v.Reveal())) }\n"
			},
			spec: lvDeclareTransforming("head → strings.Cut", 2),
		},
		{
			name: "премиса: потребитель объявлен без вида",
			spec: func(s *check.LoginVerifierSpec) {
				s.OpaqueConsumers["LoginMethodRepo.Get → r.pool.QueryRow"] = check.LoginVerifierConsumer{Reason: "оператор чтения"}
			},
			wantPremise: "«LoginMethodRepo.Get → r.pool.QueryRow»: вид не объявлен",
		},
		{
			name: "премиса: потребитель объявлен без причины",
			spec: func(s *check.LoginVerifierSpec) {
				s.OpaqueConsumers["LoginMethodRepo.Get → r.pool.QueryRow"] = check.LoginVerifierConsumer{Kind: check.ConsumerAbsorbing}
			},
			wantPremise: "причина не названа",
		},
		{
			name: "премиса: поглощающему объявлены чистые позиции",
			spec: func(s *check.LoginVerifierSpec) {
				s.OpaqueConsumers["LoginMethodRepo.Get → r.pool.QueryRow"] = check.LoginVerifierConsumer{
					Kind: check.ConsumerAbsorbing, Reason: "оператор чтения", Clean: map[int]string{0: "строка исхода"},
				}
			},
			wantPremise: "у поглощающего чисты все позиции",
		},
		{
			name: "премиса: чистая позиция преобразующего без причины",
			spec: func(s *check.LoginVerifierSpec) {
				s.OpaqueConsumers["LoginMethodRepo.Get → r.pool.QueryRow"] = check.LoginVerifierConsumer{
					Kind: check.ConsumerTransforming, Reason: "оператор чтения", Clean: map[int]string{0: ""},
				}
			},
			wantPremise: "чистая позиция 0 без причины",
		},
		{
			name: "объявленный потребитель без предмета истекает",
			spec: func(s *check.LoginVerifierSpec) {
				s.OpaqueConsumers["LoginMethodRepo.Delete → r.pool.Exec"] = absorbing("оператор удаления строки способа")
			},
			wantFinding: "потребитель «LoginMethodRepo.Delete → r.pool.Exec»",
		},
		{
			name: "потребитель, объявленный у функции, не прощает тот же вызов в другой",
			spec: func(s *check.LoginVerifierSpec) {
				delete(s.OpaqueConsumers, "LoginMethodRepo.Get → r.pool.QueryRow")
			},
			wantFinding: "ключ «LoginMethodRepo.Get → r.pool.QueryRow»",
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

type execer interface{ Exec(q string, args ...any) error }

func write(db execer, v interface{ Reveal() string }) error { return db.Exec("INSERT", v.Reveal()) }

func isLoginMethodsTable(name string) bool { return name != "" }
`
			},
			wantPremise: "правило второго читателя ослепло",
		},
	}
	for _, sc := range scenes {
		t.Run(sc.name, func(t *testing.T) {
			corpus := lawfulLoginVerifierCorpus()
			if sc.edit != nil {
				sc.edit(corpus)
			}
			spec := lawfulLoginVerifierSpec()
			if sc.spec != nil {
				sc.spec(&spec)
			}
			findings, census, err := check.AuditLoginVerifierContainment(corpus, spec)
			t.Log(census)
			t.Logf("находки: %q", findings)
			switch {
			case sc.wantPremise != "":
				require.Error(t, err, "премиса обязана отказать, а не смолчать")
				require.Contains(t, err.Error(), sc.wantPremise)
			case sc.wantFinding != "":
				require.NoError(t, err)
				require.NotEmpty(t, findings, "внесённый дефект обязан быть найден")
				require.Contains(t, strings.Join(findings, "\n"), sc.wantFinding, "находка обязана называть координату")
				if sc.at != "" {
					line := lvLineOf(t, corpus[lvOwner], sc.at)
					require.Contains(t, strings.Join(findings, "\n"), fmt.Sprintf("%s:%d: ", lvOwner, line),
						"находка обязана указать на строку %q", sc.at)
				}
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

// lvImporting — файл-владелец синтетики импортирует ещё и пакеты imports.
func lvImporting(c check.TreeCorpus, imports ...string) {
	var b strings.Builder
	b.WriteString("import (\n")
	for _, imp := range imports {
		fmt.Fprintf(&b, "\t%q\n", imp)
	}
	b.WriteString("\n\t\"github.com/PRO-Robotech/kaname/internal/domain\"\n)")
	c[lvOwner] = strings.Replace(c[lvOwner], `import "github.com/PRO-Robotech/kaname/internal/domain"`, b.String(), 1)
}

// lvLineOf — номер строки, где в тексте src впервые стоит needle.
func lvLineOf(t *testing.T, src, needle string) int {
	t.Helper()
	i := strings.Index(src, needle)
	require.GreaterOrEqualf(t, i, 0, "строки %q в синтетике нет — сцена не построена", needle)
	return strings.Count(src[:i], "\n") + 1
}

// lvDeclareTransforming — объявить потребителя ПРЕОБРАЗУЮЩИМ: результат несёт
// предмет во всех позициях, кроме clean.
func lvDeclareTransforming(key string, clean ...int) func(*check.LoginVerifierSpec) {
	return func(s *check.LoginVerifierSpec) {
		c := check.LoginVerifierConsumer{Kind: check.ConsumerTransforming, Reason: "сцена: преобразующий"}
		if len(clean) > 0 {
			c.Clean = map[int]string{}
			for _, pos := range clean {
				c.Clean[pos] = "сцена: позиция признака либо числа"
			}
		}
		s.OpaqueConsumers[key] = c
	}
}

// lvDeclareAbsorbing — объявить потребителя ПОГЛОЩАЮЩИМ: результат предмета не несёт.
func lvDeclareAbsorbing(key string) func(*check.LoginVerifierSpec) {
	return func(s *check.LoginVerifierSpec) {
		s.OpaqueConsumers[key] = absorbing("сцена: поглощающий")
	}
}

// absorbing — объявление поглощающего потребителя с причиной.
func absorbing(reason string) check.LoginVerifierConsumer {
	return check.LoginVerifierConsumer{Kind: check.ConsumerAbsorbing, Reason: reason}
}

// TestLoginVerifierGate_TracedResultsAreCountedApart — перепись называет
// прослеженные результаты отдельно от объявленных потребителей (kaname#139):
// «потребителей 3» при «результатов прослежено 0» и при «1» — разные
// утверждения, и читатель переписи обязан их различать.
func TestLoginVerifierGate_TracedResultsAreCountedApart(t *testing.T) {
	corpus := lawfulLoginVerifierCorpus()
	lvImporting(corpus, "strings")
	corpus[lvOwner] += "\nfunc head(m string) string {\n\th, _, _ := strings.Cut(m, \"$\")\n\treturn h\n}\n\n" +
		"func (r *LoginMethodRepo) Size(v interface{ Reveal() string }) int { return len(head(v.Reveal())) }\n"
	spec := lawfulLoginVerifierSpec()
	lvDeclareTransforming("head → strings.Cut", 2)(&spec)

	findings, census, err := check.AuditLoginVerifierContainment(corpus, spec)
	require.NoError(t, err)
	t.Log(census)
	require.Empty(t, findings)
	require.Equal(t, 1, census.ConsumersTransforming)
	require.Equal(t, 1, census.CleanPositions)
	require.Equal(t, 1, census.Material.Transformed, "результат преобразующего прослежен — и назван числом")
	require.Equal(t, 1, census.Material.ReturnsInFile, "возврат помощника своему файлу прослежен у вызывающего")
	require.Contains(t, census.String(), "преобразующих 1")
	require.Contains(t, census.String(), "возвратов своему файлу прослежено 1")
}

// TestLoginVerifierGate_PremiseTextIsDeterministic — при двух негодных чистых
// позициях отказ называет одну и ту же — наименьшую: текст отказа, зависящий от
// порядка обхода карты, меняется от прогона к прогону и не сверяется ни с чем.
func TestLoginVerifierGate_PremiseTextIsDeterministic(t *testing.T) {
	for range 64 {
		spec := lawfulLoginVerifierSpec()
		spec.OpaqueConsumers["LoginMethodRepo.Get → r.pool.QueryRow"] = check.LoginVerifierConsumer{
			Kind: check.ConsumerTransforming, Reason: "оператор чтения",
			Clean: map[int]string{0: "", 1: "", 2: "", 3: ""},
		}
		_, _, err := check.AuditLoginVerifierContainment(lawfulLoginVerifierCorpus(), spec)
		require.Error(t, err)
		require.Contains(t, err.Error(), "чистая позиция 0 без причины")
	}
}
