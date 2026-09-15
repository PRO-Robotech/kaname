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
		{
			name: "объявленный потребитель без предмета истекает",
			spec: func(s *check.LoginVerifierSpec) {
				s.OpaqueConsumers["LoginMethodRepo.Delete → r.pool.Exec"] = "оператор удаления строки способа"
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
			spec := loginVerifierSpec()
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
