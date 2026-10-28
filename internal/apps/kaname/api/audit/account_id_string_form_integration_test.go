// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package audit_test

// account_id_string_form_integration_test.go — идентификатор аккаунта есть
// строка, заданная клиентом (задача kaname#1052, приёмка
// `docs/engineering/acceptance/account-id-may-be-supplied-at-create.md`,
// редакция 7, sha256 a3dff53e9ae56e3e1fa959d6ee3b43a932aaf09d3918795a62c06377550e3e52,
// вердикт круга 4 — APPROVED).
//
// Сценарии уровня I, которые судят use-case с НАСТОЯЩИМ хранилищем:
//
//   - AID-35 — строка, освобождённая правкой имени или удалением, снова
//     принимается; реестр держит только идентификатор (ключ Р6а держит лишь
//     живые строки), миры (i-а), (i-в), (i-б), (ii), (ii-б), (iii);
//   - AID-29 — каждый потребитель идентификатора аккаунта (перепись §1.3 на
//     голове ветки и якорь области привязки) принимает заданную форму,
//     отвергает чужую одним текстом и отвечает на пустую строку прежним
//     ответом.
//
// Таблицы AID-05 и AID-06 объявлены здесь же и читаются пробами
// `account_id_supplied_*_integration_test.go`, AID-33 (паритет схемы) и
// AID-39 (резерв в двух средах): перечень значений один, второго написания нет.
//
// # Чем краснеет до реализации
//
// Use-case создания сегодня судит присланный `id` формой генератора
// (`create.go:249`), а потребители — префиксом и длиной
// (`shared.ValidateResourceID`). Поэтому пробы собираются и исполняются, и их
// отказ — синхронный `invalid account id '<X>'` там, где приёмка требует приёма.
// Миры, которые сегодня держит прежний `accounts_name_unique` (AID-35 i-б и ii),
// зелёные с первого прогона и закрепляют контракт против ключа Р6а, который
// освобождал бы строку не на каждом пути; третья половина AID-29 (пустая
// строка) зелёная сегодня по построению — её таблица снята с головы ветки.

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"

	accessbindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/account"
	groupapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/group"
	membershipapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/membership"
	projectapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/project"
	roleapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/role"
	serviceaccountapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/service_account"
	userapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/user"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
	repoab "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	repomembership "github.com/PRO-Robotech/kaname/internal/repo/kaname/membership"
	reporole "github.com/PRO-Robotech/kaname/internal/repo/kaname/role"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// Литералы владельца (§0.2): допустимые идентификаторы как есть. На уровне I
// у каждой пробы своя база, поэтому литерал не сгорает между прогонами.
const (
	ownerLoginDlputi = "dlputi1u"
	ownerLoginGodjee = "godjee"
)

// aid29SystemViewRole — системная роль просмотра, посеянная миграцией (та же,
// что у кейсов `tests/newman/cases/iam-access-binding-account-scope.py:45`).
const aid29SystemViewRole = "rol1bda80f2be4d3658e"

// formRefusal — ФОРМА (§5, значения): нарушена форма (а)–(г).
func formRefusal(v string) string {
	return "invalid account id '" + v + "': an account id is 3 to 30 characters of lowercase letters, " +
		"digits and single hyphens, starts with a letter and ends with a letter or digit"
}

// reserveRefusal — РЕЗЕРВ (§5, значения): строка в резерве (д).
func reserveRefusal(v string) string {
	return "invalid account id '" + v + "': this id has a reserved form and cannot be supplied"
}

// aid05Row — строка таблицы AID-05: значение, его различие с годным близнецом,
// ожидаемое сообщение и сам близнец (его судит AID-06).
type aid05Row struct {
	value, differs, message, twin string
}

// aid05Table — таблица AID-05 редакции 7 дословно, 26 строк (15 ФОРМА, 11
// РЕЗЕРВ). Пять последних строк резерва — редакция 6: резерв (д1)/(д2) есть
// функция строки при любом префиксе, (д4) — и после свёртки похожих знаков.
func aid05Table() []aid05Row {
	form := func(v, differs, twin string) aid05Row { return aid05Row{v, differs, formRefusal(v), twin} }
	reserve := func(v, differs, twin string) aid05Row { return aid05Row{v, differs, reserveRefusal(v), twin} }
	return []aid05Row{
		form("Godjee", "заглавная буква", "godjee"),
		form(" godjee", "ведущий пробел", "godjee"),
		form("godjee ", "хвостовой пробел", "godjee"),
		form("god_jee", "подчёркивание", "god-jee"),
		form("god.jee", "точка", "god-jee"),
		form("god:jee", "двоеточие — разделитель объекта модели прав", "god-jee"),
		form("god#jee", "решётка — разделитель отношения модели прав", "god-jee"),
		form("god/jee", "косая черта — разделитель пути", "god-jee"),
		form("god--jee", "два дефиса подряд", "god-jee"),
		form("-godjee", "первый знак — дефис", "godjee"),
		form("godjee-", "последний знак — дефис", "godjee"),
		form("1godjee", "первый знак — цифра", "g1odjee"),
		form("go", "2 знака", "goj"),
		form("abcdefghijklmnopqrstuvwxyz01234", "31 знак", "abcdefghijklmnopqrstuvwxyz0123"),
		form("godjeе", "последний знак — кириллическая «е»", "godjee"),
		reserve("prj7m3k9q2x5v8b4n6t1", "полная форма идентификатора проекта", "prj7m3k9q2x5v8b4n6tu"),
		reserve("usr7m3k9q2x5v8b4n6t1", "полная форма идентификатора пользователя", "usr7m3k9q2x5v8b4n6tu"),
		reserve("acc-7m3k9q2x5v8b4n6t1", "дефисная форма аккаунта", "acc-7m3k9q2x5v8b4n6tu"),
		reserve("mbr-7m3k9q2x5v8b4n6t1", "дефисная форма членства", "mbr-7m3k9q2x5v8b4n6tu"),
		reserve("rol000000000sysviewer", "посеянный идентификатор роли", "rol000000000sysviewe"),
		reserve("personal-cloud-godjee", "пространство личных аккаунтов", "personal-clouds-godjee"),
		reserve("xyz7m3k9q2x5v8b4n6t1", "слитная форма генератора с префиксом, которого в каталоге фундамента нет",
			"xyz7m3k9q2x5v8b4n6tu"),
		reserve("e9b7m3k9q2x5v8b4n6t1", "слитная форма генератора с цифрой в префиксе", "e9b7m3k9q2x5v8b4n6tu"),
		reserve("qq-7m3k9q2x5v8b4n6t1", "дефисная форма с префиксом, которого в каталоге нет", "qq-7m3k9q2x5v8b4n6tu"),
		reserve("abcdefghijkl-7m3k9q2x5v8b4n6t1", "дефисная форма с началом из 12 знаков (30 знаков)",
			"abcdefghijkl-7m3k9q2x5v8b4n6tu"),
		reserve("pers0nal-c1oud-godjee", "пространство личных аккаунтов после свёртки", "pers0nal-c1oudx-godjee"),
	}
}

// aid06Values — перечень AID-06 редакции 7 и годный близнец каждой строки
// AID-05, без повторов. Порядок — объявления.
func aid06Values() []string {
	out := []string{
		ownerLoginDlputi, ownerLoginGodjee, "goj", "abcdefghijklmnopqrstuvwxyz0123", "god-jee", "g1odjee",
		"acc7m3k9q2x5v8b4n6t1", "acc00000000000000000", "acczzzzzzzzzzzzzzzzz",
		"acc7m3k9q2x5v8b4n6tu", "acc7m3k9q2x5v8b4n6t", "acc7m3k9q2x5v8b4n6t12",
		"prjmanager", "usr-team",
	}
	seen := make(map[string]bool, len(out))
	for _, v := range out {
		seen[v] = true
	}
	for _, r := range aid05Table() {
		if !seen[r.twin] {
			seen[r.twin] = true
			out = append(out, r.twin)
		}
	}
	return out
}

// accountsHoldingString — строки `accounts`, где строка — идентификатор ИЛИ имя.
func accountsHoldingString(t *testing.T, pool *pgxpool.Pool, s string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT count(*) FROM kaname.accounts WHERE id = $1 OR name = $1`, s).Scan(&n))
	return n
}

// createOutcome — создание от своего человека фикстуры; синхронный отказ
// роняет пробу с текстом, операция дожидается своего исхода.
func createOutcome(t *testing.T, env *testEnv, uc *account.CreateAccountUseCase, who string, a domain.Account) *operations.Operation {
	t.Helper()
	owner, _ := seedUserAccount(t, context.Background(), env.pool, who)
	a.Labels = domain.Labels{}
	op, err := uc.Execute(withPrincipal(owner), a)
	require.NoError(t, err, "%s: создание (id=%q, name=%q) отвергнуто синхронно", who, a.ID, a.Name)
	require.NotNil(t, op)
	if a.ID != "" {
		require.Equal(t, string(a.ID), createMetadata(t, op).GetAccountId(), "%s: указанный идентификатор не записан", who)
	}
	awaitWorkers(t)
	return finished(t, env, op.ID)
}

// requireNameTaken — исход операции: ALREADY_EXISTS текстом имени.
func requireNameTaken(t *testing.T, op *operations.Operation, name string) {
	t.Helper()
	require.Nil(t, op.Response, "занятое имя %s: операция вернула ресурс", name)
	require.NotNil(t, op.Error, "занятое имя %s: операция завершилась без ошибки", name)
	require.Equal(t, int32(codes.AlreadyExists), op.Error.Code, "код исхода: %v", op.Error)
	require.Equal(t, "Account with name "+name+" already exists", op.Error.Message)
}

// renameAccount — штатная правка имени хранилищем аккаунта с маской `name`;
// исход утверждается до следующего шага.
func renameAccount(t *testing.T, env *testEnv, id, name string) {
	t.Helper()
	ctx := context.Background()
	w, err := env.repo.Writer(ctx)
	require.NoError(t, err)
	defer func() { _ = w.Rollback(ctx) }()
	_, err = w.AccountsW().Update(ctx, domain.Account{ID: domain.AccountID(id), Name: domain.AccountName(name)}, []string{"name"})
	require.NoError(t, err, "правка имени %s → %s", id, name)
	require.NoError(t, w.Commit(ctx))
	var got string
	require.NoError(t, env.pool.QueryRow(ctx, `SELECT name FROM kaname.accounts WHERE id = $1`, id).Scan(&got))
	require.Equal(t, name, got, "правка имени не легла")
}

// ── AID-35 ───────────────────────────────────────────────────────────────────

// TestAccountID35_FreedStringIsAcceptedAgainRegistryHoldsOnlyTheID — AID-35.
// У каждого мира своя база: миры (i-а) и (i-б) друг друга исключают.
func TestAccountID35_FreedStringIsAcceptedAgainRegistryHoldsOnlyTheID(t *testing.T) {
	t.Run("world_i_a_rename_frees_the_string_as_an_id", func(t *testing.T) {
		env := newProbeEnv(t)
		uc := createUseCase(env, &relationDouble{admin: true})
		const s = ownerLoginDlputi

		a1 := responseAccount(t, createOutcome(t, env, uc, "aid35ia-1", domain.Account{Name: s}))
		require.Equal(t, s, a1.GetName())

		before := createOutcome(t, env, uc, "aid35ia-2", domain.Account{ID: s, Name: "aid35-ia"})
		requireAlreadyExists(t, before, s)

		renameAccount(t, env, a1.GetId(), s+"-old")

		after := createOutcome(t, env, uc, "aid35ia-3", domain.Account{ID: s, Name: "aid35-ia"})
		require.Equal(t, s, responseAccount(t, after).GetId(), "после правки имени строка не принята идентификатором")
		require.Equal(t, 1, accountsHoldingString(t, env.pool, s))
	})

	// Мир (i-в), редакция 6: `{"id": S}` БЕЗ имени, где S — имя другого живого
	// аккаунта. Совпадают обе строки запроса (имя по умолчанию равно id), а текст
	// — идентификатора (Р4), не имени. После правки имени A1 строка свободна.
	t.Run("world_i_v_default_name_equal_to_a_live_name_answers_the_id_text", func(t *testing.T) {
		env := newProbeEnv(t)
		uc := createUseCase(env, &relationDouble{admin: true})
		const s = "aid35-ic"

		a1 := responseAccount(t, createOutcome(t, env, uc, "aid35ic-1", domain.Account{Name: s}))

		requireAlreadyExists(t, createOutcome(t, env, uc, "aid35ic-2", domain.Account{ID: s}), s)

		renameAccount(t, env, a1.GetId(), s+"x")

		after := responseAccount(t, createOutcome(t, env, uc, "aid35ic-3", domain.Account{ID: s}))
		require.Equal(t, s, after.GetId(), "после правки имени строка не принята идентификатором")
		require.Equal(t, s, after.GetName(), "имя по умолчанию — не идентификатор")
		require.Equal(t, 1, accountsHoldingString(t, env.pool, s))
	})

	t.Run("world_i_b_rename_frees_the_string_as_a_name", func(t *testing.T) {
		env := newProbeEnv(t)
		uc := createUseCase(env, &relationDouble{admin: true})
		const s = "aid35-ib"

		a1 := responseAccount(t, createOutcome(t, env, uc, "aid35ib-1", domain.Account{Name: s}))

		requireNameTaken(t, createOutcome(t, env, uc, "aid35ib-2", domain.Account{Name: s}), s)

		renameAccount(t, env, a1.GetId(), "aid35-ibx")

		after := createOutcome(t, env, uc, "aid35ib-3", domain.Account{Name: s})
		require.Equal(t, s, responseAccount(t, after).GetName(), "после правки имени строка не принята именем")
		require.Equal(t, 1, accountsHoldingString(t, env.pool, s))
	})

	t.Run("world_ii_delete_frees_the_name", func(t *testing.T) {
		env := newProbeEnv(t)
		uc := createUseCase(env, &relationDouble{admin: true})
		const s = "aid35-m"

		created := createOutcome(t, env, uc, "aid35m-1", domain.Account{Name: s})
		a2 := responseAccount(t, created)

		requireNameTaken(t, createOutcome(t, env, uc, "aid35m-2", domain.Account{Name: s}), s)

		removeAccount(t, env, a2.GetId(), createMetadata(t, created).GetDefaultProjectId())

		after := createOutcome(t, env, uc, "aid35m-3", domain.Account{Name: s})
		require.Equal(t, s, responseAccount(t, after).GetName(), "после удаления имя не принято")
		require.Equal(t, 1, accountsHoldingString(t, env.pool, s))
	})

	// Мир (ii-б), редакция 6: имя удалённого аккаунта освобождено и для роли
	// идентификатора. Одно различие с отказом «до» — удаление A2.
	t.Run("world_ii_b_delete_frees_the_name_for_the_id_role", func(t *testing.T) {
		env := newProbeEnv(t)
		uc := createUseCase(env, &relationDouble{admin: true})
		const s = "aid35-m"

		created := createOutcome(t, env, uc, "aid35mb-1", domain.Account{Name: s})
		a2 := responseAccount(t, created)

		requireAlreadyExists(t, createOutcome(t, env, uc, "aid35mb-2", domain.Account{ID: s, Name: "aid35-mx"}), s)

		removeAccount(t, env, a2.GetId(), createMetadata(t, created).GetDefaultProjectId())

		after := responseAccount(t, createOutcome(t, env, uc, "aid35mb-3", domain.Account{ID: s, Name: "aid35-mx"}))
		require.Equal(t, s, after.GetId(), "после удаления имя не принято идентификатором")
		require.Equal(t, 1, accountsHoldingString(t, env.pool, s))
	})

	t.Run("world_iii_deleted_id_is_a_name_never_an_id", func(t *testing.T) {
		env := newProbeEnv(t)
		uc := createUseCase(env, &relationDouble{admin: true})
		const s = ownerLoginGodjee

		created := createOutcome(t, env, uc, "aid35g-1", domain.Account{ID: s})
		g := responseAccount(t, created)
		require.Equal(t, s, g.GetId())
		require.Equal(t, s, g.GetName(), "имя по умолчанию — идентификатор")
		removeAccount(t, env, s, createMetadata(t, created).GetDefaultProjectId())

		requireAlreadyExists(t, createOutcome(t, env, uc, "aid35g-2", domain.Account{ID: s, Name: "aid35-g"}), s)
		require.Equal(t, 1, registryRows(t, env.pool, s), "строка %s в реестре не одна", s)

		asName := responseAccount(t, createOutcome(t, env, uc, "aid35g-3", domain.Account{Name: s}))
		require.Equal(t, s, asName.GetName(), "идентификатор удалённого аккаунта не принят именем")
		require.Regexp(t, generatorAccountID, asName.GetId())
		require.Equal(t, 1, accountsHoldingString(t, env.pool, s))
	})
}

// ── AID-33, паритет ──────────────────────────────────────────────────────────

// TestAccountID33_RegistryFormAgreesWithTheTables — паритет формы схемы с
// синтаксической частью (а)–(г): реестр выданных Р5 на голове цепи принимает
// каждое значение AID-06 и отвергает каждое значение AID-05 со строкой ФОРМА
// (CHECK, 23514). Строки РЕЗЕРВ схема не судит: по Р10 схема держит
// синтаксическую часть (а)–(г), а строка резерва (д) через контракт в таблицу
// не попадает — её отвергает распознаватель до операции. Распознаватель службы
// судит те же таблицы пробами AID-05/AID-06/AID-39 этого пакета: таблицы одни,
// и паритет — по общему перечню, а не по второму написанию.
func TestAccountID33_RegistryFormAgreesWithTheTables(t *testing.T) {
	env := newProbeEnv(t)
	ctx := context.Background()
	requireRegistry(t, env.pool)

	var accepted, refused int
	for _, v := range aid06Values() {
		_, err := env.pool.Exec(ctx, `INSERT INTO kaname.issued_account_ids (id) VALUES ($1)`, v)
		require.NoError(t, err, "реестр отверг годное по Р2 значение %q", v)
		accepted++
	}
	for _, row := range aid05Table() {
		if row.message != formRefusal(row.value) {
			continue
		}
		_, err := env.pool.Exec(ctx, `INSERT INTO kaname.issued_account_ids (id) VALUES ($1)`, row.value)
		require.Error(t, err, "реестр принял значение вне формы %q (%s)", row.value, row.differs)
		require.Contains(t, err.Error(), "23514", "%q отвергнут не проверкой формы: %v", row.value, err)
		refused++
	}
	t.Logf("перепись паритета: принято %d · отвергнуто %d", accepted, refused)
	require.Positive(t, accepted)
	require.Positive(t, refused)
}

// ── AID-29 ───────────────────────────────────────────────────────────────────

// aid29Site — место §1.3, принимающее идентификатор аккаунта: адрес в дереве и
// вызов его use-case с идентификатором аккаунта.
type aid29Site struct {
	where string
	call  func(ctx context.Context, rel *relationDouble, id string) error
}

// aid29AnchorSite — адрес якоря области привязки (§1.3, роль «якорь области
// привязки», `strings.HasPrefix(…PrefixAccount)`); его use-case — создание
// привязки в области аккаунта.
const aid29AnchorSite = "internal/domain/access_binding_scope.go"

// aid29EmptyAnswer — третья половина AID-29: ответ каждого места на ПУСТУЮ
// строку в ссылочном `account_id`. Таблица снята с головы ветки (база
// `origin/942` @ f0c8a1a52 под стволом `092bee4fb322`, §1.0 приёмки) чтением
// кода мест, а не выводится: пустое значение на чтении не становится ни
// генератором, ни принятым аккаунтом (Р10). Код каждой строки — INVALID_ARGUMENT,
// синхронно и до вопроса модели. Пустое значение строки таблицы означает
// «отказа формы нет»: у `AccessBindingService/List` поле — необязательный
// фильтр, и пустая строка выдачу не сужает.
var aid29EmptyAnswer = map[string]string{
	"access_binding/list.go":                  "",
	"access_binding/list_assignable_roles.go": "invalid account id ''",
	"access_binding/list_by_account.go":       "invalid account id ''",
	"account/delete.go":                       "invalid account id ''",
	"account/get.go":                          "invalid account id ''",
	"account/handler.go":                      "invalid account id ''",
	"account/list_all_operations.go":          "invalid account id ''",
	"account/update.go":                       "invalid account id ''",
	"group/create.go":                         "account_id required",
	"membership/get.go":                       "invalid account id ''",
	"membership/list.go":                      "invalid account id ''",
	"project/create.go":                       "account_id required",
	"role/create.go":                          "Illegal argument: one of account_id / project_id required (system roles are seeded via migration, not API)",
	"service_account/create.go":               "account_id required",
	"user/invite.go":                          "Illegal argument account_id: required",
	"user/remove_from_account.go":             "invalid account id ''",
	"user/resend_invite.go":                   "invalid account id ''",
	aid29AnchorSite:                           "invalid access binding scope id ''",
}

// aid29ForeignAnswer — вторая половина AID-29: прежний текст полосы места на
// строке вне формы любого вида. У якоря привязки — отказ ворот `validateScopeID`.
func aid29ForeignAnswer(where, v string) string {
	if where == aid29AnchorSite {
		return "invalid access binding scope id '" + v + "'"
	}
	return "invalid account id '" + v + "'"
}

// aid29StringFormRefusals — ответы, которые на годной заданной форме означают
// «отвергнуто формой»: текст отказа формы аккаунта и отказ якоря привязки.
func aid29StringFormRefusals(v string) []string {
	return []string{"invalid account id '" + v + "'", "scope does not match resource_type / resource_id"}
}

// aid29Sites — перепись мест §1.3 на голове ветки: 17 проверок
// `ValidateResourceID(…PrefixAccount…)` и якорь области привязки. Место,
// которого здесь нет, — находка: перепись сверяет TestAccountID29_EverySiteHasARow.
func aid29Sites(env *testEnv, caller, member domain.UserID) []aid29Site {
	logger := discardLogger()
	return []aid29Site{
		{aid29AnchorSite, func(ctx context.Context, rel *relationDouble, id string) error {
			_, err := accessbindingapp.NewCreateAccessBindingUseCase(env.repo, env.opsRepo, catalogfixture.Source()).
				WithRelationStore(rel, logger).
				Execute(ctx, domain.AccessBinding{
					SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(member),
					RoleID: aid29SystemViewRole, ResourceType: "account", ResourceID: id,
					Scope: domain.ScopeAccount,
				})
			return err
		}},
		{"access_binding/list.go", func(ctx context.Context, rel *relationDouble, id string) error {
			_, err := accessbindingapp.NewListUseCase(env.repo).WithRelationStore(rel).
				Execute(ctx, repoab.ListFilter{AccountID: id})
			return err
		}},
		{"access_binding/list_assignable_roles.go", func(ctx context.Context, rel *relationDouble, id string) error {
			_, _, err := accessbindingapp.NewListAssignableRolesUseCase(env.repo).WithRelationStore(rel, logger).
				Execute(ctx, "account", id, reporole.ListFilter{})
			return err
		}},
		{"access_binding/list_by_account.go", func(ctx context.Context, rel *relationDouble, id string) error {
			_, _, err := accessbindingapp.NewListByAccountUseCase(env.repo).WithRelationStore(rel, logger).
				Execute(ctx, id, repoab.AccountPageFilter{})
			return err
		}},
		{"account/delete.go", func(ctx context.Context, _ *relationDouble, id string) error {
			_, err := account.NewDeleteAccountUseCase(env.repo, env.opsRepo).Execute(ctx, domain.AccountID(id))
			return err
		}},
		{"account/get.go", func(ctx context.Context, rel *relationDouble, id string) error {
			_, err := account.NewGetAccountUseCase(env.repo).WithRelationStore(rel).Execute(ctx, domain.AccountID(id))
			return err
		}},
		{"account/handler.go", func(ctx context.Context, _ *relationDouble, id string) error {
			h := account.NewHandler(nil, nil, nil, nil, nil).
				WithListOperations(shared.NewListOperationsUseCase(env.opsRepo))
			_, err := h.ListOperations(ctx, &iamv1.ListAccountOperationsRequest{AccountId: id})
			return err
		}},
		{"account/list_all_operations.go", func(ctx context.Context, rel *relationDouble, id string) error {
			_, _, err := account.NewListAllOperationsUseCase(env.repo, env.opsRepo).WithRelationStore(rel, logger).
				Execute(ctx, id, 0, "")
			return err
		}},
		{"account/update.go", func(ctx context.Context, rel *relationDouble, id string) error {
			_, err := account.NewUpdateAccountUseCase(env.repo, env.opsRepo).WithRelationStore(rel, logger).
				Execute(ctx, account.UpdateAccountInput{
					ID: domain.AccountID(id), Labels: domain.Labels{"k": "v"}, UpdateMask: []string{"labels"},
				})
			return err
		}},
		{"group/create.go", func(ctx context.Context, rel *relationDouble, id string) error {
			_, err := groupapp.NewCreateGroupUseCase(env.repo, env.opsRepo).WithRelationStore(rel, logger).
				Execute(ctx, domain.Group{AccountID: domain.AccountID(id), Name: "aid29-grp", Labels: domain.Labels{}})
			return err
		}},
		{"membership/get.go", func(ctx context.Context, _ *relationDouble, id string) error {
			_, err := membershipapp.NewGetMembershipUseCase(env.repo).
				Execute(ctx, domain.AccountID(id), domain.MembershipID(ids.NewHyphenID(ids.PrefixMembershipHyphen)))
			return err
		}},
		{"membership/list.go", func(ctx context.Context, _ *relationDouble, id string) error {
			_, _, err := membershipapp.NewListMembershipsUseCase(env.repo).
				Execute(ctx, repomembership.ListFilter{AccountID: domain.AccountID(id)})
			return err
		}},
		{"project/create.go", func(ctx context.Context, rel *relationDouble, id string) error {
			_, err := projectapp.NewCreateProjectUseCase(env.repo, env.opsRepo).WithRelationStore(rel, logger).
				Execute(ctx, domain.Project{AccountID: domain.AccountID(id), Name: "aid29-prj", Labels: domain.Labels{}})
			return err
		}},
		{"role/create.go", func(ctx context.Context, rel *relationDouble, id string) error {
			_, err := roleapp.NewCreateRoleUseCase(env.repo, env.opsRepo, catalogfixture.Source()).WithRelationStore(rel, logger).
				Execute(ctx, domain.Role{AccountID: domain.AccountID(id), Name: "aid29-role"})
			return err
		}},
		{"service_account/create.go", func(ctx context.Context, rel *relationDouble, id string) error {
			_, err := serviceaccountapp.NewCreateServiceAccountUseCase(env.repo, env.opsRepo).WithRelationStore(rel, logger).
				Execute(ctx, domain.ServiceAccount{AccountID: domain.AccountID(id), Name: "aid29-sa", Enabled: true})
			return err
		}},
		{"user/invite.go", func(ctx context.Context, rel *relationDouble, id string) error {
			_, err := userapp.NewInviteUserUseCase(env.repo, env.opsRepo, rel).WithRelationStore(rel, logger).
				Execute(ctx, userapp.InviteUserInput{AccountID: domain.AccountID(id), Email: "aid29-invitee@example.invalid"})
			return err
		}},
		{"user/remove_from_account.go", func(ctx context.Context, _ *relationDouble, id string) error {
			_, err := userapp.NewRemoveFromAccountUseCase(env.repo, env.opsRepo).Execute(ctx, caller, domain.AccountID(id))
			return err
		}},
		{"user/resend_invite.go", func(ctx context.Context, rel *relationDouble, id string) error {
			_, err := userapp.NewResendInviteUseCase(env.repo, env.opsRepo, rel,
				outboxtypes.InviteMailRateLimit{MaxPerWindow: 10, Window: time.Hour}, nil).
				Execute(ctx, caller, domain.AccountID(id))
			return err
		}},
	}
}

// TestAccountID29_EveryConsumerAcceptsTheStringFormAndRefusesAForeignOne — AID-29.
//
// Каждое место исполняется трижды: с `godjee` (заданная форма), с `God Jee`
// (вне формы любого вида) и с пустой строкой. Близнец каждой строки — её вторая
// половина; третья утверждает, что прежний ответ не изменился. Дублёр
// хранилища прав отвечает «нет» на всё: проба судит ФОРМУ, и с годной формой
// исход каждого места — не отказ формы (а отказ права, «нет такого» либо пустая
// страница). С негодной и с пустой — синхронный отказ прежним текстом и до
// вопроса модели (вопросов дублёру ноль).
func TestAccountID29_EveryConsumerAcceptsTheStringFormAndRefusesAForeignOne(t *testing.T) {
	env := newProbeEnv(t)
	caller, _ := seedUserAccount(t, context.Background(), env.pool, "aid29")
	member, _ := seedUserAccount(t, context.Background(), env.pool, "aid29m")
	ctx := withPrincipal(caller)

	sites := aid29Sites(env, caller, member)
	var refusedForm, emptyDrift []string
	requireSyncRefusal := func(t *testing.T, where string, rel *relationDouble, err error, message string) {
		t.Helper()
		require.Error(t, err, "%s: принято, а ждали отказа %q", where, message)
		st, ok := status.FromError(err)
		require.True(t, ok, "%s: ожидается статус gRPC: %v", where, err)
		require.Equal(t, codes.InvalidArgument, st.Code(), "%s: %v", where, err)
		require.Equal(t, message, st.Message(), "%s", where)
		require.Empty(t, rel.questions(), "%s: отказ пришёл после вопроса модели", where)
	}
	for _, site := range sites {
		t.Run(site.where+"/foreign", func(t *testing.T) {
			rel := &relationDouble{}
			const bad = "God Jee"
			requireSyncRefusal(t, site.where, rel, site.call(ctx, rel, bad), aid29ForeignAnswer(site.where, bad))
		})
		t.Run(site.where+"/string_form", func(t *testing.T) {
			rel := &relationDouble{}
			err := site.call(ctx, rel, ownerLoginGodjee)
			st, ok := status.FromError(err)
			if !ok || err == nil || st.Code() != codes.InvalidArgument {
				return
			}
			for _, refusal := range aid29StringFormRefusals(ownerLoginGodjee) {
				if st.Message() == refusal {
					refusedForm = append(refusedForm, site.where)
					t.Errorf("%s: идентификатор заданной формы %q отвергнут формой: %v", site.where, ownerLoginGodjee, err)
				}
			}
		})
		t.Run(site.where+"/empty", func(t *testing.T) {
			want, has := aid29EmptyAnswer[site.where]
			require.True(t, has, "%s: у места нет строки таблицы пустой строки — находка, а не пропуск", site.where)
			rel := &relationDouble{}
			err := site.call(ctx, rel, "")
			if want == "" {
				if st, ok := status.FromError(err); ok && err != nil && st.Code() == codes.InvalidArgument {
					emptyDrift = append(emptyDrift, site.where)
					t.Errorf("%s: пустая строка необязательного фильтра стала отказом: %v", site.where, err)
				}
				return
			}
			requireSyncRefusal(t, site.where, rel, err, want)
		})
	}
	awaitWorkers(t)
	t.Logf("перепись AID-29: мест %d · отвергли заданную форму %d %v · пустой фильтр стал отказом %d %v",
		len(sites), len(refusedForm), refusedForm, len(emptyDrift), emptyDrift)
}

// TestAccountID29_EverySiteHasARow — строки таблицы AID-29 по месту, а не по
// выбору: перечень мест сверяется с переписью дерева по РАЗБОРУ кода (вызов
// `ValidateResourceID` с аргументом `PrefixAccount`, роль «проверка account_id в
// RPC», §1.3). Место без строки — находка, а не пропуск.
//
// Перепись по написанию ноль — цель реализации (AID-34: распознаватель заменил
// все места), и проба на ней проходит, объявляя «мест 0», а не падает; сверку
// таблицы с местами нового распознавателя держит тогда AID-34 предикатом по роли.
func TestAccountID29_EverySiteHasARow(t *testing.T) {
	census, files := accountIDCheckCensus(t)
	require.Positive(t, files, "обход дерева не прочитал ни одного файла — перепись не судит ничего")
	have := map[string]bool{}
	for _, s := range aid29Sites(&testEnv{}, "", "") {
		have[s.where] = true
		_, hasEmpty := aid29EmptyAnswer[s.where]
		require.True(t, hasEmpty, "строка %s без ответа на пустую строку", s.where)
	}
	require.Len(t, aid29EmptyAnswer, len(have), "в таблице пустой строки есть строка без места")
	var missing []string
	for _, where := range census {
		if !have[where] {
			missing = append(missing, where)
		}
	}
	t.Logf("перепись мест: файлов прочитано %d · мест по написанию %d · строк таблицы %d · без строки %d",
		files, len(census), len(have), len(missing))
	require.Empty(t, missing, "места проверки идентификатора аккаунта без строки AID-29: %v", missing)
}

// accountIDCheckCensus — места вызова `ValidateResourceID(…, PrefixAccount, …)` и
// `HasPrefix(…, PrefixAccount)` (якорь области привязки, §1.3) в не-тестовом Go
// под `internal/`, разбором AST (литерал в строке и комментарий местом не
// считаются). Адрес — путь от `internal/apps/kaname/api/`, иначе от корня модуля.
// Второе значение — число прочитанных файлов.
func accountIDCheckCensus(t *testing.T) ([]string, int) {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", "..", "..", ".."))
	require.NoError(t, err)
	_, err = os.Stat(filepath.Join(root, "go.mod"))
	require.NoError(t, err, "корень модуля не найден от каталога пробы: %s", root)
	api := filepath.Join(root, "internal", "apps", "kaname", "api")

	seen := map[string]bool{}
	var out []string
	files := 0
	fset := token.NewFileSet()
	walkErr := filepath.WalkDir(filepath.Join(root, "internal"), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}
		files++
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || !(isCallNamed(call, "ValidateResourceID") || isCallNamed(call, "HasPrefix")) {
				return true
			}
			for _, a := range call.Args {
				if isNamed(a, "PrefixAccount") {
					where, rerr := filepath.Rel(api, path)
					if rerr != nil || strings.HasPrefix(where, "..") {
						where, _ = filepath.Rel(root, path)
					}
					where = filepath.ToSlash(where)
					if !seen[where] {
						seen[where] = true
						out = append(out, where)
					}
				}
			}
			return true
		})
		return nil
	})
	require.NoError(t, walkErr)
	return out, files
}

func isCallNamed(call *ast.CallExpr, name string) bool {
	switch fn := call.Fun.(type) {
	case *ast.SelectorExpr:
		return fn.Sel.Name == name
	case *ast.Ident:
		return fn.Name == name
	}
	return false
}

func isNamed(e ast.Expr, name string) bool {
	switch x := e.(type) {
	case *ast.SelectorExpr:
		return x.Sel.Name == name
	case *ast.Ident:
		return x.Name == name
	}
	return false
}

// discardLogger — журнал use-case пробы молчит: предмет — ответ, а не строки лога.
func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }
