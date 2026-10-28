// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// account_id_string_key_integration_test.go — «строка обозначает не больше одного
// аккаунта» (Р6а) и тексты её отказа (Р4) уровнем хранилища (задача kaname#1052,
// приёмка `docs/engineering/acceptance/account-id-may-be-supplied-at-create.md`,
// редакция 7, sha256 a3dff53e9ae56e3e1fa959d6ee3b43a932aaf09d3918795a62c06377550e3e52).
//
// Хранилище формы не судит — её судит use-case, — поэтому здесь идентификатор
// заданной формы пишется уже сегодня, и пробы красны ровно ОТСУТСТВИЕМ ключа Р6а
// и правила текста, а не отказом формы.
//
// Сценарий AID-32 на уровне хранилища и заказы разбора экспозиции классов
// (запись `docs/specs/reviews/account-id-may-be-supplied-at-create-class-exposure/initial/50214cb9….md`,
// заказ 5):
//
//   - (а) K12 — `{"id": "S"}` с именем по умолчанию, где S — имя другого живого
//     аккаунта: текст идентификатора, а не имени;
//   - (б) K14 — оба поля конфликтуют с РАЗНЫМИ аккаунтами: текст выбирается по
//     правилу «сначала идентификатор»;
//   - (в) K23 — аккаунт `{"id": "godjee"}` переименован прочь от id: строка его
//     идентификатора по-прежнему занята; правка обратно на id проходит.
//
// Заказ 6 (б) — перебор имени личного аккаунта при установленном ключе без сырого
// 23505 — держит существующая проба
// `internal/apps/kaname/api/registration/register_reserved_name_integration_test.go`
// (`TestRegisterIntegration_F4_28_OccupiedNameDoesNotRefuseRegistration`): она
// исполняется на полной цепи миграций и с ключом Р6а судит тот же путь.

import (
	"context"
	stderrors "errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/ids"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

type keyProbe struct {
	ctx    context.Context
	pool   *pgxpool.Pool
	repo   *kanamepg.Repository
	seeded int
}

func newKeyProbe(t *testing.T) *keyProbe {
	t.Helper()
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return &keyProbe{ctx: ctx, pool: pool, repo: kanamepg.New(pool, nil)}
}

// owner — свой человек на каждую вставку: темп заведения считается на личность,
// а предмет пробы — ключ, а не темп.
func (p *keyProbe) owner(t *testing.T) domain.UserID {
	t.Helper()
	p.seeded++
	return mustSeedUser(t, p.ctx, p.pool, fmt.Sprintf("kr6a-%d", p.seeded))
}

func (p *keyProbe) insert(t *testing.T, id, name string) error {
	t.Helper()
	return insertAccountTx(p.ctx, p.repo, accountWith(id, name, p.owner(t)))
}

func (p *keyProbe) rename(id, name string) error {
	w, err := p.repo.Writer(p.ctx)
	if err != nil {
		return err
	}
	if _, err = w.AccountsW().Update(p.ctx, domain.Account{ID: domain.AccountID(id), Name: domain.AccountName(name)}, []string{"name"}); err != nil {
		_ = w.Rollback(p.ctx)
		return err
	}
	return w.Commit(p.ctx)
}

func (p *keyProbe) holding(t *testing.T, s string) int {
	t.Helper()
	var n int
	require.NoError(t, p.pool.QueryRow(p.ctx,
		`SELECT count(*) FROM kaname.accounts WHERE id = $1 OR name = $1`, s).Scan(&n))
	return n
}

func (p *keyProbe) nameOf(t *testing.T, id string) string {
	t.Helper()
	var name string
	require.NoError(t, p.pool.QueryRow(p.ctx, `SELECT name FROM kaname.accounts WHERE id = $1`, id).Scan(&name))
	return name
}

func requireNameTakenText(t *testing.T, err error, name string) {
	t.Helper()
	require.Error(t, err, "строка %s занята, а запись прошла", name)
	require.True(t, stderrors.Is(err, iamerr.ErrAlreadyExists), "ожидается ErrAlreadyExists: %v", err)
	require.Contains(t, err.Error(), "Account with name "+name+" already exists")
	require.NotContains(t, err.Error(), genericUniqueText, "конфликт строки ушёл в общий текст")
}

// TestAccountID32_StoreKeyRefusesAnIDEqualToAnotherLiveName — Р6а, сторона
// идентификатора: присланный id равен имени другого живого аккаунта — отказ
// текстом идентификатора (Р4). Близнец — тот же id, когда строка не занята.
func TestAccountID32_StoreKeyRefusesAnIDEqualToAnotherLiveName(t *testing.T) {
	p := newKeyProbe(t)
	const n1 = "aid32n-k1"
	require.NoError(t, p.insert(t, ids.NewID(domain.PrefixAccount), n1), "«Дано»: аккаунт H с именем N1")

	err := p.insert(t, n1, "aid32b-k1")
	requireAccountTaken(t, err, n1)
	require.Equal(t, 1, p.holding(t, n1), "строка %s обозначает больше одного аккаунта", n1)

	// Близнец: строка не занята ни как id, ни как имя — вставка проходит.
	require.NoError(t, p.insert(t, "aid32n-k1x", "aid32b-k1x"))
}

// TestAccountID32_StoreKeyRefusesANameEqualToAnotherLiveID — Р6а, сторона имени:
// имя равно идентификатору другого живого аккаунта — на создании и на правке
// отказ текстом имени (тот же, что при конфликте с чужим именем, AID-25).
// Близнецы — свободное имя на создании и на правке.
func TestAccountID32_StoreKeyRefusesANameEqualToAnotherLiveID(t *testing.T) {
	p := newKeyProbe(t)
	const xl = "dlputi1u-k32"
	require.NoError(t, p.insert(t, xl, "aid32-k32"), "«Дано»: аккаунт A с идентификатором Xl")

	requireNameTakenText(t, p.insert(t, ids.NewID(domain.PrefixAccount), xl), xl)
	require.Equal(t, 1, p.holding(t, xl), "строка %s обозначает больше одного аккаунта", xl)

	own := ids.NewID(domain.PrefixAccount)
	require.NoError(t, p.insert(t, own, "aid32n-own"), "близнец: свободное имя на создании")
	requireNameTakenText(t, p.rename(own, xl), xl)
	require.Equal(t, "aid32n-own", p.nameOf(t, own), "отвергнутая правка изменила имя")

	require.NoError(t, p.rename(own, "aid32n-ownx"), "близнец: свободное имя на правке")
	require.Equal(t, "aid32n-ownx", p.nameOf(t, own))
}

// TestAccountIDOrderK12_DefaultNameEqualToAnotherLiveNameAnswersTheIDText — заказ
// 5 (а): `{"id": "S"}` без имени (имя по умолчанию — S), где S — имя другого
// живого аккаунта. Р4: присланный id в конфликте — `Account S already exists`,
// а не текст имени. Сегодня текст выбирается по форме генератора
// (`accountNameTakenText`), и ответ — `Account with name S already exists`.
func TestAccountIDOrderK12_DefaultNameEqualToAnotherLiveNameAnswersTheIDText(t *testing.T) {
	p := newKeyProbe(t)
	const s = "k12-taken"
	require.NoError(t, p.insert(t, ids.NewID(domain.PrefixAccount), s), "«Дано»: живой аккаунт с именем S")

	err := p.insert(t, s, s)
	requireAccountTaken(t, err, s)
	require.NotContains(t, err.Error(), "Account with name", "конфликт присланного id назван текстом имени")
}

// TestAccountIDOrderK14_BothFieldsConflictWithDifferentAccountsAnswersTheIDText —
// заказ 5 (б): присланный id равен имени аккаунта B, присланное имя — имени
// аккаунта C. Правило «сначала идентификатор» (как `insertConflict`): текст
// идентификатора, и он не зависит от порядка срабатывания ключей.
func TestAccountIDOrderK14_BothFieldsConflictWithDifferentAccountsAnswersTheIDText(t *testing.T) {
	p := newKeyProbe(t)
	const nb, nc = "k14-nb", "k14-nc"
	require.NoError(t, p.insert(t, ids.NewID(domain.PrefixAccount), nb), "«Дано»: аккаунт B с именем nb")
	require.NoError(t, p.insert(t, ids.NewID(domain.PrefixAccount), nc), "«Дано»: аккаунт C с именем nc")

	err := p.insert(t, nb, nc)
	requireAccountTaken(t, err, nb)
	require.NotContains(t, err.Error(), "Account with name", "при двух конфликтах назван не идентификатор")
}

// TestAccountIDOrderK23_RenamedAwayFromItsIDKeepsTheIDString — заказ 5 (в):
// аккаунт `{"id": "godjee"}` (имя по умолчанию `godjee`) переименован в
// `godjee-x`; строка `godjee` по-прежнему обозначает его идентификатор, и
// создание с именем `godjee` отвергается текстом имени. Правка обратно на
// собственный id проходит: самоконфликта ключа нет. Близнец — имя `godjee-y`,
// не занятое ничем: проходит.
func TestAccountIDOrderK23_RenamedAwayFromItsIDKeepsTheIDString(t *testing.T) {
	p := newKeyProbe(t)
	const g = "godjee"
	require.NoError(t, p.insert(t, g, g), "«Дано»: аккаунт с id и именем godjee")
	require.NoError(t, p.rename(g, g+"-x"), "правка имени прочь от id")

	requireNameTakenText(t, p.insert(t, ids.NewID(domain.PrefixAccount), g), g)
	require.Equal(t, 1, p.holding(t, g), "строка %s обозначает больше одного аккаунта", g)

	require.NoError(t, p.insert(t, ids.NewID(domain.PrefixAccount), g+"-y"), "близнец: свободное имя")

	require.NoError(t, p.rename(g, g), "правка имени обратно на собственный id")
	require.Equal(t, g, p.nameOf(t, g))
}
