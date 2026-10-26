// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// grant_authority_one_connection_test.go — право выдавать на области аккаунта
// и проекта не берёт второе соединение пула, держа первое (задача
// PRO-Robotech/kaname#1015, находка ревью SD-986-R1 — тот же класс, что SD-986-C1
// на делегированном пути).
//
// Читатель хранилища и хранилище отношений стоят на ОДНОМ пуле
// (`relverdict.NewAsker(pool)`, `cmd/kaname/wiring.go`). Путь, задающий вопрос о
// праве при открытой читающей транзакции, держит одно соединение и ждёт второго;
// при числе одновременных запросов не меньше свободных соединений пул встаёт
// целиком, а с ним — вся служба.
//
// Проба без базы: пул — счётчик занятых соединений, его берут читатель хранилища
// (до `Rollback`) и каждый вопрос хранилища отношений (на время вопроса).
// Судится пик: больше одного — путь держит соединение, ожидая другого.
// Положительный контроль — исход пути: право признано по кортежу `admin` на
// области, то есть вопрос Пути 2 задан, а не обойдён.
//
// Имена фикстуры — свои (`grantPool…`): проба SD-986-C1 ветки 986 заводит в этом
// же пакете `connPool`, `connRepo` и соседей.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	repoaccount "github.com/PRO-Robotech/kaname/internal/repo/kaname/account"
	repoproject "github.com/PRO-Robotech/kaname/internal/repo/kaname/project"
)

// grantPool — пул соединений пробы: число занятых и наибольшее одновременно занятое.
type grantPool struct{ held, peak int }

func (p *grantPool) acquire() {
	p.held++
	if p.held > p.peak {
		p.peak = p.held
	}
}

func (p *grantPool) release() { p.held-- }

// grantPoolWorld — аккаунт с владельцем и проект в нём.
type grantPoolWorld struct {
	acc   domain.AccountID
	owner domain.UserID
	proj  domain.ProjectID
}

type grantPoolRepo struct {
	kanamerepo.Repository
	pool *grantPool
	w    grantPoolWorld
}

func (r *grantPoolRepo) Reader(context.Context) (kanamerepo.Reader, error) {
	r.pool.acquire()
	return &grantPoolReader{pool: r.pool, w: r.w}, nil
}

type grantPoolReader struct {
	kanamerepo.Reader
	pool   *grantPool
	w      grantPoolWorld
	closed bool
}

func (rd *grantPoolReader) done() {
	if !rd.closed {
		rd.closed = true
		rd.pool.release()
	}
}

func (rd *grantPoolReader) Rollback(context.Context) error { rd.done(); return nil }
func (rd *grantPoolReader) Commit(context.Context) error   { rd.done(); return nil }
func (rd *grantPoolReader) Accounts() repoaccount.ReaderIface {
	return grantPoolAccounts{w: rd.w}
}
func (rd *grantPoolReader) Projects() repoproject.ReaderIface {
	return grantPoolProjects{w: rd.w}
}

type grantPoolAccounts struct {
	repoaccount.ReaderIface
	w grantPoolWorld
}

func (a grantPoolAccounts) Get(_ context.Context, id domain.AccountID) (domain.Account, error) {
	return domain.Account{ID: id, OwnerUserID: a.w.owner}, nil
}

type grantPoolProjects struct {
	repoproject.ReaderIface
	w grantPoolWorld
}

func (p grantPoolProjects) Get(_ context.Context, id domain.ProjectID) (domain.Project, error) {
	return domain.Project{ID: id, AccountID: p.w.acc}, nil
}

// grantPoolRelations — хранилище отношений на том же пуле: соединение — на время
// вопроса. Держит `admin` на любой области и не держит супер-гейт: путь доходит
// до Пути 2 и проходит по нему.
type grantPoolRelations struct{ pool *grantPool }

func (r grantPoolRelations) Check(_ context.Context, _, relation, _ string) (bool, error) {
	r.pool.acquire()
	defer r.pool.release()
	return relation == "admin", nil
}

// SD-986-R1 — право выдавать на области аккаунта и проекта держит не больше
// одного соединения пула за раз.
func TestGrantAuthority_SD986R1_HoldsOneConnectionAtATime(t *testing.T) {
	w := grantPoolWorld{
		acc:   domain.AccountID(ids.NewID(domain.PrefixAccount)),
		owner: domain.UserID(ids.NewID(domain.PrefixUser)),
		proj:  domain.ProjectID(ids.NewID(domain.PrefixProject)),
	}
	// Вызывающий — не владелец: Путь 1 не срабатывает, путь доходит до вопроса.
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: ids.NewID(domain.PrefixUser)})

	for _, tc := range []struct{ scope, id string }{
		{scope: "account", id: string(w.acc)},
		{scope: "project", id: string(w.proj)},
	} {
		t.Run(tc.scope, func(t *testing.T) {
			pool := &grantPool{}

			err := requireGrantAuthority(ctx, &grantPoolRepo{pool: pool, w: w}, grantPoolRelations{pool: pool}, tc.scope, tc.id)

			require.NoError(t, err, "контроль: право признано по кортежу admin на области — вопрос Пути 2 задан")
			require.Zero(t, pool.held, "соединения пути возвращены в пул")
			require.Equalf(t, 1, pool.peak,
				"путь права выдавать держал %d соединений пула разом: вопрос хранилищу прав задан при открытой читающей транзакции", pool.peak)
		})
	}
}
