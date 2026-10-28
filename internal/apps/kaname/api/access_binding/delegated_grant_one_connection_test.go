// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// delegated_grant_one_connection_test.go — делегированный путь права выдавать
// не берёт второе соединение пула, держа первое (задача PRO-Robotech/kaname#986,
// находка ревью SD-986-C1).
//
// Читающая транзакция делегированного пути и вопрос о праве делегирующего (Д3)
// стоят на ОДНОМ пуле: читатель хранилища и хранилище отношений
// (`relverdict.NewAsker(pool)`, `cmd/kaname/wiring.go`). Если вопрос задаётся при
// открытой читающей транзакции, каждая выдача делегатом держит одно соединение и
// ждёт второго; при числе одновременных выдач не меньше свободных соединений пул
// встаёт целиком, а с ним — вся служба.
//
// Проба без базы: пул — счётчик занятых соединений, его берут читатель
// хранилища (до `Rollback`) и каждый вопрос хранилища отношений (на время
// вопроса). Судится пик: больше одного — путь держит соединение, ожидая
// другого, и пул размером с число одновременных выдач встаёт. Положительный
// контроль — исход пути: выдача принята, а не отвергнута до вопроса Д3.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	repoab "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	repoaccount "github.com/PRO-Robotech/kaname/internal/repo/kaname/account"
	repogd "github.com/PRO-Robotech/kaname/internal/repo/kaname/grant_delegation"
	repogroup "github.com/PRO-Robotech/kaname/internal/repo/kaname/group"
	reposa "github.com/PRO-Robotech/kaname/internal/repo/kaname/service_account"
)

// connPool — пул соединений пробы: число занятых и наибольшее одновременно занятое.
type connPool struct{ held, peak int }

func (p *connPool) acquire() {
	p.held++
	if p.held > p.peak {
		p.peak = p.held
	}
}

func (p *connPool) release() { p.held-- }

// connWorld — мир одной выдачи делегатом: делегирование D аккаунта acc от
// владельца usr, учётка-субъект того же аккаунта, зарегистрированный объект.
type connWorld struct {
	acc       domain.AccountID
	owner     domain.UserID
	delegate  domain.ServiceAccountID
	subjectSA domain.ServiceAccountID
	group     domain.GroupID
	role      domain.RoleID
	members   map[domain.SubjectID]bool
	d         domain.GrantDelegation
}

type connRepo struct {
	kanamerepo.Repository
	pool *connPool
	w    *connWorld
}

func (r *connRepo) Reader(context.Context) (kanamerepo.Reader, error) {
	r.pool.acquire()
	return &connReader{pool: r.pool, w: r.w}, nil
}

type connReader struct {
	kanamerepo.Reader
	pool   *connPool
	w      *connWorld
	closed bool
}

func (rd *connReader) done() {
	if !rd.closed {
		rd.closed = true
		rd.pool.release()
	}
}

func (rd *connReader) Rollback(context.Context) error { rd.done(); return nil }
func (rd *connReader) Commit(context.Context) error   { rd.done(); return nil }
func (rd *connReader) Accounts() repoaccount.ReaderIface {
	return connAccounts{w: rd.w}
}
func (rd *connReader) ServiceAccounts() reposa.ReaderIface { return connSAs{w: rd.w} }
func (rd *connReader) Groups() repogroup.ReaderIface       { return connGroups{w: rd.w} }
func (rd *connReader) AccessBindings() repoab.ReaderIface  { return connAB{w: rd.w} }

type connAccounts struct {
	repoaccount.ReaderIface
	w *connWorld
}

func (a connAccounts) Get(_ context.Context, id domain.AccountID) (domain.Account, error) {
	return domain.Account{ID: id, OwnerUserID: a.w.owner}, nil
}

type connSAs struct {
	reposa.ReaderIface
	w *connWorld
}

func (s connSAs) Get(_ context.Context, id domain.ServiceAccountID) (domain.ServiceAccount, error) {
	return domain.ServiceAccount{ID: id, AccountID: s.w.acc}, nil
}

type connGroups struct {
	repogroup.ReaderIface
	w *connWorld
}

func (g connGroups) Get(_ context.Context, id domain.GroupID) (domain.Group, error) {
	return domain.Group{ID: id, AccountID: g.w.acc}, nil
}

func (g connGroups) IsMember(_ context.Context, id domain.GroupID, t domain.SubjectType, m domain.SubjectID) (bool, error) {
	return id == g.w.group && t == domain.SubjectTypeServiceAccount && g.w.members[m], nil
}

type connAB struct {
	repoab.ReaderIface
	w *connWorld
}

func (a connAB) GrantDelegations() repogd.ReaderIface { return connGD{w: a.w} }

type connGD struct {
	repogd.ReaderIface
	w *connWorld
}

func (g connGD) ActiveFor(context.Context, domain.AccountID, domain.ServiceAccountID) (domain.GrantDelegation, error) {
	return g.w.d, nil
}

func (g connGD) TargetObjectAccount(context.Context, domain.ResourceRef) (bool, domain.AccountID, error) {
	return true, g.w.acc, nil
}

// connRelations — хранилище отношений на том же пуле: соединение — на время вопроса.
type connRelations struct{ pool *connPool }

func (r connRelations) Check(context.Context, string, string, string) (bool, error) {
	r.pool.acquire()
	defer r.pool.release()
	return false, nil
}

func newConnWorld() *connWorld {
	w := &connWorld{
		acc:       domain.AccountID(ids.NewID(domain.PrefixAccount)),
		owner:     domain.UserID(ids.NewID(domain.PrefixUser)),
		delegate:  domain.ServiceAccountID(ids.NewID(domain.PrefixServiceAccount)),
		subjectSA: domain.ServiceAccountID(ids.NewID(domain.PrefixServiceAccount)),
		group:     domain.GroupID(ids.NewID(domain.PrefixGroup)),
		role:      domain.RoleID(ids.NewID(domain.PrefixRole)),
		members:   map[domain.SubjectID]bool{},
	}
	w.d = domain.GrantDelegation{
		ID:           domain.GrantDelegationID(ids.NewID(domain.PrefixGrantDelegation)),
		AccountID:    w.acc,
		DelegateID:   w.delegate,
		RoleIDs:      []domain.RoleID{w.role},
		TargetTypes:  []string{"registry.registries"},
		SubjectTypes: []domain.SubjectType{domain.SubjectTypeServiceAccount, domain.SubjectTypeGroup},
		Module:       "registry",
		Status:       domain.GrantDelegationActive,
		DelegatedBy:  domain.GrantDelegationActor{Type: "user", ID: string(w.owner)},
	}
	return w
}

func (w *connWorld) binding(s domain.Subject) domain.AccessBinding {
	return domain.AccessBinding{
		RoleID:       w.role,
		ResourceType: "account",
		ResourceID:   string(w.acc),
		Target:       domain.AccessTarget{Resources: []domain.ResourceRef{{Type: "registry.registries", ID: "reg-conn"}}},
		Subjects:     []domain.Subject{s},
	}
}

func asDelegate(w *connWorld) context.Context {
	return operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "service_account", ID: string(w.delegate)})
}

// SD-986-C1 — выдача делегатом держит не больше одного соединения пула за раз.
func TestDelegatedGrant_SD986C1_HoldsOneConnectionAtATime(t *testing.T) {
	w := newConnWorld()
	pool := &connPool{}
	p := NewDelegatedGrantPath(&connRepo{pool: pool, w: w}, connRelations{pool: pool})

	gdl, err := delegatedGrantAuthority(asDelegate(w), p, w.binding(domain.Subject{
		Type: domain.SubjectTypeServiceAccount, ID: domain.SubjectID(w.subjectSA)}), false)

	require.NoError(t, err, "контроль: выдача делегатом в пределах делегирования принята (Д3 — владелец)")
	require.Equal(t, w.d.ID, gdl, "контроль: ссылка выдачи — делегирование D")
	require.Zero(t, pool.held, "соединения пути возвращены в пул")
	require.Equalf(t, 1, pool.peak,
		"делегированный путь держал %d соединений пула разом: вопрос о праве делегирующего задан при открытой читающей транзакции", pool.peak)
}
