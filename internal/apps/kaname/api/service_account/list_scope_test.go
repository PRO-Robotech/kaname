// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package service_account

// list_scope_test.go — единая модель видимости (паритет с account/list_vlist_union).
// ListServiceAccountsUseCase фильтрует страницу ПООБЪЕКТНЫМ вопросом о том
// отношении, которым гейтится одиночное чтение этого же типа:
//
//	видна(iam_service_account:<id>) = Check(субъект, "v_get", "iam_service_account:"+<id>)
//
// Предикат объявлен ровно один раз — `authzfilter.RelationsFor(…)`, — поэтому
// страница не может разойтись с чтением по id.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЗДЕСЬ СТОЯЛО И ПОЧЕМУ ЭТО ПЕРЕСТАЛО ОПИСЫВАТЬ ДЕЙСТВИТЕЛЬНОСТЬ
//
// Прежняя редакция объявляла предикат ОБЪЕДИНЕНИЕМ двух перечислений внешнего
// движка:
//
//	ListObjects(subj,"viewer",…) ∪ ListObjects(subj,"v_list",…)
//
// Ложным стало и то, и другое. Перечисления объектов нет: движок снят (стадия S6),
// и `clients.RelationQueries` его не несёт вовсе. Объединения тоже нет: ярус
// (`viewer`) и объектный грант-селектор (`v_list`) страницу НЕ открывают — иначе
// вызывающий получал бы строку, которую его же Get не отдаст. Это утверждает
// проба в этом же файле (TestListServiceAccounts_PageMembershipRequiresReadRelation),
// то есть заголовок противоречил собственному тексту ниже.
//
// Что остаётся верным и ради чего абзац не выкинут: ПРИЧИНА снятия перечисления.
// Оно имело серверный предел и не имело продолжения, поэтому строка сверх предела
// становилась своему владельцу невидимой НАВСЕГДА при живых правах — разбор в
// package doc `internal/authzfilter`.
//
// Прежняя membership-over-show модель (любой член аккаунта видел ВСЕ SA аккаунта)
// устранена: видны только SA с per-object грантом. Инварианты: anonymous → empty
// (до единого вопроса о доступе); отказ формы → Unavailable (fail-closed);
// cluster-admin/operator покрыты полом system_viewer.

import (
	"context"
	stderrors "errors"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kaname/internal/authzfilter"
	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/account"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/group"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/project"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/role"
	reposa "github.com/PRO-Robotech/kaname/internal/repo/kaname/service_account"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/user"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/visibility"
)

const (
	scopeAcctA  = "acc0000000000000aaaa"
	scopeUserID = "usr0000000000000user"
)

// ── fakes ────────────────────────────────────────────────────────────────────

// scopeSARepo — fake Repo; `sas` is what ServiceAccounts.List returns (the page
// the use-case then intersects with the FGA visible-set).
type scopeSARepo struct {
	sas []domain.ServiceAccount
}

func (f *scopeSARepo) Reader(context.Context) (kanamerepo.Reader, error) {
	return &scopeSAReader{parent: f}, nil
}
func (f *scopeSARepo) Writer(context.Context) (kanamerepo.Writer, error) { return nil, nil }
func (f *scopeSARepo) Close()                                            {}

type scopeSAReader struct{ parent *scopeSARepo }

func (r *scopeSAReader) Accounts() account.ReaderIface { return nil }
func (r *scopeSAReader) Projects() project.ReaderIface { return nil }
func (r *scopeSAReader) Users() user.ReaderIface       { return nil }
func (r *scopeSAReader) ServiceAccounts() reposa.ReaderIface {
	return &scopeSARdr{parent: r.parent}
}
func (r *scopeSAReader) Groups() group.ReaderIface                  { return nil }
func (r *scopeSAReader) Roles() role.ReaderIface                    { return nil }
func (r *scopeSAReader) AccessBindings() access_binding.ReaderIface { return nil }
func (r *scopeSAReader) Commit(context.Context) error               { return nil }
func (r *scopeSAReader) Rollback(context.Context) error             { return nil }

type scopeSARdr struct{ parent *scopeSARepo }

func (r *scopeSARdr) Get(context.Context, domain.ServiceAccountID) (domain.ServiceAccount, error) {
	return domain.ServiceAccount{}, nil
}
func (r *scopeSARdr) List(context.Context, reposa.ListFilter) ([]domain.ServiceAccount, string, error) {
	return r.parent.sas, "", nil
}

// fgaObjectID extracts the bare id from an FGA object string
// ("iam_service_account:x" → "x"). Shared by the package's per-object Check stubs.
func fgaObjectID(object string) string {
	for i := 0; i < len(object); i++ {
		if object[i] == ':' {
			return object[i+1:]
		}
	}
	return object
}

// saUnionFGAStub — дублёр clients.RelationQueries, отвечающий по отношению.
//
// Имя несёт «Union» по историческим причинам и НЕ описывает предикат: страница
// судится одним отношением (`v_get`). Идентификатор оставлен, потому что его
// держит соседний файл пакета (list_pagination_order_test.go); ложным было
// УТВЕРЖДЕНИЕ в комментарии, и правится оно, а не имя.
type saUnionFGAStub struct {
	clients.RelationQueries
	mu    sync.Mutex // the per-object Check port is called concurrently
	idsBy map[string]map[string][]string
	err   error
	calls map[string]int
}

func newSAUnionFGAStub() *saUnionFGAStub {
	return &saUnionFGAStub{idsBy: map[string]map[string][]string{}, calls: map[string]int{}}
}

func (s *saUnionFGAStub) set(relation, subject string, ids []string) {
	if s.idsBy[relation] == nil {
		s.idsBy[relation] = map[string][]string{}
	}
	s.idsBy[relation][subject] = ids
}

// asked — сколько вопросов о доступе задано ВСЕГО, по всем отношениям.
//
// Считается отдельно от `calls`, и это не удобство. Пробы «спросили ли вообще»
// раньше смотрели в `calls["viewer"]` — счётчик отношения, которым страница НЕ
// судится (предикат членства — `v_get`). У такого счётчика нет ПРОИЗВОДИТЕЛЯ:
// ноль в нём истинен при любом поведении use-case'а, в том числе при полностью
// снятом коротком замыкании. Сумма по всем отношениям краснеет на первом же
// заданном вопросе.
func (s *saUnionFGAStub) asked() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, c := range s.calls {
		n += c
	}
	return n
}

// CheckWithContext — пообъектный вопрос, который use-case и задаёт, отвечающий из
// тех же наборов (отношение, субъект): фикстуры и намерение проб не менялись.
func (s *saUnionFGAStub) CheckWithContext(_ context.Context, subject, relation, object string,
	_ map[string]any) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls[relation]++
	if s.err != nil {
		return false, s.err
	}
	id := fgaObjectID(object)
	for _, got := range s.idsBy[relation][subject] {
		if got == id {
			return true, nil
		}
	}
	return false, nil
}

func saIDs(in []domain.ServiceAccount) []string {
	out := make([]string, 0, len(in))
	for _, sa := range in {
		out = append(out, string(sa.ID))
	}
	return out
}

func ctxUser(id string) context.Context {
	return operations.WithPrincipal(context.Background(), operations.Principal{Type: "user", ID: id})
}

// ── tests ──────────────────────────────────────────────────────────────────

// Страница не может быть ШИРЕ чтения: держатель яруса (или объектного грант-селектора
// `v_list`) не должен получать строку, которую его же Get не отдаст. Отрицание идёт В
// ПАРЕ с положительным — одиночное «не видно» зеленеет сильнее всего тогда, когда
// фильтр не показывает вообще ничего.
func TestListServiceAccounts_PageMembershipRequiresReadRelation(t *testing.T) {
	for _, tc := range []struct {
		name     string
		relation string
		wantSeen []string
	}{
		{name: "ярус — Get откажет", relation: "viewer", wantSeen: nil},
		{name: "объектный грант-селектор", relation: "v_list", wantSeen: nil},
		{name: "отношение, которым гейтится Get", relation: "v_get", wantSeen: []string{"sva0000000000000xxxx"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &scopeSARepo{sas: []domain.ServiceAccount{
				{ID: "sva0000000000000xxxx", AccountID: scopeAcctA},
				{ID: "sva0000000000000yyyy", AccountID: scopeAcctA},
			}}
			fga := newSAUnionFGAStub()
			fga.set(tc.relation, "user:"+scopeUserID, []string{"sva0000000000000xxxx"})

			uc := NewListServiceAccountsUseCase(repo).WithRelationStore(fga)
			out, _, err := uc.Execute(ctxUser(scopeUserID), reposa.ListFilter{AccountID: scopeAcctA})
			require.NoError(t, err)
			require.ElementsMatch(t, tc.wantSeen, saIDs(out),
				"в странице ровно те служебные учётки, которые вызывающий вправе прочитать по id")
		})
	}
}

// T3.3 — membership-over-show устранен: член аккаунта БЕЗ per-object гранта НЕ
// видит SA аккаунта (раньше видел все).
func TestListServiceAccounts_MembershipWithoutGrant_Hidden(t *testing.T) {
	repo := &scopeSARepo{sas: []domain.ServiceAccount{
		{ID: "sva0000000000000xxxx", AccountID: scopeAcctA},
	}}
	fga := newSAUnionFGAStub() // no grants at all
	uc := NewListServiceAccountsUseCase(repo).WithRelationStore(fga)
	out, _, err := uc.Execute(ctxUser(scopeUserID), reposa.ListFilter{AccountID: scopeAcctA})
	require.NoError(t, err)
	assert.Empty(t, out, "membership-over-show устранен: без per-object гранта SA не виден")
}

// T3.3 — anonymous → empty ДО любого FGA-вызова.
func TestListServiceAccounts_AnonymousEmpty(t *testing.T) {
	repo := &scopeSARepo{sas: []domain.ServiceAccount{
		{ID: "sva0000000000000xxxx", AccountID: scopeAcctA},
	}}
	fga := newSAUnionFGAStub()
	uc := NewListServiceAccountsUseCase(repo).WithRelationStore(fga)
	out, _, err := uc.Execute(context.Background(), reposa.ListFilter{AccountID: scopeAcctA})
	require.NoError(t, err)
	assert.Empty(t, out)
	assert.Zero(t, fga.asked(), "anonymous замыкается ДО единого вопроса о доступе")
}

// Не-переданная личность (край не передал заголовки `x-kacho-principal-*` →
// PrincipalFromContext отдаёт запасного system/bootstrap) относится
// authzguard.IsAnonymous к анонимным → пустая страница ДО любого обращения к
// модели. Паритет с group/user.
//
// Проба заведена задачей #648 и на момент заведения была ЗЕЛЁНОЙ на неизменённом
// коде — это и есть доказательство того, что стоявшая ниже по функции ветка
// «системный бутстрап → несужённая страница» не исполнялась ни при каком входе:
// замыкание по личности стоит выше и относит бутстрап к анонимным. Ветка снята,
// проба осталась — она держит инвариант вперёд.
func TestListServiceAccounts_SystemBootstrapFallback_FailClosed(t *testing.T) {
	repo := &scopeSARepo{sas: []domain.ServiceAccount{
		{ID: "sva0000000000000xxxx", AccountID: scopeAcctA},
	}}
	fga := newSAUnionFGAStub()
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: domain.PrincipalTypeSystem, ID: domain.PrincipalIDBootstrap})
	uc := NewListServiceAccountsUseCase(repo).WithRelationStore(fga)
	out, _, err := uc.Execute(ctx, reposa.ListFilter{AccountID: scopeAcctA})
	require.NoError(t, err)
	assert.Empty(t, out, "system/bootstrap fallback → anonymous → empty (fail-closed)")
	assert.Zero(t, fga.asked(), "замыкается ДО единого вопроса о доступе")
}

// T3.3 — форма не ответила на любом отношении → Unavailable (fail-closed, INV-7).
//
// «Не смог спросить» и «доступа нет» — разные миры: вернув пустую страницу,
// use-case выдал бы недоступность своей базы за законный отказ.
func TestListServiceAccounts_FGAUnavailable_FailClosed(t *testing.T) {
	repo := &scopeSARepo{sas: []domain.ServiceAccount{
		{ID: "sva0000000000000xxxx", AccountID: scopeAcctA},
	}}
	fga := newSAUnionFGAStub()
	fga.err = stderrors.New("реляционная форма не ответила: соединение закрыто")
	uc := NewListServiceAccountsUseCase(repo).WithRelationStore(fga)
	out, _, err := uc.Execute(ctxUser(scopeUserID), reposa.ListFilter{AccountID: scopeAcctA})
	require.Error(t, err)
	require.Empty(t, out)
	st, ok := status.FromError(err)
	require.True(t, ok, "want grpc status; got %v", err)
	require.Equal(t, codes.Unavailable, st.Code())
}

// BatchCheckWithContext — батчевая дверь к ТОМУ ЖЕ оракулу, из которого отвечает
// CheckWithContext, чтобы вердикт не зависел от того, какую дверь выбрал фильтр.
//
// Это не вежливость: authzfilter выбирает батчевый путь всякий раз, когда дублёр
// несёт этот метод, — дублёр без него оставил бы каждую пробу файла на пути,
// которым продукт не ходит.
//
// Отказ на партии крупнее authzfilter.MaxBatchChecksPerRequest держит дублёра от
// СНИСХОДИТЕЛЬНОСТИ к объявлению, за которое он стоит: это тот размер партии,
// который authzfilter объявляет и по которому режет страницу. Фильтр, переставший
// соблюдать собственное объявление, краснеет здесь, а не меняет форму запроса
// молча. Ошибка, а не усечение: короткий ответ неотличим от страницы отказов.
func (s *saUnionFGAStub) BatchCheckWithContext(ctx context.Context, subject, relation string,
	objects []string, condCtx map[string]any) ([]bool, error) {
	if len(objects) > authzfilter.MaxBatchChecksPerRequest {
		return nil, fmt.Errorf("партия из %d объектов крупнее объявленного размера %d",
			len(objects), authzfilter.MaxBatchChecksPerRequest)
	}
	out := make([]bool, len(objects))
	for i, object := range objects {
		allowed, err := s.CheckWithContext(ctx, subject, relation, object, condCtx)
		if err != nil {
			return nil, err
		}
		out[i] = allowed
	}
	return out, nil
}

// Visibility — дублёр структурных фактов о вызывающем не несёт: они читаются
// живой БД, и пробы, которые их проверяют, гоняют настоящий Postgres
// (services/iam/internal/apps/kaname/api/listvisibility). nil здесь означает
// «сузить нечем», и списочный use-case обязан на нём ОТКАЗАТЬ, а не листать
// ненаречённое.
// Visibility — структурные факты о вызывающем, объявленные НЕСУЖЁННЫМИ.
//
// Это НАМЕРЕННО снисходительнее продукта, и цена названа вслух: строк выдачи у
// этой фикстуры нет вовсе (её гранты живут только в дублёре стора отношений),
// поэтому назвать кандидатов она не может — а сузив набор до пустого, вернула бы
// пустую страницу везде и стёрла бы ровно то, о чём эти пробы спрашивают.
//
// Отсюда граница: предмет проб этого пакета — ВЕРДИКТ (каким отношением судится
// строка страницы, как ведут себя полы, что происходит на отказе стора). ОТБОР
// кандидатов они не проверяют и проверять не могут; он проверяется на настоящем
// Postgres и настоящей модели прав —
// services/iam/internal/apps/kaname/api/listvisibility, где снисходительного
// дублёра нет ни с одной стороны именно потому, что предмет там — ПОРЯДОК между
// страницей и сужением.
func (r *scopeSAReader) Visibility() visibility.ReaderIface { return saUnrestrictedVisibility{} }

// saUnrestrictedVisibility — «кандидаты не сужаются»: Candidates(...) вернёт nil,
// и репозиторий не получит ни одного предиката отбора.
type saUnrestrictedVisibility struct{}

func (saUnrestrictedVisibility) ScopeOf(_ context.Context, _ visibility.Subject) (visibility.Scope, error) {
	return visibility.Scope{Unrestricted: true, GrantedObjects: map[string][]string{}}, nil
}
