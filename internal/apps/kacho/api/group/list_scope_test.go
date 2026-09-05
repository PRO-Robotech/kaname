// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package group

// list_scope_test.go — единая модель видимости GroupService.List (паритет с
// account/project/service_account/role List). Страница фильтруется ПООБЪЕКТНЫМ
// вопросом о том отношении, которым гейтится одиночное чтение этого же типа:
//
//	видна(iam_group:<id>) = Check(субъект, "v_get", "iam_group:"+<id>)
//
// Предикат объявлен ровно один раз — `authzfilter.RelationsFor("iam_group")`, —
// и именно поэтому страница не может разойтись с чтением по id.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЗДЕСЬ СТОЯЛО И ПОЧЕМУ ЭТО ПЕРЕСТАЛО ОПИСЫВАТЬ ДЕЙСТВИТЕЛЬНОСТЬ
//
// Прежняя редакция объявляла предикат ОБЪЕДИНЕНИЕМ двух перечислений внешнего
// движка:
//
//	ListObjects(subj,"viewer","iam_group") ∪ ListObjects(subj,"v_list","iam_group")
//
// Ложным стало и то, и другое. Перечисления нет: движок снят (стадия S6), и
// `clients.RelationQueries` перечисления объектов не несёт вовсе — есть вопрос об
// объекте, вопрос о странице объектов и перечисление СУБЪЕКТОВ. Объединения тоже
// нет: ярус (`viewer`) и объектный грант-селектор (`v_list`) страницу НЕ
// открывают, иначе вызывающий получал бы строку, которую его же Get не отдаст.
// Это утверждает проба в этом же файле (TestListGroups_PageMembershipRequiresReadRelation)
// — то есть заголовок противоречил собственному тексту ниже.
//
// Что остаётся верным и ради чего абзац не выкинут: ПРИЧИНА, по которой
// перечисление снято. Оно имело серверный предел и не имело продолжения, поэтому
// строка сверх предела становилась своему владельцу невидимой НАВСЕГДА при живых
// правах — разбор в package doc `internal/authzfilter`.
//
// Устраняет over-show: прежде List возвращал ВСЕ группы аккаунта любому держателю
// account#v_list (account-tier не каскадит в iam_group — DIRECT-only).
// Инварианты: anonymous → empty (до единого вопроса о доступе); не-forwarded
// principal (system/bootstrap fallback) → тоже empty (fail-closed); отказ формы,
// отвечающей на вопрос о доступе, → Unavailable (fail-closed).

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

	"github.com/PRO-Robotech/kacho-iam/internal/authzfilter"
	"github.com/PRO-Robotech/kacho-iam/internal/clients"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	kachorepo "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho"
	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/access_binding"
	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/account"
	repogroup "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/group"
	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/project"
	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/role"
	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/service_account"
	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/user"
	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/visibility"
)

const (
	grpScopeAcct = "acc0000000000000aaaa"
	grpScopeUser = "usr0000000000000user"
)

// ── fakes ────────────────────────────────────────────────────────────────────

// scopeGroupRepo — fake Repo; `groups` is what Groups.List returns (the page the
// use-case then intersects with the FGA visible-set).
type scopeGroupRepo struct {
	groups []domain.Group
}

func (f *scopeGroupRepo) Reader(context.Context) (kachorepo.Reader, error) {
	return &scopeGroupReader{parent: f}, nil
}
func (f *scopeGroupRepo) Writer(context.Context) (kachorepo.Writer, error) { return nil, nil }
func (f *scopeGroupRepo) Close()                                           {}

type scopeGroupReader struct{ parent *scopeGroupRepo }

func (r *scopeGroupReader) Accounts() account.ReaderIface { return nil }
func (r *scopeGroupReader) Projects() project.ReaderIface { return nil }
func (r *scopeGroupReader) Users() user.ReaderIface       { return nil }
func (r *scopeGroupReader) ServiceAccounts() service_account.ReaderIface {
	return nil
}
func (r *scopeGroupReader) Groups() repogroup.ReaderIface {
	return &scopeGroupRdr{parent: r.parent}
}
func (r *scopeGroupReader) Roles() role.ReaderIface                    { return nil }
func (r *scopeGroupReader) AccessBindings() access_binding.ReaderIface { return nil }
func (r *scopeGroupReader) Commit(context.Context) error               { return nil }
func (r *scopeGroupReader) Rollback(context.Context) error             { return nil }

type scopeGroupRdr struct{ parent *scopeGroupRepo }

func (r *scopeGroupRdr) Get(context.Context, domain.GroupID) (domain.Group, error) {
	return domain.Group{}, nil
}
func (r *scopeGroupRdr) List(context.Context, repogroup.ListFilter) ([]domain.Group, string, error) {
	return r.parent.groups, "", nil
}
func (r *scopeGroupRdr) ListMembers(context.Context, domain.GroupID, repogroup.MemberPage) ([]domain.GroupMember, string, error) {
	return nil, "", nil
}
func (r *scopeGroupRdr) IsMember(context.Context, domain.GroupID, domain.SubjectType, domain.SubjectID) (bool, error) {
	return false, nil
}

// fgaObjectID extracts the bare id from an FGA object string
// ("iam_group:x" → "x"). Shared by the package's per-object Check stubs.
func fgaObjectID(object string) string {
	for i := 0; i < len(object); i++ {
		if object[i] == ':' {
			return object[i+1:]
		}
	}
	return object
}

// groupUnionFGAStub — дублёр clients.RelationQueries, отвечающий по отношению.
//
// Имя несёт «Union» по историческим причинам и НЕ описывает предикат: страница
// судится одним отношением (`v_get`), а объединения ярусов больше нет — см.
// заголовок файла. Идентификатор оставлен, потому что его держит соседний файл
// пакета (list_pagination_order_test.go); ложным было УТВЕРЖДЕНИЕ в комментарии,
// и правится оно, а не имя.
type groupUnionFGAStub struct {
	clients.RelationQueries
	mu    sync.Mutex // the per-object Check port is called concurrently
	idsBy map[string]map[string][]string
	err   error
	calls map[string]int
}

func newGroupUnionFGAStub() *groupUnionFGAStub {
	return &groupUnionFGAStub{idsBy: map[string]map[string][]string{}, calls: map[string]int{}}
}

func (s *groupUnionFGAStub) set(relation, subject string, ids []string) {
	if s.idsBy[relation] == nil {
		s.idsBy[relation] = map[string][]string{}
	}
	s.idsBy[relation][subject] = ids
}

// asked — сколько вопросов о доступе задано ВСЕГО, по всем отношениям.
//
// Считается отдельно от `calls`, и это не удобство. Пробы «спросили ли вообще»
// раньше смотрели в `calls["viewer"]` — счётчик отношения, которым страница НЕ
// судится (предикат членства для iam_group — `v_get`). У такого счётчика нет
// ПРОИЗВОДИТЕЛЯ: ноль в нём истинен при любом поведении use-case'а, в том числе
// при полностью снятом коротком замыкании. Сумма по всем отношениям краснеет на
// первом же заданном вопросе.
func (s *groupUnionFGAStub) asked() int {
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
func (s *groupUnionFGAStub) CheckWithContext(_ context.Context, subject, relation, object string,
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

func grpIDs(in []domain.Group) []string {
	out := make([]string, 0, len(in))
	for _, g := range in {
		out = append(out, string(g.ID))
	}
	return out
}

func ctxGrpUser(id string) context.Context {
	return operations.WithPrincipal(context.Background(), operations.Principal{Type: "user", ID: id})
}

// ── tests ──────────────────────────────────────────────────────────────────

// Exact-set: grant на ПОДМНОЖЕСТВО групп аккаунта → List возвращает РОВНО это
// подмножество (over-show устранен: неграненые группы скрыты). Зеркалит newman
// IAM-SET-GRP-LABEL-EXACT-OK (M+ видимы, M−/baz скрыты).
func TestListGroups_ExactSet_OnlyGrantedSubset(t *testing.T) {
	repo := &scopeGroupRepo{groups: []domain.Group{
		{ID: "grp0000000000000aaaa", AccountID: grpScopeAcct},
		{ID: "grp0000000000000bbbb", AccountID: grpScopeAcct},
		{ID: "grp0000000000000cccc", AccountID: grpScopeAcct},
	}}
	fga := newGroupUnionFGAStub()
	fga.set("v_get", "user:"+grpScopeUser, []string{"grp0000000000000aaaa", "grp0000000000000bbbb"})

	uc := NewListGroupsUseCase(repo).WithRelationStore(fga)
	out, _, err := uc.Execute(ctxGrpUser(grpScopeUser), repogroup.ListFilter{AccountID: grpScopeAcct})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"grp0000000000000aaaa", "grp0000000000000bbbb"}, grpIDs(out),
		"List returns EXACTLY the readable subset; the ungranted group stays hidden")
}

// Страница не может быть ШИРЕ чтения: держатель яруса (или объектного грант-селектора
// `v_list`) не должен получать строку, которую его же Get не отдаст. Отрицание идёт В
// ПАРЕ с положительным — одиночное «не видно» зеленеет сильнее всего тогда, когда
// фильтр не показывает вообще ничего.
func TestListGroups_PageMembershipRequiresReadRelation(t *testing.T) {
	for _, tc := range []struct {
		name     string
		relation string
		wantSeen []string
	}{
		{name: "ярус — Get откажет", relation: "viewer", wantSeen: nil},
		{name: "объектный грант-селектор", relation: "v_list", wantSeen: nil},
		{name: "отношение, которым гейтится Get", relation: "v_get", wantSeen: []string{"grp0000000000000aaaa"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &scopeGroupRepo{groups: []domain.Group{
				{ID: "grp0000000000000aaaa", AccountID: grpScopeAcct},
				{ID: "grp0000000000000bbbb", AccountID: grpScopeAcct},
			}}
			fga := newGroupUnionFGAStub()
			fga.set(tc.relation, "user:"+grpScopeUser, []string{"grp0000000000000aaaa"})

			uc := NewListGroupsUseCase(repo).WithRelationStore(fga)
			out, _, err := uc.Execute(ctxGrpUser(grpScopeUser), repogroup.ListFilter{AccountID: grpScopeAcct})
			require.NoError(t, err)
			require.ElementsMatch(t, tc.wantSeen, grpIDs(out),
				"в странице ровно те группы, которые вызывающий вправе прочитать по id")
		})
	}
}

// over-show устранен: член аккаунта БЕЗ per-object гранта НЕ видит группу аккаунта
// (раньше account#v_list-держатель видел все группы).
func TestListGroups_MembershipWithoutGrant_Hidden(t *testing.T) {
	repo := &scopeGroupRepo{groups: []domain.Group{
		{ID: "grp0000000000000aaaa", AccountID: grpScopeAcct},
	}}
	fga := newGroupUnionFGAStub() // no grants at all
	uc := NewListGroupsUseCase(repo).WithRelationStore(fga)
	out, _, err := uc.Execute(ctxGrpUser(grpScopeUser), repogroup.ListFilter{AccountID: grpScopeAcct})
	require.NoError(t, err)
	assert.Empty(t, out, "без per-object гранта группа не видна (over-show устранен)")
}

// anonymous → empty ДО любого FGA-вызова (fail-closed).
func TestListGroups_AnonymousEmpty(t *testing.T) {
	repo := &scopeGroupRepo{groups: []domain.Group{
		{ID: "grp0000000000000aaaa", AccountID: grpScopeAcct},
	}}
	fga := newGroupUnionFGAStub()
	uc := NewListGroupsUseCase(repo).WithRelationStore(fga)
	out, _, err := uc.Execute(context.Background(), repogroup.ListFilter{AccountID: grpScopeAcct})
	require.NoError(t, err)
	assert.Empty(t, out)
	assert.Zero(t, fga.asked(), "anonymous замыкается ДО единого вопроса о доступе")
}

// Форма не ответила на любом отношении → Unavailable (fail-closed, никогда partial).
//
// «Не смог спросить» и «доступа нет» — разные миры: вернув пустую страницу,
// use-case выдал бы недоступность своей базы за законный отказ.
func TestListGroups_FGAUnavailable_FailClosed(t *testing.T) {
	repo := &scopeGroupRepo{groups: []domain.Group{
		{ID: "grp0000000000000aaaa", AccountID: grpScopeAcct},
	}}
	fga := newGroupUnionFGAStub()
	fga.err = stderrors.New("реляционная форма не ответила: соединение закрыто")
	uc := NewListGroupsUseCase(repo).WithRelationStore(fga)
	out, _, err := uc.Execute(ctxGrpUser(grpScopeUser), repogroup.ListFilter{AccountID: grpScopeAcct})
	require.Error(t, err)
	require.Empty(t, out)
	st, ok := status.FromError(err)
	require.True(t, ok, "want grpc status; got %v", err)
	require.Equal(t, codes.Unavailable, st.Code())
}

// non-forwarded principal (api-gateway не передал заголовки → system/bootstrap
// fallback) трактуется authzguard.IsAnonymous как anonymous → empty ДО FGA
// (fail-closed, паритет с account/project/role/SA List — без unfiltered-обхода).
func TestListGroups_SystemBootstrapFallback_FailClosed(t *testing.T) {
	repo := &scopeGroupRepo{groups: []domain.Group{
		{ID: "grp0000000000000aaaa", AccountID: grpScopeAcct},
		{ID: "grp0000000000000bbbb", AccountID: grpScopeAcct},
	}}
	fga := newGroupUnionFGAStub()
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: domain.PrincipalTypeSystem, ID: domain.PrincipalIDBootstrap})
	uc := NewListGroupsUseCase(repo).WithRelationStore(fga)
	out, _, err := uc.Execute(ctx, repogroup.ListFilter{AccountID: grpScopeAcct})
	require.NoError(t, err)
	assert.Empty(t, out, "system/bootstrap fallback → anonymous → empty (fail-closed)")
	assert.Zero(t, fga.asked(), "замыкается ДО единого вопроса о доступе")
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
// молча. Ошибка, а не усечение: короткий ответ неотличим от страницы отказов, а
// страница молчаливых отказов — ровно тот дефект вечной невидимости, против
// которого написан этот файл.
func (s *groupUnionFGAStub) BatchCheckWithContext(ctx context.Context, subject, relation string,
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
// (services/iam/internal/apps/kacho/api/listvisibility). nil здесь означает
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
// services/iam/internal/apps/kacho/api/listvisibility, где снисходительного
// дублёра нет ни с одной стороны именно потому, что предмет там — ПОРЯДОК между
// страницей и сужением.
func (r *scopeGroupReader) Visibility() visibility.ReaderIface { return grpUnrestrictedVisibility{} }

// grpUnrestrictedVisibility — «кандидаты не сужаются»: Candidates(...) вернёт nil,
// и репозиторий не получит ни одного предиката отбора.
type grpUnrestrictedVisibility struct{}

func (grpUnrestrictedVisibility) ScopeOf(_ context.Context, _ visibility.Subject) (visibility.Scope, error) {
	return visibility.Scope{Unrestricted: true, GrantedObjects: map[string][]string{}}, nil
}

// MembersOfGroups — предмет этой пробы не касается состава нескольких групп;
// дублёр отвечает пусто и говорит об этом, а не притворяется источником.
func (r *scopeGroupRdr) MembersOfGroups(context.Context, []domain.GroupID) ([]domain.GroupMember, []domain.GroupID, error) {
	return nil, nil, nil
}
