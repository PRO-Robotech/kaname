// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package user

// list_scope_test.go — единая модель видимости (паритет с
// account/serviceAccount/role List). ListUsersUseCase сужает страницу
// ОБЪЕДИНЕНИЕМ отношений `viewer` ∪ `v_list` на iam_user:
//
//	видим(iam_user) ⟺ вопрос о доступе отвечает «да» на viewer ЛИБО на v_list
//
// Здесь стояло `ListObjects(subj, …)` — ПЕРЕЧИСЛЕНИЕ объектов у чужого хранилища
// отношений. Ни этого RPC, ни хранилища в дереве нет (S6), а само перечисление
// снято раньше и по своей причине: у него был жёсткий серверный предел и не было
// продолжения, поэтому объекты сверх предела становились владельцу невидимы
// НАВСЕГДА при живых правах. Сегодня страница читается курсором из своей базы, а
// права проверяются пообъектно на идентификаторах ЭТОЙ страницы
// (`internal/authzfilter`).
//
// Прежняя membership-over-show модель (любой член аккаунта видел ВСЕХ user'ов
// аккаунта) устранена (T3.3 D-5): видны только user'ы с пообъектным правом
// viewer/v_list (включая себя — через самокортеж, ветвью viewer). Инварианты:
// anonymous → empty (до вопроса о доступе); отказ источника вердикта →
// Unavailable (fail-closed); cluster-admin/operator/owner покрыты веткой viewer
// (каскад уровней); не-forwarded principal (system/bootstrap fallback) — тоже
// anonymous → empty.

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
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/service_account"
	repouser "github.com/PRO-Robotech/kaname/internal/repo/kaname/user"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/visibility"
)

const (
	listAcctA    = "acc0000000000000aaaa"
	listMemberID = "usr0000000000000memb"
	listUser1ID  = "usr0000000000000one0"
	listUser2ID  = "usr0000000000000two0"
)

// ── fakes ────────────────────────────────────────────────────────────────────

// scopeUserRepo — fake Repo; `users` is what Users.List returns (the page the
// use-case then intersects with the FGA visible-set).
type scopeUserRepo struct {
	users []domain.User
}

func (f *scopeUserRepo) Reader(context.Context) (kanamerepo.Reader, error) {
	return &scopeUserReader{parent: f}, nil
}
func (f *scopeUserRepo) Writer(context.Context) (kanamerepo.Writer, error) { return nil, nil }
func (f *scopeUserRepo) Close()                                            {}

type scopeUserReader struct{ parent *scopeUserRepo }

func (r *scopeUserReader) Accounts() account.ReaderIface                { return nil }
func (r *scopeUserReader) Projects() project.ReaderIface                { return nil }
func (r *scopeUserReader) Users() repouser.ReaderIface                  { return &scopeUserRdr{parent: r.parent} }
func (r *scopeUserReader) ServiceAccounts() service_account.ReaderIface { return nil }
func (r *scopeUserReader) Groups() group.ReaderIface                    { return nil }
func (r *scopeUserReader) Roles() role.ReaderIface                      { return nil }
func (r *scopeUserReader) AccessBindings() access_binding.ReaderIface   { return nil }
func (r *scopeUserReader) Commit(context.Context) error                 { return nil }
func (r *scopeUserReader) Rollback(context.Context) error               { return nil }

type scopeUserRdr struct{ parent *scopeUserRepo }

func (r *scopeUserRdr) Get(context.Context, domain.UserID) (domain.User, error) {
	return domain.User{}, stderrors.New("not found")
}
func (r *scopeUserRdr) GetByEmail(context.Context, domain.Email) (domain.User, error) {
	return domain.User{}, stderrors.New("not found")
}
func (r *scopeUserRdr) List(context.Context, repouser.ListFilter) ([]domain.User, string, error) {
	return r.parent.users, "", nil
}
func (r *scopeUserRdr) GetByAccountEmail(context.Context, domain.AccountID, domain.Email) (domain.User, error) {
	return domain.User{}, stderrors.New("not found")
}
func (r *scopeUserRdr) FindPendingByEmail(context.Context, domain.Email) ([]domain.User, error) {
	return nil, nil
}
func (r *scopeUserRdr) FindActiveByExternalID(context.Context, domain.ExternalSubject) ([]domain.User, error) {
	return nil, nil
}
func (r *scopeUserRdr) FindByExternalIDInStatuses(context.Context, domain.ExternalSubject, []domain.InviteStatus) ([]domain.User, error) {
	return nil, nil
}
func (r *scopeUserRdr) FindActiveByEmail(context.Context, domain.Email) ([]domain.User, error) {
	return nil, nil
}
func (r *scopeUserRdr) ListAccountsForUser(context.Context, domain.UserID) ([]domain.AccountID, error) {
	return nil, nil
}

// fgaObjectID extracts the bare id from an FGA object string
// ("iam_user:x" → "x"). Shared by the package's per-object Check stubs.
func fgaObjectID(object string) string {
	for i := 0; i < len(object); i++ {
		if object[i] == ':' {
			return object[i+1:]
		}
	}
	return object
}

// userUnionFGAStub — дублёр источника вердикта, различающий ОТНОШЕНИЕ (viewer
// против v_list): он и есть предмет этого файла.
//
// У него стоял ещё метод `ListObjects` — перечисление объектов у чужого
// хранилища. Порт его больше не объявляет, прод-код не зовёт, и держать его тут
// значило бы дать дублёру способность ШИРЕ настоящего: фильтр страницы выбирает
// путь, спрашивая у переданного ему значения, какие способности оно предлагает,
// — и лишний метод молча увёл бы пробы на путь, которым продукт не ходит.
type userUnionFGAStub struct {
	clients.RelationQueries
	mu    sync.Mutex // the per-object Check port is called concurrently
	idsBy map[string]map[string][]string
	err   error
	calls map[string]int
}

func newUserUnionFGAStub() *userUnionFGAStub {
	return &userUnionFGAStub{idsBy: map[string]map[string][]string{}, calls: map[string]int{}}
}

func (s *userUnionFGAStub) set(relation, subject string, ids []string) {
	if s.idsBy[relation] == nil {
		s.idsBy[relation] = map[string][]string{}
	}
	s.idsBy[relation][subject] = ids
}

// CheckWithContext — the DIRECT per-object oracle the use-case now asks instead
// of enumerating (internal/authzfilter), answering from the SAME (relation,
// subject) id-sets, so these tests' fixtures and intent are unchanged.
func (s *userUnionFGAStub) CheckWithContext(_ context.Context, subject, relation, object string,
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

func userIDs(in []domain.User) []string {
	out := make([]string, 0, len(in))
	for _, u := range in {
		out = append(out, string(u.ID))
	}
	return out
}

func ctxListUser(id string) context.Context {
	return operations.WithPrincipal(context.Background(), operations.Principal{Type: "user", ID: id})
}

func seedListUsers() []domain.User {
	return []domain.User{
		{ID: domain.UserID(listUser1ID), AccountID: listAcctA},
		{ID: domain.UserID(listUser2ID), AccountID: listAcctA},
	}
}

// ── tests ──────────────────────────────────────────────────────────────────

// Страница не может быть ШИРЕ чтения: держатель яруса (или объектного грант-селектора
// `v_list`) не должен получать строку, которую его же Get не отдаст. Отрицание идёт В
// ПАРЕ с положительным — одиночное «не видно» зеленеет сильнее всего тогда, когда
// фильтр не показывает вообще ничего.
//
// Собственная запись вызывающего сюда не попадает: она держится ПОЛОМ, который вообще
// не спрашивает модель (TestListUsers_SelfFloor_NoFGATuple), и сужением не задета.
func TestListUsers_PageMembershipRequiresReadRelation(t *testing.T) {
	for _, tc := range []struct {
		name     string
		relation string
		wantSeen []string
	}{
		{name: "ярус — Get откажет", relation: "viewer", wantSeen: nil},
		{name: "объектный грант-селектор", relation: "v_list", wantSeen: nil},
		{name: "отношение, которым гейтится Get", relation: "v_get", wantSeen: []string{listUser1ID}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &scopeUserRepo{users: seedListUsers()}
			fga := newUserUnionFGAStub()
			fga.set(tc.relation, "user:"+listMemberID, []string{listUser1ID})

			uc := NewListUsersUseCase(repo).WithRelationStore(fga)
			out, _, err := uc.Execute(ctxListUser(listMemberID), repouser.ListFilter{AccountID: listAcctA})
			require.NoError(t, err)
			require.ElementsMatch(t, tc.wantSeen, userIDs(out),
				"в странице ровно те пользователи, которых вызывающий вправе прочитать по id")
		})
	}
}

// T3.3-MAT-02 — membership-over-show устранен: член аккаунта БЕЗ per-object гранта
// НЕ видит user'ов аккаунта (раньше видел всех).
func TestListUsers_MembershipWithoutGrant_Hidden(t *testing.T) {
	repo := &scopeUserRepo{users: seedListUsers()}
	fga := newUserUnionFGAStub() // no grants at all
	uc := NewListUsersUseCase(repo).WithRelationStore(fga)
	out, _, err := uc.Execute(ctxListUser(listMemberID), repouser.ListFilter{AccountID: listAcctA})
	require.NoError(t, err)
	assert.Empty(t, out, "membership-over-show устранен: без per-object гранта user не виден")
}

// T3.3-MAT-02 — self-floor: member видит себя (self-tuple резолвит viewer-ветку).
func TestListUsers_SelfVisible(t *testing.T) {
	repo := &scopeUserRepo{users: []domain.User{
		{ID: domain.UserID(listMemberID), AccountID: listAcctA},
		{ID: domain.UserID(listUser1ID), AccountID: listAcctA},
	}}
	fga := newUserUnionFGAStub()
	// self-tuple iam_user:<member>#subject@user:<member> резолвится в viewer-ветку.
	fga.set("viewer", "user:"+listMemberID, []string{listMemberID})
	uc := NewListUsersUseCase(repo).WithRelationStore(fga)
	out, _, err := uc.Execute(ctxListUser(listMemberID), repouser.ListFilter{AccountID: listAcctA})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{listMemberID}, userIDs(out),
		"member видит себя (self-floor); чужого user'а без гранта — нет")
}

// Self-floor — code-level, НЕ зависит от FGA-материализации: юзер БЕЗ единого
// viewer/v_list-гранта на себя (отсутствует/протух subject self-tuple) все равно
// видит собственную запись. Паритет с GetUser.IsSelf. Гонять с ПУСТЫМ FGA-стабом:
// без code-floor visible пуст → self отфильтровывается → юзер не видит даже себя.
func TestListUsers_SelfFloor_NoFGATuple(t *testing.T) {
	repo := &scopeUserRepo{users: []domain.User{
		{ID: domain.UserID(listMemberID), AccountID: listAcctA},
		{ID: domain.UserID(listUser1ID), AccountID: listAcctA},
	}}
	fga := newUserUnionFGAStub() // пусто: ни viewer, ни v_list, ни self-tuple
	uc := NewListUsersUseCase(repo).WithRelationStore(fga)
	out, _, err := uc.Execute(ctxListUser(listMemberID), repouser.ListFilter{AccountID: listAcctA})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{listMemberID}, userIDs(out),
		"self-floor: юзер видит себя даже без FGA-гранта; чужого без гранта — нет")
}

// Self-floor НЕ применяется к service-account-принципалу (SA — не iam_user): SA без
// гранта не «видит себя» в списке user'ов.
func TestListUsers_SelfFloor_ServiceAccountPrincipal_NoSelf(t *testing.T) {
	repo := &scopeUserRepo{users: seedListUsers()}
	fga := newUserUnionFGAStub()
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "service_account", ID: listUser1ID})
	uc := NewListUsersUseCase(repo).WithRelationStore(fga)
	out, _, err := uc.Execute(ctx, repouser.ListFilter{AccountID: listAcctA})
	require.NoError(t, err)
	assert.Empty(t, out, "SA-принципал не получает user-self-floor")
}

// T3.3-AUTHZ-01 — anonymous → empty ДО любого FGA-вызова.
func TestListUsers_AnonymousEmpty(t *testing.T) {
	repo := &scopeUserRepo{users: seedListUsers()}
	fga := newUserUnionFGAStub()
	uc := NewListUsersUseCase(repo).WithRelationStore(fga)
	out, _, err := uc.Execute(context.Background(), repouser.ListFilter{AccountID: listAcctA})
	require.NoError(t, err)
	assert.Empty(t, out)
	assert.Zero(t, fga.calls["viewer"], "anonymous short-circuits before FGA")
}

// Не-переданная личность (край не передал заголовки `x-kacho-principal-*` →
// PrincipalFromContext отдаёт запасного system/bootstrap) относится
// authzguard.IsAnonymous к анонимным → пустая страница ДО любого обращения к
// модели. Паритет с group/service_account.
//
// Проба заведена задачей #648 и на момент заведения была ЗЕЛЁНОЙ на неизменённом
// коде — это и есть доказательство того, что стоявшая ниже по функции ветка
// «системный бутстрап → несужённая страница» не исполнялась ни при каком входе:
// замыкание по личности стоит выше и относит бутстрап к анонимным. Ветка снята,
// проба осталась — она держит инвариант вперёд.
func TestListUsers_SystemBootstrapFallback_FailClosed(t *testing.T) {
	repo := &scopeUserRepo{users: seedListUsers()}
	fga := newUserUnionFGAStub()
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: domain.PrincipalTypeSystem, ID: domain.PrincipalIDBootstrap})
	uc := NewListUsersUseCase(repo).WithRelationStore(fga)
	out, _, err := uc.Execute(ctx, repouser.ListFilter{AccountID: listAcctA})
	require.NoError(t, err)
	assert.Empty(t, out, "system/bootstrap fallback → anonymous → empty (fail-closed)")
	assert.Zero(t, fga.calls["viewer"], "short-circuits before FGA")
}

// T3.3-AUTHZ-02 — FGA-ошибка на любой relation → Unavailable (fail-closed).
func TestListUsers_FGAUnavailable_FailClosed(t *testing.T) {
	repo := &scopeUserRepo{users: seedListUsers()}
	fga := newUserUnionFGAStub()
	// Текст ошибки — ЛЮБОЙ: предмет пробы в том, что отказ ИСТОЧНИКА вердикта
	// превращается в Unavailable, а не в пустую страницу. Здесь стояло имя
	// снятого RPC внешнего движка — оно называло механизм, которого нет, и
	// следующий читатель искал бы его в дереве.
	fga.err = stderrors.New("источник вердикта недоступен")
	uc := NewListUsersUseCase(repo).WithRelationStore(fga)
	out, _, err := uc.Execute(ctxListUser(listMemberID), repouser.ListFilter{AccountID: listAcctA})
	require.Error(t, err)
	require.Empty(t, out)
	st, ok := status.FromError(err)
	require.True(t, ok, "want grpc status; got %v", err)
	require.Equal(t, codes.Unavailable, st.Code())
}

// BatchCheckWithContext — the batched door onto the SAME oracle CheckWithContext
// answers from, so a verdict cannot depend on which door the filter chose.
//
// It is not optional politeness: authzfilter takes its batched path whenever the
// checker offers this method, so a stub that omitted it would leave every test in
// this file exercising a code path production does not take. It refuses an
// over-cap partition the way the relation store refuses one — an error, never a
// trim — so the stub is never more permissive than the thing it stands in for.
func (s *userUnionFGAStub) BatchCheckWithContext(ctx context.Context, subject, relation string,
	objects []string, condCtx map[string]any) ([]bool, error) {
	if len(objects) > authzfilter.MaxBatchChecksPerRequest {
		return nil, fmt.Errorf("batchCheck received %d checks, the maximum allowed is %d",
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
func (r *scopeUserReader) Visibility() visibility.ReaderIface { return usrUnrestrictedVisibility{} }

// usrUnrestrictedVisibility — «кандидаты не сужаются»: Candidates(...) вернёт nil,
// и репозиторий не получит ни одного предиката отбора.
type usrUnrestrictedVisibility struct{}

func (usrUnrestrictedVisibility) ScopeOf(_ context.Context, _ visibility.Subject) (visibility.Scope, error) {
	return visibility.Scope{Unrestricted: true, GrantedObjects: map[string][]string{}}, nil
}

// MembershipExists — дублёр не отвечает на вопрос о членстве: предмет этой
// пробы другой, и подставной ответ был бы утверждением, которого никто не
// делал. Единственный прод-вызывающий — разрешение осиротевшей операции
// исключения из аккаунта (#1127).
func (*scopeUserRdr) MembershipExists(context.Context, domain.UserID, domain.AccountID) (bool, error) {
	return false, nil
}
