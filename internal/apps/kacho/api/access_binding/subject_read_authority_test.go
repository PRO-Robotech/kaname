// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// subject_read_authority_test.go — ДВЕ полосы чтения выдач субъекта решают
// допуск ОДНИМ предикатом, и страница каждой сужается построчно (#1352, #1354).
//
// # Предмет
//
// `ListBySubject` и `ListSubjectPrivileges` отвечают на ОДИН вопрос — «какие
// выдачи есть у названного субъекта», — и оба принимают `subject_type` +
// `subject_id` без обязательного аккаунта. Допуск у них был РАЗНЫЙ: первый
// требовал БЫТЬ субъектом, второй допускал ещё и распорядителя домашнего
// аккаунта. Наблюдаемое следствие: делегированный распорядитель читал выдачи
// сотрудника своего аккаунта одним глаголом и не читал вторым — ответ на один
// вопрос зависел от того, какой глагол выбран.
//
// # Почему проба СРАВНИВАЕТ ПОЛОСЫ, а не проверяет каждую
//
// Односторонняя проба («второй глагол допускает распорядителя») зеленеет при
// ЛЮБОМ расхождении: она ничего не утверждает о первом. Расхождение же и есть
// предмет — обе полосы валидны по отдельности, неверна их РАЗНИЦА
// (`architecture.md` §«Параллельные полосы одного механизма обязаны сверяться
// МЕЖДУ СОБОЙ»). Поэтому исход снимается с ОБОИХ глаголов на одном и том же
// вызывающем, одной и той же фикстуре, и утверждается их СОВПАДЕНИЕ.
//
// Перепись при этом печатает ДВЕ величины — «полос N · совпало M», — потому что
// одно число скрывает ровно тот случай, ради которого проба заведена.
//
// # Отрицание — только в паре с положительным
//
// «Совпали» зеленеет и тогда, когда оба глагола отказывают ВСЕМ: сломанный
// продукт совпадает сам с собой лучше исправного. Поэтому у таблицы есть
// положительный контроль (кто-то допущен) и отрицательный (кто-то отвергнут);
// вырождение любой половины — отказ.

import (
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho-iam/internal/clients"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	repoab "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/access_binding"
)

// Выдачи субъекта usr-MEMBER: одна в его домашнем аккаунте acc-A, вторая — в
// чужом acc-B. Идентификаторы общие для ОБОИХ глаголов: сравнивать полосы можно
// только на одном и том же предмете.
const (
	srBindHome    = "acb0000000000home02"
	srBindForeign = "acb00000000foreign2"
)

// srRepo — общая фикстура обеих полос: субъект usr-MEMBER (дом acc-A) с двумя
// выдачами, видимыми ОБОИМ чтениям — сырым биндингом и обогащённой привилегией.
func srRepo() *abFakeRepo {
	repo := spRepo()
	repo.seedSubjectPrivileges([]domain.SubjectPrivilege{
		spPriv(srBindHome, "rol_v", "viewer", "account", spAccA, domain.ScopeAccount),
		spPriv(srBindForeign, "rol_e", "editor", "account", spAccB, domain.ScopeAccount),
	})
	seedABListBySubject(repo, []domain.AccessBinding{
		{ID: srBindHome, ResourceType: "account", ResourceID: spAccA,
			SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(spMemberID)},
		{ID: srBindForeign, ResourceType: "account", ResourceID: spAccB,
			SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(spMemberID)},
	})
	return repo
}

// srAdmitted — допустил ли глагол вызывающего. Различается ровно отказ в правах:
// всё остальное (недоступность, негодный ввод) допуском не является и обязано
// добраться до утверждения, а не быть свёрнутым в «нет».
func srAdmitted(t *testing.T, err error) bool {
	t.Helper()
	switch {
	case err == nil:
		return true
	case status.Code(err) == codes.PermissionDenied:
		return false
	default:
		t.Fatalf("исход не является ни допуском, ни отказом в правах: %v", err)
		return false
	}
}

// srBindingIDs — идентификаторы выдач сырого чтения, в порядке ответа.
func srBindingIDs(rows []domain.AccessBinding) []string {
	out := make([]string, 0, len(rows))
	for _, b := range rows {
		out = append(out, string(b.ID))
	}
	return out
}

// ── НЕСУЩАЯ ПРОБА #1352: один допуск, два глагола ───────────────────────────

func TestSubjectReads_1352_BothVerbsAdmitTheSameCallers(t *testing.T) {
	type row struct {
		name      string
		callerID  string
		relations clients.RelationStore
		queries   *abQueriesStub
		cluster   bool
		admitted  bool
	}
	// Модель прав: распорядитель acc-A выводит `v_get` на выдаче в acc-A через
	// `super_admin from account`; на выдаче в acc-B — не выводит ниоткуда.
	adminQueries := func() *abQueriesStub {
		q := newABQueriesStub()
		q.set("v_get", "user:"+spAdminID, []string{srBindHome})
		return q
	}
	ownerQueries := func() *abQueriesStub {
		q := newABQueriesStub()
		q.set("v_get", "user:"+spOwnerID, []string{srBindHome})
		return q
	}
	rows := []row{
		{name: "сам субъект", callerID: spMemberID,
			relations: &denyingFGA{}, queries: newABQueriesStub(), admitted: true},
		{name: "владелец домашнего аккаунта", callerID: spOwnerID,
			relations: &denyingFGA{}, queries: ownerQueries(), admitted: true},
		{name: "делегированный распорядитель аккаунта", callerID: spAdminID,
			relations: &scopedFGA{allow: map[string]bool{"admin|account:" + spAccA: true}},
			queries:   adminQueries(), admitted: true},
		{name: "администратор облака", callerID: spOtherID,
			relations: onlyClusterAdmin(), queries: newABQueriesStub(), cluster: true, admitted: true},
		{name: "посторонний", callerID: spOtherID,
			relations: &denyingFGA{}, queries: newABQueriesStub(), admitted: false},
	}

	agreed, admittedSeen, deniedSeen := 0, 0, 0
	for _, r := range rows {
		ctx := userCtxAB(r.callerID)

		byName := NewListBySubjectUseCase(srRepo()).
			WithRelationStore(r.relations, nil).
			WithRelationQueries(r.queries)
		_, _, errBySubject := byName.Execute(ctx,
			domain.SubjectTypeUser, domain.SubjectID(spMemberID), repoab.PageFilter{PageSize: 100})

		byPriv := NewListSubjectPrivilegesUseCase(srRepo()).
			WithRelationStore(r.relations, nil).
			WithRelationQueries(r.queries)
		_, _, errPriv := byPriv.Execute(ctx,
			domain.SubjectTypeUser, domain.SubjectID(spMemberID), repoab.PageFilter{PageSize: 100})

		gotBySubject := srAdmitted(t, errBySubject)
		gotPriv := srAdmitted(t, errPriv)
		if gotBySubject != gotPriv {
			t.Errorf("%s: полосы решают допуск ПО-РАЗНОМУ — ListBySubject=%v (%v), "+
				"ListSubjectPrivileges=%v (%v). Ответ на один вопрос зависит от выбранного "+
				"глагола; расхождение и есть предмет #1352",
				r.name, gotBySubject, errBySubject, gotPriv, errPriv)
			continue
		}
		agreed++
		if gotBySubject != r.admitted {
			t.Errorf("%s: обе полосы решили %v, ожидалось %v", r.name, gotBySubject, r.admitted)
		}
		if gotBySubject {
			admittedSeen++
		} else {
			deniedSeen++
		}
	}
	t.Logf("перепись: вызывающих %d · полосы совпали на %d · допущено %d · отвергнуто %d",
		len(rows), agreed, admittedSeen, deniedSeen)
	if admittedSeen == 0 || deniedSeen == 0 {
		t.Fatalf("КОНТРОЛЬ вырожден: допущено %d, отвергнуто %d. «Совпали» зеленеет и на "+
			"глаголах, отвергающих всех", admittedSeen, deniedSeen)
	}
}

// ── НЕСУЩАЯ ПРОБА #1354 на ОБЕИХ полосах: сужение построчно ─────────────────

// TestSubjectReads_1352_DelegatedAdministratorIsNarrowedOnBothVerbs — исход для
// делегированного распорядителя, снятый с ОБОИХ глаголов сразу.
//
// Пара утверждений об ОДНОМ ответе каждого глагола: своя область обязана
// присутствовать (иначе отрицание зеленело бы на пустоте), чужая — отсутствовать.
func TestSubjectReads_1352_DelegatedAdministratorIsNarrowedOnBothVerbs(t *testing.T) {
	relations := func() clients.RelationStore {
		return &scopedFGA{allow: map[string]bool{"admin|account:" + spAccA: true}}
	}
	queries := func() *abQueriesStub {
		q := newABQueriesStub()
		q.set("v_get", "user:"+spAdminID, []string{srBindHome})
		return q
	}
	ctx := userCtxAB(spAdminID)

	rawRows, _, err := NewListBySubjectUseCase(srRepo()).
		WithRelationStore(relations(), nil).
		WithRelationQueries(queries()).
		Execute(ctx, domain.SubjectTypeUser, domain.SubjectID(spMemberID), repoab.PageFilter{PageSize: 100})
	if err != nil {
		t.Fatalf("ListBySubject: распорядитель аккаунта субъекта допущен — отказа быть не должно: %v", err)
	}
	privRows, _, err := NewListSubjectPrivilegesUseCase(srRepo()).
		WithRelationStore(relations(), nil).
		WithRelationQueries(queries()).
		Execute(ctx, domain.SubjectTypeUser, domain.SubjectID(spMemberID), repoab.PageFilter{PageSize: 100})
	if err != nil {
		t.Fatalf("ListSubjectPrivileges: тот же вызывающий, тот же субъект — отказа быть не должно: %v", err)
	}

	for _, got := range []struct {
		verb string
		ids  []string
	}{
		{"ListBySubject", srBindingIDs(rawRows)},
		{"ListSubjectPrivileges", spIDs(privRows)},
	} {
		if !spContains(got.ids, srBindHome) {
			t.Errorf("%s: положительная половина — выдача в аккаунте, которым вызывающий "+
				"распоряжается, обязана остаться в ответе; получено %v", got.verb, got.ids)
		}
		if spContains(got.ids, srBindForeign) {
			t.Errorf("%s: выдача в ЧУЖОМ аккаунте отдана вызывающему, который им не "+
				"распоряжается: %v — состав арендаторов картируется по областям выдач "+
				"ровно так же, как по членствам (#1085)", got.verb, got.ids)
		}
	}
}

// TestSubjectReads_1352_SelfReadIsNotNarrowedOnBothVerbs — собственное чтение
// сужению не подлежит НИ НА ОДНОМ из двух глаголов.
//
// Без этой половины «чужого нет» зеленело бы на сужении, применённом ко всем
// полосам сразу: главное употребление обоих чтений опустело бы ТИХО, отдав `200`
// с пустым перечнем.
func TestSubjectReads_1352_SelfReadIsNotNarrowedOnBothVerbs(t *testing.T) {
	ctx := userCtxAB(spMemberID)

	rawRows, _, err := NewListBySubjectUseCase(srRepo()).
		WithRelationStore(&denyingFGA{}, nil).
		WithRelationQueries(newABQueriesStub()).
		Execute(ctx, domain.SubjectTypeUser, domain.SubjectID(spMemberID), repoab.PageFilter{PageSize: 100})
	if err != nil {
		t.Fatalf("ListBySubject: собственное чтение обязано проходить: %v", err)
	}
	privRows, _, err := NewListSubjectPrivilegesUseCase(srRepo()).
		WithRelationStore(&denyingFGA{}, nil).
		WithRelationQueries(newABQueriesStub()).
		Execute(ctx, domain.SubjectTypeUser, domain.SubjectID(spMemberID), repoab.PageFilter{PageSize: 100})
	if err != nil {
		t.Fatalf("ListSubjectPrivileges: собственное чтение обязано проходить: %v", err)
	}

	for _, got := range []struct {
		verb string
		ids  []string
	}{
		{"ListBySubject", srBindingIDs(rawRows)},
		{"ListSubjectPrivileges", spIDs(privRows)},
	} {
		if !spContains(got.ids, srBindHome) || !spContains(got.ids, srBindForeign) {
			t.Errorf("%s: собственные выдачи обязаны быть отданы целиком, получено %v",
				got.verb, got.ids)
		}
	}
}

// ── FAIL-CLOSED на НОВОЙ полосе сужения ListBySubject ───────────────────────
//
// Пробы ниже — про глагол, у которого сужения раньше не было вовсе. Их близнецы
// для ListSubjectPrivileges стоят в list_subject_privileges_narrowing_test.go;
// здесь они не наследуются, потому что наследовать нечего: полоса новая, и
// проверять её обязана СВОЯ проба.

// TestSubjectReads_1352_ListBySubject_UnwiredNarrowing_IsUnavailable —
// непровязанный порт модели обязан ОТКАЗАТЬ, а не отдать несуженный перечень.
//
// Полоса края у этого чтения — `scope_filtered`: пообъектной проверки за ним нет,
// откатиться не на что. Непровязанный порт — не «сужать нечем, отдадим как есть»,
// а «вердикта нет».
func TestSubjectReads_1352_ListBySubject_UnwiredNarrowing_IsUnavailable(t *testing.T) {
	uc := NewListBySubjectUseCase(srRepo()).
		WithRelationStore(&scopedFGA{allow: map[string]bool{"admin|account:" + spAccA: true}}, nil)
	// порт сужения НЕ провязан

	out, next, err := uc.Execute(userCtxAB(spAdminID),
		domain.SubjectTypeUser, domain.SubjectID(spMemberID), repoab.PageFilter{PageSize: 100})

	if status.Code(err) != codes.Unavailable {
		t.Fatalf("сужение непровязано — ожидался Unavailable, получено %v", err)
	}
	if len(out) != 0 || next != "" {
		t.Fatalf("выдача не прервана: строк=%d, курсор=%q — несуженный перечень при отсутствующем "+
			"вердикте есть та самая утечка, ради которой сужение и заведено", len(out), next)
	}
}

// TestSubjectReads_1352_ListBySubject_NarrowingOutage_IsUnavailable —
// неотвеченный вопрос сужения обязан ПРЕРВАТЬ выдачу, а не быть прочитан как
// «нечего показать» и не как «показать всё».
func TestSubjectReads_1352_ListBySubject_NarrowingOutage_IsUnavailable(t *testing.T) {
	uc := NewListBySubjectUseCase(srRepo()).
		WithRelationStore(&scopedFGA{allow: map[string]bool{"admin|account:" + spAccA: true}}, nil).
		WithRelationQueries(&outageOnNarrowingQueries{})

	out, next, err := uc.Execute(userCtxAB(spAdminID),
		domain.SubjectTypeUser, domain.SubjectID(spMemberID), repoab.PageFilter{PageSize: 100})

	if status.Code(err) != codes.Unavailable {
		t.Fatalf("модель прав не ответила на вопрос страницы — ожидался Unavailable, получено %v", err)
	}
	if len(out) != 0 || next != "" {
		t.Fatalf("выдача не прервана: строк=%d, курсор=%q", len(out), next)
	}
}

// TestSubjectReads_1352_ListBySubject_EmptyPrincipalSubject_Denied —
// вызывающий, чью личность нечем назвать модели, отсекается БЕЗУСЛОВНО, а не
// «сужается в пустоту»: пустой субъект `VisibleSet` не отвергает, он возвращает
// пустой набор, и страница молча схлопнулась бы в `200`.
func TestSubjectReads_1352_ListBySubject_EmptyPrincipalSubject_Denied(t *testing.T) {
	uc := NewListBySubjectUseCase(srRepo()).
		WithRelationStore(&denyingFGA{}, nil).
		WithRelationQueries(newABQueriesStub())

	out, _, err := uc.Execute(unnamableOwnerCtxSP(),
		domain.SubjectTypeUser, domain.SubjectID(spMemberID), repoab.PageFilter{PageSize: 100})

	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("принципал, которого нечем назвать модели, обязан быть отвергнут; получено %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("строки отданы вызывающему, которого нечем назвать модели: %v", srBindingIDs(out))
	}
}

// ── СУБЪЕКТ-ГРУППА: та же полоса на обоих глаголах ──────────────────────────

// TestSubjectReads_1352_GroupSubjectAdmitsMemberAndAccountAdminOnBothVerbs —
// участник группы и распорядитель её домашнего аккаунта допускаются ОБОИМИ
// глаголами, посторонний — ни одним.
//
// Раньше эти три вызывающих делились между глаголами: участника допускал только
// ListBySubject, распорядителя — только ListSubjectPrivileges. Проба снимает
// исход с обоих и требует совпадения; отрицательный вызывающий стоит рядом,
// иначе «совпали» зеленело бы на глаголах, допускающих всех.
func TestSubjectReads_1352_GroupSubjectAdmitsMemberAndAccountAdminOnBothVerbs(t *testing.T) {
	rows := []struct {
		name      string
		callerID  string
		member    bool
		relations clients.RelationStore
		admitted  bool
	}{
		{name: "участник группы", callerID: spMemberID, member: true,
			relations: &denyingFGA{}, admitted: true},
		{name: "распорядитель домашнего аккаунта группы", callerID: spAdminID,
			relations: &scopedFGA{allow: map[string]bool{"admin|account:" + spAccA: true}},
			admitted:  true},
		{name: "посторонний, не состоящий в группе", callerID: spOtherID,
			relations: &denyingFGA{}, admitted: false},
	}
	agreed, admittedSeen, deniedSeen := 0, 0, 0
	for _, r := range rows {
		mk := func() *abFakeRepo {
			repo := srRepo()
			if r.member {
				repo.AddGroupMember(spGroupID, "user", r.callerID)
			}
			return repo
		}
		q := newABQueriesStub()
		q.set("v_get", "user:"+r.callerID, []string{srBindHome})
		ctx := userCtxAB(r.callerID)

		_, _, errBySubject := NewListBySubjectUseCase(mk()).
			WithRelationStore(r.relations, nil).WithRelationQueries(q).
			Execute(ctx, domain.SubjectTypeGroup, domain.SubjectID(spGroupID), repoab.PageFilter{PageSize: 100})
		_, _, errPriv := NewListSubjectPrivilegesUseCase(mk()).
			WithRelationStore(r.relations, nil).WithRelationQueries(q).
			Execute(ctx, domain.SubjectTypeGroup, domain.SubjectID(spGroupID), repoab.PageFilter{PageSize: 100})

		gotBySubject, gotPriv := srAdmitted(t, errBySubject), srAdmitted(t, errPriv)
		if gotBySubject != gotPriv {
			t.Errorf("%s: полосы решают допуск к субъекту-группе ПО-РАЗНОМУ — "+
				"ListBySubject=%v (%v), ListSubjectPrivileges=%v (%v)",
				r.name, gotBySubject, errBySubject, gotPriv, errPriv)
			continue
		}
		agreed++
		if gotBySubject != r.admitted {
			t.Errorf("%s: обе полосы решили %v, ожидалось %v", r.name, gotBySubject, r.admitted)
		}
		if gotBySubject {
			admittedSeen++
		} else {
			deniedSeen++
		}
	}
	t.Logf("перепись: вызывающих %d · полосы совпали на %d · допущено %d · отвергнуто %d",
		len(rows), agreed, admittedSeen, deniedSeen)
	if admittedSeen == 0 || deniedSeen == 0 {
		t.Fatalf("КОНТРОЛЬ вырожден: допущено %d, отвергнуто %d", admittedSeen, deniedSeen)
	}
}
