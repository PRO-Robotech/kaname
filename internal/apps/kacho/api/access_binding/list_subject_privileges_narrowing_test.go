// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// list_subject_privileges_narrowing_test.go — сужение перечня привилегий субъекта
// по правам вызывающего, ПОСТРОЧНО (задача #1354).
//
// # Предмет
//
// Допуск и сужение — разные вещи, и здесь стояло только первое. Пройдя допуск
// «распорядитель ДОМАШНЕГО аккаунта субъекта», вызывающий получал перечень
// ЦЕЛИКОМ — включая выдачи, чья область лежит в ЧУЖИХ аккаунтах, к которым он
// отношения не имеет. Строка ответа несёт `resource_type`/`resource_id`, то есть
// называет область; перечень таких строк картирует состав арендаторов ровно так
// же, как перечень аккаунтов человека, отданный распорядителю одного из них
// (решение по #1085).
//
// Соседнее чтение того же сервиса — `ListBySubject` — устроено иначе: вызывающий
// обязан БЫТЬ названным субъектом, поэтому его ответ не шире того, что ему и так
// принадлежит. Оно и есть законный близнец: то же семейство, тот же ресурс, и
// сужения ему не требуется.
//
// # Отрицание — только в паре с положительным
//
// «Чужой области в ответе нет» зеленеет на ПУСТОМ ответе, то есть на полностью
// сломанном сужении, которое не отдаёт ничего. Поэтому у каждой пробы отрицания
// здесь стоит положительная половина в ТОМ ЖЕ прогоне и на ТОМ ЖЕ ответе: своя
// область обязана присутствовать. Обе половины утверждаются об одном вызове —
// разнесённые по разным пробам, они допускали бы «одна зелена, потому что вторая
// красна».
//
// # Что здесь НЕ проверяется
//
// Дублёр модели прав (`abQueriesStub`) отвечает из засеянных наборов и деривации
// модели не воспроизводит: в бою `v_get` на выдаче выводится через
// `super_admin from account`, поэтому распорядитель аккаунта A держит его на
// КАЖДОЙ выдаче, чей родитель — A, без единого прямого кортежа. Пробы ниже
// засевают ровно то, что модель вывела бы, и утверждают про ПОВЕДЕНИЕ
// use-case'а, а не про вывод модели; вывод модели — предмет самой модели и её
// интеграционных проб.

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho-iam/internal/clients"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	repoab "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/access_binding"
)

const (
	// Выдача, чья область — ДОМАШНИЙ аккаунт субъекта: ровно то, чем распоряжается
	// допущенный вызывающий.
	spBindHome = "acb0000000000home01"
	// Выдача, чья область — ЧУЖОЙ аккаунт: предмет утечки. Вызывающий не
	// распоряжается им и не должен узнать о его существовании.
	spBindForeign = "acb00000000foreign1"
)

// spNarrowRepo — субъект usr-MEMBER (дом acc-A) с двумя выдачами: одна в его
// домашнем аккаунте, вторая в чужом acc-B.
func spNarrowRepo() *abFakeRepo {
	repo := spRepo()
	repo.seedSubjectPrivileges([]domain.SubjectPrivilege{
		spPriv(spBindHome, "rol_v", "viewer", "account", spAccA, domain.ScopeAccount),
		spPriv(spBindForeign, "rol_e", "editor", "account", spAccB, domain.ScopeAccount),
	})
	return repo
}

// spIDs — идентификаторы выдач ответа, в порядке ответа.
func spIDs(rows []domain.SubjectPrivilege) []string {
	out := make([]string, 0, len(rows))
	for _, p := range rows {
		out = append(out, string(p.BindingID))
	}
	return out
}

// spNamesScope — называет ли ответ хоть одной строкой указанную область.
func spNamesScope(rows []domain.SubjectPrivilege, resourceID string) bool {
	for _, p := range rows {
		if p.ResourceID == resourceID {
			return true
		}
	}
	return false
}

// unnamableOwnerCtxSP — вызывающий, которого ДОПУСК признаёт, а модель прав
// назвать нечем.
//
// Две проверки личности в этом чтении спрашивают РАЗНОЕ, и здесь они расходятся:
// допуск по владельцу аккаунта сверяет `IsSelf`, то есть голый идентификатор
// принципала, и о виде принципала не спрашивает; сужение же строит субъект через
// `SubjectFromPrincipal`, а тот знает лишь два вида — человека и служебную
// учётку — и на любом другом честно отдаёт пустую строку.
//
// Поэтому принципал вида `system` с идентификатором ВЛАДЕЛЬЦА аккаунта проходит
// допуск и приходит к сужению без имени. Пустой субъект `VisibleSet` не
// отвергает: он возвращает пустой набор, и страница молча схлопывается в `200`
// с пустым перечнем — исход, неотличимый для вызывающего от отзыва прав.
//
// Идентификатор намеренно НЕ `bootstrap`: пару `system`+`bootstrap`
// `IsAnonymous` относит к анонимным, и проба закрывалась бы гейтом
// аутентификации, ничего не утверждая о СВОЁМ предмете.
func unnamableOwnerCtxSP() context.Context {
	return operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "system", ID: spOwnerID})
}

func spContains(ids []string, want string) bool {
	for _, got := range ids {
		if got == want {
			return true
		}
	}
	return false
}

// spVisibleTo — дублёр модели прав, у которого названный вызывающий вправе
// прочитать по идентификатору ровно перечисленные выдачи.
//
// Одно написание на весь пакет: пробы полосы распорядителя обязаны НАЗЫВАТЬ свою
// предпосылку сужения, а не наследовать её от соседа. Дублёр отвечает тем же
// оракулом на оба вопроса — пообъектный и партионный, — поэтому шире настоящего
// он не становится.
func spVisibleTo(callerID string, bindingIDs ...string) *abQueriesStub {
	q := newABQueriesStub()
	q.set("v_get", "user:"+callerID, bindingIDs)
	return q
}

// ── ПРЕДМЕТ: распорядитель одного аккаунта видит только свои области ─────────

// TestListSubjectPrivileges_1354_AccountAdminSeesOnlyAdministeredScopes —
// несущая проба задачи. Пара утверждений об ОДНОМ ответе:
//
//	положительное — выдача в домашнем аккаунте, которым вызывающий распоряжается,
//	                в ответе ЕСТЬ (иначе отрицание ниже зеленело бы на пустоте);
//	отрицательное — выдачи в чужом аккаунте нет, и сам чужой аккаунт ответом не
//	                назван ни одной строкой.
func TestListSubjectPrivileges_1354_AccountAdminSeesOnlyAdministeredScopes(t *testing.T) {
	repo := spNarrowRepo()

	// usr-ADMIN держит `admin` на account:acc-A — этим он и допущен к чтению
	// привилегий usr-MEMBER, чей дом — acc-A. Кластерным администратором он НЕ
	// является: иначе сужения не было бы вовсе и проба утверждала бы о другой полосе.
	relations := &scopedFGA{allow: map[string]bool{
		"admin|account:" + spAccA: true,
	}}
	// Модель прав: `v_get` на выдаче в acc-A выводится у него через
	// `super_admin from account`; на выдаче в acc-B — не выводится ниоткуда.
	queries := newABQueriesStub()
	queries.set("v_get", "user:"+spAdminID, []string{spBindHome})

	uc := NewListSubjectPrivilegesUseCase(repo).
		WithRelationStore(relations, nil).
		WithRelationQueries(queries)

	out, _, err := uc.Execute(userCtxAB(spAdminID),
		domain.SubjectTypeUser, domain.SubjectID(spMemberID), repoab.PageFilter{PageSize: 100})
	if err != nil {
		t.Fatalf("распорядитель домашнего аккаунта допущен к чтению — отказа быть не должно: %v", err)
	}

	ids := spIDs(out)
	if !spContains(ids, spBindHome) {
		t.Fatalf("положительная половина: выдача в аккаунте, которым вызывающий распоряжается, "+
			"обязана остаться в ответе; получено %v. Без неё отрицание ниже зеленело бы на "+
			"полностью сломанном сужении", ids)
	}
	if spContains(ids, spBindForeign) {
		t.Fatalf("выдача в ЧУЖОМ аккаунте отдана вызывающему, который им не распоряжается: %v", ids)
	}
	if spNamesScope(out, spAccB) {
		t.Fatalf("ответ назвал чужой аккаунт %q — состав арендаторов картируется по областям "+
			"выдач ровно так же, как по членствам (#1085): %+v", spAccB, out)
	}
}

// ── ПОЛОСА СОБСТВЕННОГО ЧТЕНИЯ: сужению здесь нечего сужать ─────────────────

// TestListSubjectPrivileges_1354_SelfViewIsNotNarrowed — вызывающий, читающий
// СВОИ привилегии, получает их целиком.
//
// Это не послабление, а та же граница, по которой законным близнецом считается
// `ListBySubject`: ответ не шире того, что вызывающему и так принадлежит. Проба
// стоит здесь потому, что сужение, применённое и к этой полосе, опустошило бы
// главное употребление чтения — и опустошило бы ТИХО, отдав `200` с пустым
// перечнем.
func TestListSubjectPrivileges_1354_SelfViewIsNotNarrowed(t *testing.T) {
	repo := spNarrowRepo()
	// Модель не выдаёт субъекту `v_get` ни на одну из его выдач — обычное
	// положение дел: выдачей распоряжается администратор области, а не тот, кому
	// она выдана.
	queries := newABQueriesStub()

	uc := NewListSubjectPrivilegesUseCase(repo).
		WithRelationStore(&denyingFGA{}, nil).
		WithRelationQueries(queries)

	out, _, err := uc.Execute(userCtxAB(spMemberID),
		domain.SubjectTypeUser, domain.SubjectID(spMemberID), repoab.PageFilter{PageSize: 100})
	if err != nil {
		t.Fatalf("собственное чтение обязано проходить: %v", err)
	}
	ids := spIDs(out)
	if !spContains(ids, spBindHome) || !spContains(ids, spBindForeign) {
		t.Fatalf("собственные привилегии обязаны быть отданы целиком, получено %v", ids)
	}
}

// TestListSubjectPrivileges_1354_ClusterAdminIsNotNarrowed — администратор
// облака читает перечень целиком (`security.md` §Три уровня супер-доступа), в
// паритете с каждым соседним чтением этого типа.
func TestListSubjectPrivileges_1354_ClusterAdminIsNotNarrowed(t *testing.T) {
	repo := spNarrowRepo()
	queries := newABQueriesStub() // ни одного прямого кортежа — как у него и бывает

	uc := NewListSubjectPrivilegesUseCase(repo).
		WithRelationStore(onlyClusterAdmin(), nil).
		WithRelationQueries(queries)

	out, _, err := uc.Execute(clusterAdminCtx(spOtherID),
		domain.SubjectTypeUser, domain.SubjectID(spMemberID), repoab.PageFilter{PageSize: 100})
	if err != nil {
		t.Fatalf("администратор облака обязан читать: %v", err)
	}
	ids := spIDs(out)
	if !spContains(ids, spBindHome) || !spContains(ids, spBindForeign) {
		t.Fatalf("администратору облака перечень отдаётся целиком, получено %v", ids)
	}
}

// ── FAIL-CLOSED: за сужаемым чтением нет пообъектного гейта края ─────────────

// TestListSubjectPrivileges_1354_UnwiredNarrowing_IsUnavailableNotUnfiltered —
// непровязанный порт модели обязан ОТКАЗАТЬ, а не отдать несуженный перечень.
//
// Полоса края у этого чтения — `scope_filtered`: пообъектной проверки за ним нет,
// откатиться не на что. Непровязанный порт — не «сужать нечем, отдадим как есть»,
// а «вердикта нет»; отдать при этом всё значит потерять сужение целиком и молча.
func TestListSubjectPrivileges_1354_UnwiredNarrowing_IsUnavailableNotUnfiltered(t *testing.T) {
	repo := spNarrowRepo()
	relations := &scopedFGA{allow: map[string]bool{"admin|account:" + spAccA: true}}

	uc := NewListSubjectPrivilegesUseCase(repo).WithRelationStore(relations, nil) // порт НЕ провязан

	out, next, err := uc.Execute(userCtxAB(spAdminID),
		domain.SubjectTypeUser, domain.SubjectID(spMemberID), repoab.PageFilter{PageSize: 100})

	wantCode(t, err, codes.Unavailable, "сужение непровязано")
	if len(out) != 0 || next != "" {
		t.Fatalf("выдача не прервана: строк=%d, курсор=%q — несуженный перечень при отсутствующем "+
			"вердикте есть та самая утечка, ради которой сужение и заведено", len(out), next)
	}
}

// errNarrowingDown — отказ ТРАНСПОРТА модели прав, а не вердикт о доступе.
var errNarrowingDown = errors.New("relation store unreachable")

// outageOnNarrowingQueries — дублёр, у которого не отвечает ровно пообъектный
// вопрос страницы. Вопрос допуска (`RelationStore.Check`) при этом жив: иначе
// проба зеленела бы на починке соседней полосы и об ЭТОЙ не утверждала бы ничего.
type outageOnNarrowingQueries struct {
	clients.RelationQueries
}

func (*outageOnNarrowingQueries) CheckWithContext(_ context.Context, _, _, _ string,
	_ map[string]any) (bool, error) {
	return false, errNarrowingDown
}

func (*outageOnNarrowingQueries) BatchCheckWithContext(_ context.Context, _, _ string,
	_ []string, _ map[string]any) ([]bool, error) {
	return nil, errNarrowingDown
}

// TestListSubjectPrivileges_1354_NarrowingOutage_IsUnavailableNotUnfiltered —
// неотвеченный вопрос сужения обязан ПРЕРВАТЬ выдачу, а не быть прочитан как
// «нечего показать» и не как «показать всё».
func TestListSubjectPrivileges_1354_NarrowingOutage_IsUnavailableNotUnfiltered(t *testing.T) {
	repo := spNarrowRepo()
	relations := &scopedFGA{allow: map[string]bool{"admin|account:" + spAccA: true}}

	uc := NewListSubjectPrivilegesUseCase(repo).
		WithRelationStore(relations, nil).
		WithRelationQueries(&outageOnNarrowingQueries{})

	out, next, err := uc.Execute(userCtxAB(spAdminID),
		domain.SubjectTypeUser, domain.SubjectID(spMemberID), repoab.PageFilter{PageSize: 100})

	wantCode(t, err, codes.Unavailable, "модель прав не ответила на вопрос страницы")
	if len(out) != 0 || next != "" {
		t.Fatalf("выдача не прервана: строк=%d, курсор=%q", len(out), next)
	}
}

// TestListSubjectPrivileges_1354_EmptyPrincipalSubject_Denied — вызывающий, чью
// личность нечем назвать модели, отсекается БЕЗУСЛОВНО, а не «сужается в пустоту».
//
// Полоса края у этого чтения — `scope_filtered`: пообъектной проверки за ним нет,
// откатиться не на что, поэтому пустой субъект обязан быть ОТКАЗОМ. Без
// безусловного отсечения он проходит допуск по владельцу (см.
// unnamableOwnerCtxSP) и получает либо весь перечень целиком, либо молча пустую
// страницу — оба исхода вызывающий не отличит от законного ответа.
func TestListSubjectPrivileges_1354_EmptyPrincipalSubject_Denied(t *testing.T) {
	repo := spNarrowRepo()
	queries := newABQueriesStub()

	uc := NewListSubjectPrivilegesUseCase(repo).
		WithRelationStore(&denyingFGA{}, nil).
		WithRelationQueries(queries)

	out, _, err := uc.Execute(unnamableOwnerCtxSP(),
		domain.SubjectTypeUser, domain.SubjectID(spMemberID), repoab.PageFilter{PageSize: 100})

	wantCode(t, err, codes.PermissionDenied, "принципал, которого нечем назвать модели")
	if len(out) != 0 {
		t.Fatalf("строки отданы вызывающему, которого нечем назвать модели: %v", spIDs(out))
	}
}

// ── ПОРЯДОК: формат страницы судится до решения о том, кто спрашивает ────────

// TestListSubjectPrivileges_1354_PageFormatPrecedesIdentityShortCircuit — один и
// тот же негодный курсор обязан дать ОДИН ответ независимо от того, что
// вызывающему выдано.
//
// Пара: тот же вызывающий с ГОДНЫМ курсором получает отказ по личности — иначе
// «пришёл InvalidArgument» зеленело бы на коде, который отвечает так всем и всегда.
func TestListSubjectPrivileges_1354_PageFormatPrecedesIdentityShortCircuit(t *testing.T) {
	repo := spNarrowRepo()
	newUC := func() *ListSubjectPrivilegesUseCase {
		return NewListSubjectPrivilegesUseCase(repo).
			WithRelationStore(&denyingFGA{}, nil).
			WithRelationQueries(newABQueriesStub())
	}

	// usr-OTHER живёт в acc-B: к чтению привилегий usr-MEMBER он не допущен.
	stranger := userCtxAB(spOtherID)

	_, _, err := newUC().Execute(stranger, domain.SubjectTypeUser, domain.SubjectID(spMemberID),
		repoab.PageFilter{PageToken: "!!! not-a-cursor !!!"})
	wantCode(t, err, codes.InvalidArgument, "негодный курсор у недопущенного вызывающего")

	_, _, err = newUC().Execute(stranger, domain.SubjectTypeUser, domain.SubjectID(spMemberID),
		repoab.PageFilter{PageSize: 5000})
	wantCode(t, err, codes.InvalidArgument, "размер страницы вне диапазона у недопущенного вызывающего")

	// Положительный контроль: годный формат у того же вызывающего доходит до
	// решения о личности.
	_, _, err = newUC().Execute(stranger, domain.SubjectTypeUser, domain.SubjectID(spMemberID),
		repoab.PageFilter{PageSize: 100})
	wantCode(t, err, codes.PermissionDenied, "годный формат у недопущенного вызывающего")

	if status.Code(err) == codes.InvalidArgument {
		t.Fatal("контроль не различает полосы: формат и права отвечают одинаково")
	}
}
