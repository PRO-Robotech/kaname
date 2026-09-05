// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// list_by_subject_pagination_order_test.go — формат страницы судится ДО решения
// о личности, и оба чтения выдач субъекта отвечают на него ОДИНАКОВО.
//
// # Предмет (#1437)
//
// `ListBySubject` решал, кто спрашивает, раньше, чем кто-либо смотрел на
// `page_token` и `page_size`: допуск (`subjectReadAuthority`) стоял первым
// стейтментом и на вызывающем без полосы завершал чтение отказом. Тогда один и
// тот же негодный курсор получал РАЗНЫЙ ответ — `InvalidArgument` тому, у кого
// полоса есть, и `PermissionDenied` тому, у кого её нет. Вопрос «правильно ли
// составлен запрос» имеет один ответ для всех вызывающих, поэтому отвечать на
// него надо раньше, чем на вопрос «что этому вызывающему видно»
// (`api-conventions.md` §«List: валидация pagination — ДО listauthz empty-grant
// short-circuit», `security.md` §Hardening п.7).
//
// # Почему проба идёт от USE-CASE'а, а не от хендлера
//
// Хендлер `ListBySubject` формат уже судил (`shared.ValidateRawPagination`), и
// проба через хендлер была бы зелёной на этом дефекте. Требование локальное:
// проверка обязана стоять в ТОЙ ЖЕ функции, которая замыкается, — guard в
// вызывающем не защищает второго вызывающего той же функции, а «репозиторий
// провалидирует» верно ровно для того пути, который до репозитория доходит,
// тогда как замыкание до него не доходит by construction.
//
// # Почему проба ПАРНАЯ по вызывающему и ПАРНАЯ по глаголу
//
// По вызывающему: утверждение «мусорный курсор отвергнут» у названного
// вызывающего ничего не говорит о порядке — оно зеленеет и тогда, когда формат
// судит репозиторий, до которого замыкающийся не доходит. Предмет виден только
// на СРАВНЕНИИ двух ответов на ОДИН вход.
//
// По глаголу: `ListBySubject` и `ListSubjectPrivileges` отвечают на один вопрос
// об одном субъекте, и их разница уже однажды была дефектом (#1352). Полосы
// одного механизма сверяются МЕЖДУ СОБОЙ (`architecture.md`), иначе расхождение
// снова заведётся молча — по отдельности каждая защитима.
//
// # Положительный контроль обязателен
//
// Отрицание «негодный вход отвергнут» зеленеет на реализации, отвергающей ВСЁ.
// Поэтому рядом: законная страница проходит у названного вызывающего, и
// замыкание по личности на законном входе СОХРАНЯЕТСЯ у замыкающегося — фикс
// порядка не вправе превратить отказ в правах в отказ по формату.
package access_binding

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/pagetoken"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	repoab "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/access_binding"
)

// pageOrderGarbageToken — курсор, который не разбирается ни одним кодеком: не
// base64. Форма взята нарочно грубой, чтобы отказ приходил от проверки формата,
// а не от разбора содержимого.
const pageOrderGarbageToken = "!!! не base64 !!!"

// pageOrderLawfulToken — курсор ТОЙ ЖЕ формы, что производит кодек чтения.
// Собирается кодеком, а не выписывается литералом: второе написание формы
// разошлось бы с первым молча и ровно там, где расхождение не видно.
func pageOrderLawfulToken() string {
	return pagetoken.Encode(pagetoken.Cursor{
		CreatedAt: time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC),
		ID:        "acb0000000000home01",
	})
}

// subjectListVerb — одно из двух чтений выдач названного субъекта.
//
// Оба принимают `subject_type` + `subject_id` + страницу и оба замыкаются одним
// предикатом допуска, поэтому требование к порядку у них общее.
type subjectListVerb struct {
	name string
	call func(repo *abFakeRepo, ctx context.Context, f repoab.PageFilter) error
}

func subjectListVerbs() []subjectListVerb {
	return []subjectListVerb{
		{
			name: "ListBySubject",
			call: func(repo *abFakeRepo, ctx context.Context, f repoab.PageFilter) error {
				_, _, err := NewListBySubjectUseCase(repo).
					WithRelationStore(&denyingFGA{}, nil).
					WithRelationQueries(newABQueriesStub()).
					Execute(ctx, domain.SubjectTypeUser, domain.SubjectID(spMemberID), f)
				return err
			},
		},
		{
			name: "ListSubjectPrivileges",
			call: func(repo *abFakeRepo, ctx context.Context, f repoab.PageFilter) error {
				_, _, err := NewListSubjectPrivilegesUseCase(repo).
					WithRelationStore(&denyingFGA{}, nil).
					WithRelationQueries(newABQueriesStub()).
					Execute(ctx, domain.SubjectTypeUser, domain.SubjectID(spMemberID), f)
				return err
			},
		},
	}
}

// TestSubjectListsJudgePageFormatBeforeTheIdentityShortCircuit — несущая проба
// #1437.
//
// Три утверждения об ОДНОМ входе, и разносить их по разным пробам нельзя: порознь
// они допускают «одна зелена, потому что вторая красна».
func TestSubjectListsJudgePageFormatBeforeTheIdentityShortCircuit(t *testing.T) {
	// Названный вызывающий — сам субъект: полоса `subjectReadSelf`, до чтения
	// страницы доходит.
	named := func() context.Context { return userCtxAB(spMemberID) }
	// Вызывающий, попадающий в ЗАМЫКАНИЕ: чужой человек из другого аккаунта,
	// модель прав отвечает «нет» — допуск завершает чтение отказом и до
	// репозитория не доходит.
	shortCircuited := func() context.Context { return userCtxAB(spOtherID) }

	for _, verb := range subjectListVerbs() {
		t.Run(verb.name, func(t *testing.T) {
			t.Run("замыкание по личности ЕСТЬ — иначе проба ниже беспредметна", func(t *testing.T) {
				err := verb.call(spRepo(), shortCircuited(), repoab.PageFilter{PageSize: 100})
				if status.Code(err) != codes.PermissionDenied {
					t.Fatalf("предпосылка пробы: этот вызывающий обязан замыкаться отказом по личности, "+
						"получено %v. Без замыкания утверждения ниже ничего не измеряют", err)
				}
			})

			t.Run("мусорный page_token — InvalidArgument у ОБОИХ вызывающих", func(t *testing.T) {
				f := repoab.PageFilter{PageToken: pageOrderGarbageToken, PageSize: 100}

				errNamed := verb.call(spRepo(), named(), f)
				if status.Code(errNamed) != codes.InvalidArgument {
					t.Fatalf("названный вызывающий: мусорный курсор обязан давать InvalidArgument, получено %v", errNamed)
				}
				if !abNamesField(errNamed, "page_token") {
					t.Errorf("отказ обязан назвать поле page_token: %v", errNamed)
				}

				errShort := verb.call(spRepo(), shortCircuited(), f)
				if status.Code(errShort) != codes.InvalidArgument {
					t.Fatalf("вызывающий, попадающий в замыкание по личности, получил %v вместо "+
						"InvalidArgument: формат страницы судится ПОСЛЕ решения о доступе, "+
						"и ответ на один и тот же негодный ввод зависит от того, что вызывающему выдано",
						errShort)
				}
				if !abNamesField(errShort, "page_token") {
					t.Errorf("отказ обязан назвать поле page_token: %v", errShort)
				}
			})

			t.Run("page_size вне диапазона — InvalidArgument у ОБОИХ вызывающих", func(t *testing.T) {
				f := repoab.PageFilter{PageSize: 1001}

				errNamed := verb.call(spRepo(), named(), f)
				if status.Code(errNamed) != codes.InvalidArgument {
					t.Fatalf("названный вызывающий: page_size вне [0..1000] обязан давать InvalidArgument, получено %v", errNamed)
				}
				if !abNamesField(errNamed, "page_size") {
					t.Errorf("отказ обязан назвать поле page_size: %v", errNamed)
				}

				errShort := verb.call(spRepo(), shortCircuited(), f)
				if status.Code(errShort) != codes.InvalidArgument {
					t.Fatalf("вызывающий, попадающий в замыкание по личности, получил %v вместо "+
						"InvalidArgument на page_size вне диапазона", errShort)
				}
				if !abNamesField(errShort, "page_size") {
					t.Errorf("отказ обязан назвать поле page_size: %v", errShort)
				}
			})

			// ── положительный контроль ──────────────────────────────────────────
			//
			// Без него отрицания выше зеленели бы на реализации, отвергающей ВСЁ.

			t.Run("положительный контроль: законная страница проходит у названного", func(t *testing.T) {
				for name, f := range map[string]repoab.PageFilter{
					"первая страница":      {PageSize: 100},
					"законный курсор":      {PageToken: pageOrderLawfulToken(), PageSize: 100},
					"page_size на границе": {PageSize: 1000},
				} {
					if err := verb.call(spRepo(), named(), f); err != nil {
						t.Errorf("%s: законный ввод отвергнут — проверка формата ловит форму, а не негодность: %v", name, err)
					}
				}
			})

			t.Run("положительный контроль: замыкание по личности СОХРАНЕНО на законном вводе", func(t *testing.T) {
				err := verb.call(spRepo(), shortCircuited(), repoab.PageFilter{PageToken: pageOrderLawfulToken(), PageSize: 100})
				if status.Code(err) != codes.PermissionDenied {
					t.Fatalf("порядок проверок не вправе снимать отказ по личности: получено %v "+
						"вместо PermissionDenied", err)
				}
			})
		})
	}
}
