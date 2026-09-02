// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// list_subject_privileges.go — ListSubjectPrivilegesUseCase for
// RPC AccessBindingService.ListSubjectPrivileges.
//
// Sync, enriched read of a subject's privileges with server-resolved role names
// (JOIN in the repo). Привилегии — И прямые (`DIRECT`), И полученные через
// членство в группе (`GROUP`, `via_group_id` называет группу): различение делает
// сам запрос репозитория (access_binding_repo.go, subject-match). Здесь стояло
// «DIRECT privileges» — утверждение, пережившее свой предмет, и оно совпадало с
// такой же устаревшей фразой контракта. Допуск — ОДИН предикат с ListBySubject
// (subject_read_authority.go): «сам субъект ИЛИ распорядитель его ДОМАШНЕГО
// аккаунта ИЛИ администратор облака». Он зеркалит requireGrantAuthority, но
// объектом области берёт домашний аккаунт СУБЪЕКТА (account:<subject.account_id>),
// а не область выдачи.
//
// # ДОПУСК И СУЖЕНИЕ — РАЗНЫЕ ВЕЩИ, и раньше здесь стояло только первое (#1354)
//
// Допуск отвечает на вопрос «вправе ли вызывающий читать про ЭТОГО субъекта» и
// решается по ДОМАШНЕМУ аккаунту субъекта. Но строки ответа несут
// `resource_type`/`resource_id`, то есть называют ОБЛАСТЬ каждой выдачи, а
// области у одного человека бывают в разных аккаунтах. Пройдя допуск по
// аккаунту A, распорядитель A получал строки про аккаунты B и C — то есть узнавал
// о существовании арендаторов, к которым отношения не имеет.
//
// Это тот же класс, что закрыт решением по #1085 (перечень аккаунтов человека,
// отданный распорядителю одного из них), только в другой форме: не членства, а
// области выдач. Наблюдаемое следствие одно и то же — картирование состава
// арендаторов, — поэтому и запрет один.
//
// Соседнее чтение того же сервиса, ListBySubject, сужается ТЕМ ЖЕ вызовом и по
// той же причине: допуск у них общий, значит и полоса распорядителя аккаунта у
// него та же. Прежде оно допускало только самого субъекта — тогда сужать было
// нечего, — и эта разница была не решением, а расхождением (#1352).
//
// Order of sync steps (api-conventions):
//  1. subject_type whitelist  → InvalidArgument (user | service_account | group;
//     group resolution is DIRECT-derived bindings whose
//     subject_type=group, no via-group/transitive resolution).
//  2. prefix↔type validation  → InvalidArgument FIRST statement (before repo).
//  3. page format (page_size + page_token) → InvalidArgument. Стоит ДО любого
//     решения о личности: вопрос «правильно ли составлен запрос» имеет ОДИН
//     ответ для всех вызывающих, и зависеть от того, что вызывающему выдано, он
//     не вправе. Хендлер судит СЫРОЙ запрос (до насыщающего сужения int64→int32),
//     здесь судится уже разобранный фильтр — и судится в ТОЙ ЖЕ функции, которая
//     ниже замыкается по правам.
//  4-7. допуск — ОДИН предикат, общий с ListBySubject
//     (`subjectReadAuthority`, subject_read_authority.go). Он несёт: анти-анонимного
//     стража; требование быть НАЗЫВАЕМЫМ модели прав (безусловно — полоса края у
//     этого чтения `scope_filtered`, пообъектной проверки за ним нет, откатиться
//     не на что); резолв субъекта, чей ответ об отсутствии ПРИДЕРЖИВАЕТСЯ до
//     шага 8; и решение полосы — сам субъект / надзор облака / распорядитель
//     домашнего аккаунта. Полоса ЗАПОМИНАЕТСЯ: от неё зависит шаг 10.
//  8. only now, for a caller who may read the subject: a subject that did not
//     resolve → NotFound.
//  9. repo JOIN read (access_bindings ⋈ roles), keyset paginated.
//  10. СУЖЕНИЕ страницы по правам вызывающего — пообъектно, для тех, кого
//     допустила полоса распорядителя аккаунта.
//
// Why authority precedes existence (and not the other way round): the subject id
// is caller-supplied and every id in the cluster is a legal probe. Answering
// "no such subject" before deciding whether the caller may read it makes the RPC
// an enumeration oracle over every user, service account and group — the caller
// separates "exists, not yours" from "does not exist" by the reply alone. So a
// caller without authority gets ONE answer for both, and only self /
// account-admin / cluster-admin are told that the subject is missing.
//
// # ЧТО ИМЕННО СУЖАЕТСЯ, И ПОЧЕМУ ДВЕ ПОЛОСЫ ОСТАЮТСЯ НЕСУЖЕННЫМИ
//
// Строка остаётся на странице ровно тогда, когда вызывающий вправе прочитать её
// выдачу ПО ИДЕНТИФИКАТОРУ — предикат берётся не отсюда, а из
// internal/authzfilter, где он привязан к отношению, которым каталог прав гейтит
// одиночное чтение этого типа. Страница поэтому не может быть шире чтения.
//
// Законный обзор при этом НЕ сужается, и это свойство МОДЕЛИ, а не оговорка:
// `v_get` на выдаче выводится через `super_admin`, а тот — через
// `admin from account`. Распорядитель аккаунта A держит его на КАЖДОЙ выдаче,
// чей родитель — A, без единого прямого кортежа; выдача в аккаунте B ему не
// выводится ниоткуда. То есть сужение снимает ровно чужое.
//
// Две полосы проходят несужёнными:
//
//   - СОБСТВЕННОЕ чтение (вызывающий и есть субъект) — та же граница, по которой
//     ListBySubject считается безопасным: ответ не шире того, что вызывающему
//     принадлежит. Сузить и её значило бы опустошить главное употребление этого
//     чтения — и опустошить ТИХО, отдав `200` с пустым перечнем: выдачей
//     распоряжается администратор области, а не тот, кому она выдана, поэтому
//     прямого кортежа у субъекта на свою же выдачу обычно нет;
//   - АДМИНИСТРАТОР ОБЛАКА — верхний ярус супер-доступа, паритет с каждым
//     соседним чтением этого типа (Get / ListByScope / ListByAccount / ListByRole
//     / List). Вопрос задаётся ОДИН раз на запрос.
//
// Цена, названная честно: у полосы распорядителя вопрос надзора задаётся раньше
// предиката авторитета над домашним аккаунтом, а тот несёт собственное короткое
// замыкание на тот же надзор, — то есть на этой полосе один лишний вопрос к
// модели НА ЗАПРОС. Величина постоянная, от размера страницы не зависит и второй
// формулировки предиката полномочий не заводит.
//
// # СТОИМОСТЬ СТРАНИЦЫ ПРИНАДЛЕЖИТ ЗАПРОСУ
//
// Сужение спрашивает модель о ТЕХ ЖЕ идентификаторах, что уже прочитаны со
// страницы, партиями и параллельно (internal/authzfilter). Перечисления «покажи
// всё, что субъекту видно» здесь нет и быть не может: у него жёсткий серверный
// предел без продолжения, и остаток становится невидим навсегда при живых правах
// (security.md §«Фильтрация — страница → проверка страницы»).
//
// # ИЗВЕСТНЫЙ РАЗМЕН, НАЗВАННЫЙ, А НЕ СКРЫТЫЙ
//
// Страница читается курсором и сужается ПОСЛЕ чтения — та же форма, что у
// ListByAccount и ListByScope. Следствия два, и оба документированы: страница
// бывает КОРОЧЕ запрошенной, а `next_page_token` может кодировать строку,
// недоступную вызывающему (идентификатор и отметка времени; содержимое закрыто —
// security.md §«Фильтрация»). Обход при этом ничего не теряет: курсор идёт по
// собственным строкам субъекта, поэтому продолжение доходит до конца перечня.

import (
	"context"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	repoab "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
)

type ListSubjectPrivilegesUseCase struct {
	repo      Repo
	relations clients.RelationStore
	// queries — порт пообъектного вопроса к модели прав, которым СТРАНИЦА
	// сужается по правам вызывающего.
	queries clients.RelationQueries
	logger  *slog.Logger
}

func NewListSubjectPrivilegesUseCase(r Repo) *ListSubjectPrivilegesUseCase {
	return &ListSubjectPrivilegesUseCase{repo: r}
}

// WithRelationStore wires the FGA client so the account-admin authz path
// (FGA `admin` on the subject's home Account) can resolve delegated
// admins who are not the account owner. When unset (nil) the use-case falls
// back to owner-only authority and denies delegated admins.
func (u *ListSubjectPrivilegesUseCase) WithRelationStore(relations clients.RelationStore, logger *slog.Logger) *ListSubjectPrivilegesUseCase {
	u.relations = relations
	u.logger = logger
	return u
}

// WithRelationQueries wires the per-object question the PAGE is narrowed with.
func (u *ListSubjectPrivilegesUseCase) WithRelationQueries(q clients.RelationQueries) *ListSubjectPrivilegesUseCase {
	u.queries = q
	return u
}

func (u *ListSubjectPrivilegesUseCase) Execute(ctx context.Context, subjectType domain.SubjectType, subjectID domain.SubjectID, f repoab.PageFilter) ([]domain.SubjectPrivilege, string, error) {
	// 1. subject_type whitelist (user | service_account | group; group is
	// DIRECT-only).
	expectedPrefix, resName, err := subjectPrefixAndName(subjectType)
	if err != nil {
		return nil, "", err
	}

	// 2. prefix↔type validation — FIRST statement touching the id.
	// shared.ValidateResourceID checks prefix == expectedPrefix AND exact
	// length, so a well-formed sva-id passed as subject_type=user is rejected
	// (prefix mismatch) → InvalidArgument "invalid user id '<X>'".
	if err := shared.ValidateResourceID(string(subjectID), expectedPrefix, resName); err != nil {
		return nil, "", err
	}

	// 3. Формат страницы — ДО решения о личности и в ТОЙ ЖЕ функции, которая
	// ниже по правам замыкается. Иначе один и тот же негодный курсор получал бы
	// разный ответ в зависимости от того, что вызывающему выдано.
	if err := shared.ValidatePagination(f.PageToken, f.PageSize); err != nil {
		return nil, "", err
	}

	// 4-7. Допуск — ЕДИНЫМ предикатом, общим с ListBySubject
	// (subject_read_authority.go). Здесь его нет второй копией намеренно: два
	// написания одной политики разошлись бы молча, и это ровно то расхождение,
	// которым была заведена #1352.
	//
	// Предикат несёт анти-анонимного стража, требование быть НАЗЫВАЕМЫМ модели
	// прав, резолв субъекта с ПРИДЕРЖАННЫМ ответом об отсутствии и три полосы
	// допуска.
	dec, err := subjectReadAuthority(ctx, u.repo, u.relations, subjectType, subjectID)
	if err != nil {
		return nil, "", err
	}

	// 8. Только теперь, вызывающему, который вправе читать субъекта: субъект,
	// который не резолвится → его собственный NotFound.
	if !dec.resolved.found {
		return nil, "", dec.resolved.miss
	}

	// 9. Enriched repo read (JOIN role_name, keyset paginated).
	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return nil, "", shared.MapRepoErr(err)
	}
	defer func() { _ = rd.Rollback(ctx) }()
	out, next, err := rd.AccessBindings().ListSubjectPrivileges(ctx, subjectType, subjectID, f)
	if err != nil {
		return nil, "", shared.MapRepoErr(err)
	}
	if !dec.lane.narrowsPage() {
		return out, next, nil
	}

	// 10. Сужение страницы: остаются строки, чью выдачу вызывающий вправе
	// прочитать по идентификатору. Вопрос идёт через ТУ ЖЕ функцию, которой
	// пользуются List / ListByScope / ListByAccount, — второе написание того же
	// вопроса разошлось бы с ними молча.
	visible, verr := visibleOnNarrowedPage(ctx, u.queries, privilegeBindingIDs(out))
	if verr != nil {
		return nil, "", verr
	}
	return filterVisiblePrivileges(out, visible), next, nil
}

// privilegeBindingIDs projects a privilege page to the ids of the bindings it
// names — the input of the per-object question.
func privilegeBindingIDs(rows []domain.SubjectPrivilege) []string {
	out := make([]string, 0, len(rows))
	for _, p := range rows {
		out = append(out, string(p.BindingID))
	}
	return out
}

// filterVisiblePrivileges keeps the rows the caller may read, in the order they
// were read. Порядок сохраняется, потому что курсор страницы построен на нём.
func filterVisiblePrivileges(rows []domain.SubjectPrivilege, visible map[string]bool) []domain.SubjectPrivilege {
	out := make([]domain.SubjectPrivilege, 0, len(rows))
	for _, p := range rows {
		if visible[string(p.BindingID)] {
			out = append(out, p)
		}
	}
	return out
}

// subjectPrefixAndName maps a subject_type to its id-prefix + human resource
// name (used in the malformed-id error text). user | service_account | group are
// in scope; anything else (garbage) → InvalidArgument.
func subjectPrefixAndName(subjectType domain.SubjectType) (prefix, resName string, err error) {
	switch subjectType {
	case domain.SubjectTypeUser:
		return domain.PrefixUser, "user", nil
	case domain.SubjectTypeServiceAccount:
		return domain.PrefixServiceAccount, "service account", nil
	case domain.SubjectTypeGroup:
		return domain.PrefixGroup, "group", nil
	default:
		return "", "", status.Error(codes.InvalidArgument,
			"Illegal argument subject_type (allowed: user|service_account|group)")
	}
}
