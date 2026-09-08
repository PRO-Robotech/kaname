// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package group — CQRS port-iface'ы для kaname.groups + group_members.
package group

import (
	"context"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/visibility"
)

type ReaderIface interface {
	Get(ctx context.Context, id domain.GroupID) (domain.Group, error)
	List(ctx context.Context, filter ListFilter) ([]domain.Group, string, error)
	// ListMembers — one PAGE of the membership, plus the continuation token.
	//
	// Paged rather than whole because the request message publishes page_size and
	// page_token and the response publishes next_page_token: a membership returned
	// in one message makes those three fields a promise the service does not keep,
	// and a large enough group makes the reply exceed the transport's message limit
	// with no way out — the caller cannot page past a listing that never emits a
	// token.
	ListMembers(ctx context.Context, groupID domain.GroupID, page MemberPage) ([]domain.GroupMember, string, error)
	// IsMember — single-row EXISTS lookup against group_members for the
	// (groupID, memberType, memberID) triple. Used by
	// ListAccessBindingsBySubject to authorise group-subject queries: the
	// caller is allowed to enumerate bindings on a group iff they belong
	// to it.
	//
	// Returns false (no error) when the group does not exist OR the caller
	// is not a member. Backend errors (DB-unavailable / SQL syntax) surface
	// as ErrInternal / ErrUnavailable via the standard mapErr.
	IsMember(ctx context.Context, groupID domain.GroupID, memberType domain.SubjectType, memberID domain.SubjectID) (bool, error)

	// MembersOfGroups — состав НЕСКОЛЬКИХ групп ОДНИМ вопросом, ОГРАНИЧЕННЫЙ
	// сверху, с ЧЕСТНЫМ признаком усечения.
	//
	// Отдельно от ListMembers, а не «позвать его в цикле»: у полного
	// перечисления выдач (#914) на странице бывает до тысячи выдач, и вопрос
	// на каждую группу означал бы тысячу обращений к базе на один ответ —
	// стоимость страницы, принадлежащая числу строк, а не запросу.
	//
	// ПРЕДЕЛ ОБЯЗАТЕЛЕН, И ВОТ ПОЧЕМУ. Вход ограничен размером страницы выдач —
	// но он ограничивает число ГРУПП, а не число ЧЛЕНОВ. Членство неограниченно
	// by construction (ровно поэтому у него есть свой пагинированный глагол), и
	// без предела ответ на законную страницу в тысячу выдач нёс бы сумму
	// составов без верхней границы.
	//
	// Второй возврат — группы, чей состав вернулся НЕПОЛНЫМ либо не читался
	// вовсе. Молча усечённое членство читается вызывающим как факт о доступе
	// («в группе больше никого»), поэтому усечение обязано быть НАЗВАНО, а не
	// выведено вызывающим из совпадения чисел. Названы именно группы, а не
	// «где-то усечено»: по имени видно, к какой из них идти пагинированным
	// глаголом.
	//
	// Пустой перечень идентификаторов — пустой ответ, а не «все группы».
	MembersOfGroups(ctx context.Context, groupIDs []domain.GroupID) (members []domain.GroupMember, incomplete []domain.GroupID, err error)
}

type WriterIface interface {
	Insert(ctx context.Context, g domain.Group) (domain.Group, error)
	Update(ctx context.Context, g domain.Group, updateMask []string) (domain.Group, error)
	Delete(ctx context.Context, id domain.GroupID) error
	// AddMember — INSERT в group_members. DB-триггер
	// group_members_member_exists_trg проверяет существование member_id в
	// users / service_accounts → SQLSTATE 23503 → ErrFailedPrecondition.
	AddMember(ctx context.Context, m domain.GroupMember) error
	// RemoveMember — DELETE. Идемпотентен (повторное удаление участника).
	RemoveMember(ctx context.Context, groupID domain.GroupID, memberType domain.SubjectType, memberID domain.SubjectID) error
}

// MemberPage — the page bounds of ListMembers. PageSize is already validated and
// defaulted by the use-case, so the adapter takes it as given.
type MemberPage struct {
	PageSize  int64
	PageToken string
}

type ListFilter struct {
	PageSize int32
	// PageToken — токен, КАК ЕГО ПРИСЛАЛ КЛИЕНТ. Его разбирает use-case (форма
	// токена принадлежит контракту RPC, а не таблице), поэтому на пути к
	// репозиторию он пуст, а курсор приезжает разобранным в After.
	PageToken string
	Filter    string
	AccountID domain.AccountID

	// After — курсор keyset В РАЗОБРАННОМ ВИДЕ: страница начинается со строки,
	// строго следующей за (CreatedAt, ID). nil — с начала.
	//
	// Пара с PageToken взаимоисключающая по построению: одно значение выражается
	// ровно одним способом, и путь, задающий After, PageToken не задаёт.
	After *Cursor

	// Candidates — сужение НАБОРА КАНДИДАТОВ до надмножества видимого
	// вызывающему (задача #645): строка проходит, если её аккаунт назван, либо
	// названа она сама.
	//
	// nil ЗНАЧИТ «не сужать», и это НЕ то же, что пустой набор: пустой не
	// называет ничего и потому не пропускает ничего. Различие — это различие
	// между администратором облака и посторонним, и оно обязано быть представимо
	// отдельно от значений.
	//
	// Сужение НЕ решает вопрос о доступе: оно отбирает кандидатов, вердикт по
	// каждому выносит модель прав (`security.md` §«Авторизация живёт в МОДЕЛИ»).
	Candidates *visibility.PageScope
}

// Cursor — граница keyset-обхода `(created_at, id) ASC`.
type Cursor struct {
	CreatedAt time.Time
	ID        string
}
