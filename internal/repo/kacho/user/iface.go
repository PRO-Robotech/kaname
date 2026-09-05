// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package user — CQRS port-iface'ы для kacho_iam.users.
package user

import (
	"context"
	"time"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/visibility"
)

type ReaderIface interface {
	Get(ctx context.Context, id domain.UserID) (domain.User, error)
	GetByEmail(ctx context.Context, email domain.Email) (domain.User, error)
	List(ctx context.Context, filter ListFilter) ([]domain.User, string, error)

	// GetByAccountEmail — поиск user-row в конкретном Account по email
	// (case-insensitive). Используется для idempotent Invite.
	// Возвращает ErrNotFound если row нет.
	GetByAccountEmail(ctx context.Context, accountID domain.AccountID, email domain.Email) (domain.User, error)

	// FindPendingByEmail — все PENDING-row'ы по email через все Account'ы
	// (cross-Account). Используется в `InternalUserService.UpsertFromIdentity`
	// для активации pending-invites при first-login.
	FindPendingByEmail(ctx context.Context, email domain.Email) ([]domain.User, error)

	// FindActiveByExternalID — все ACTIVE-row'ы по identity (Kratos sub) через
	// все Account'ы. Используется в UpsertFromIdentity чтобы определить,
	// нужен ли bootstrap новый Account.
	FindActiveByExternalID(ctx context.Context, externalID domain.ExternalSubject) ([]domain.User, error)

	// FindByExternalIDInStatuses — все row'ы по identity (Kratos sub) через все
	// Account'ы, ограниченные множеством invite_status'ов, ORDER BY created_at
	// ASC. В отличие от FindActiveByExternalID (ACTIVE-only), этот reader видит
	// и BLOCKED-row'ы — recovery обязан их находить и re-enable'ить
	// (InternalUserService.OnRecoveryCompleted). Пустой externalID либо пустой
	// statuses → nil-срез. Возвращает nil-срез если
	// нет ни одной row.
	FindByExternalIDInStatuses(ctx context.Context, externalID domain.ExternalSubject, statuses []domain.InviteStatus) ([]domain.User, error)

	// FindActiveByEmail — все ACTIVE-row'ы по email (case-insensitive) через
	// все Account'ы, ORDER BY created_at ASC. Используется invite-flow'ом
	// чтобы привязать project-scoped AccessBinding к тому же (старейшему
	// ACTIVE) user-row, который api-gateway резолвит из JWT invitee
	// (LookupSubject). Возвращает nil-срез если ACTIVE-row нет.
	FindActiveByEmail(ctx context.Context, email domain.Email) ([]domain.User, error)

	// ListAccountsForUser — все Account'ы, где человек СОСТОИТ (активное членство
	// активной личности) либо которыми владеет, либо на которые у него есть
	// действующая выдача.
	//
	// Прод-вызывающий один — `AuthorizeService.WhoAmI` (снимок «мои аккаунты»
	// собственного профиля). Здесь стояло «используется для default-deny scope в
	// UserService.List» — утверждение пережило свой предмет: сужение списка давно
	// делает `visibility.ScopeOf`, и этот метод на том тракте не зовётся вовсе.
	// Комментарий, называющий несуществующего вызывающего, посылает следующего
	// читателя менять поведение списка правкой, которая до списка не доходит.
	ListAccountsForUser(ctx context.Context, userID domain.UserID) ([]domain.AccountID, error)

	// MembershipExists — состоит ли человек в НАЗВАННОМ аккаунте
	// (`kacho_iam.memberships`, миграция 470001).
	//
	// Вопрос задаётся ПАРОЙ, потому что членство и есть пара: у человека их может
	// быть сколько угодно, а колонка `users.account_id` называет ОДНУ из них —
	// легаси-поле перехода IAM-ID-1, читать которое как «его аккаунт» значит
	// отвечать про другого.
	//
	// Единственный прод-вызывающий — разрешение осиротевшей операции исключения
	// из аккаунта (`operationresolver`): членства нет ⇒ исключение состоялось,
	// членство есть ⇒ не состоялось. Пути use-case он не нужен: снятие
	// идемпотентно по построению (0 снятых строк = «его там и не было»), а
	// спрашивать перед записью значило бы завести check-then-act (ban #10).
	MembershipExists(ctx context.Context, userID domain.UserID, accountID domain.AccountID) (bool, error)
}

type WriterIface interface {
	// Upsert — InternalUserService.UpsertFromIdentity (legacy path; ACTIVE-only).
	// Kept for backward compatibility with tests; production-path —
	// `InsertPending` / `ActivateInvite` / `bootstrapNewIdentity` use-case.
	// Создаёт строку, если внешний субъект новый, иначе UPDATE
	// email/display_name; членство в названном аккаунте пишется в том же
	// стейтменте. Арбитр — ГЛОБАЛЬНЫЙ ключ внешнего субъекта, не пара с
	// аккаунтом. Caller должен заполнить AccountID + InviteStatus=ACTIVE.
	Upsert(ctx context.Context, u domain.User) (domain.User, bool /*created*/, error)

	// InsertPending — «человек существует и приглашён в ЭТОТ аккаунт», атомарно
	// и идемпотентно: строка человека (арбитр — ГЛОБАЛЬНЫЙ ключ почты
	// `users_identity_email_uniq`) плюс его членство в названном аккаунте, одним
	// стейтментом.
	//
	// Второй результат — «строка ЗАВЕДЕНА этим вызовом», и он несущий:
	// приглашение известной почты во второй аккаунт строки не заводит, а
	// добавляет членство, и отличить «завёл» от «нашёл» вызывающему больше нечем.
	// display_name существующей строки НЕ перезаписывается.
	InsertPending(ctx context.Context, u domain.User) (domain.User, bool /*inserted*/, error)

	// ActivateInvite — атомарный UPDATE PENDING → ACTIVE с set external_id +
	// (optional) display_name. 0 rows → ErrNotFound (row либо несуществует,
	// либо уже не PENDING — race с параллельной активацией).
	ActivateInvite(ctx context.Context, userID domain.UserID, externalID domain.ExternalSubject, displayName domain.DisplayName) (domain.User, error)

	// InsertActive — INSERT обычной ACTIVE-row (для bootstrap-flow).
	// FK violation на account_id → SQLSTATE 23503 → ErrFailedPrecondition; на
	// DEFERRABLE FK violation проверяется на COMMIT.
	InsertActive(ctx context.Context, u domain.User) (domain.User, error)

	// Delete — UserService.Delete. RESTRICT если у user'а есть Account'ы /
	// GroupMember'ы / AccessBinding'и.
	Delete(ctx context.Context, id domain.UserID) error

	// UpdateLabels — атомарный UPDATE tenant-facing меток (единственное mutable
	// поле User через публичный UpdateUser RPC). Single-statement
	// `UPDATE users SET labels = $2 WHERE id = $1 RETURNING …` защищен row-lock'ом
	// (запрет #10 — last-writer-wins, не TOCTOU). 0 rows RETURNING → ErrNotFound.
	// Identity-поля (external_id и пр.) этим путем не меняются.
	UpdateLabels(ctx context.Context, id domain.UserID, labels domain.Labels) (domain.User, error)

	// SetInviteStatus — административный запрет участию и его снятие
	// (`UserService.Block` / `Unblock`). Пишет состояние ОДНОЙ строки членства.
	//
	// Аргумент — целевое СОСТОЯНИЕ, не переход: повтор запроса того же состояния
	// проходит и оставляет строку там, где просили. Направление, делающее систему
	// безопаснее, не может падать на повторе.
	//
	// Инвариант «PENDING не трогать» выражен предикатом самого стейтмента, а не
	// проверкой-до-записи (запрет #10): приглашение без подтверждённой личности не
	// несёт внешнего идентификатора, и DB-CHECK users_invite_status_consistency
	// отверг бы ACTIVE/BLOCKED на такой строке.
	//
	// Три исхода различимы, потому что стейтмент возвращает и результат, и признак
	// существования строки: обновили → строка; строки нет → ErrNotFound;
	// строка есть, но PENDING → ErrFailedPrecondition. Схлопнуть последние два в
	// один код нельзя — «нет такого» и «есть, но нельзя» суть разные ответы, и
	// контракт-тон отсутствия ресурса на существующую строку был бы ложью.
	SetInviteStatus(ctx context.Context, id domain.UserID, status domain.InviteStatus) (domain.User, error)

	// RemoveMembership — ИСКЛЮЧИТЬ человека из названного аккаунта
	// (`UserService.RemoveFromAccount`, #1127). Снимает строку членства и НЕ
	// трогает ни одного поля строки личности: человек, исключённый из аккаунта A,
	// продолжает работать в аккаунте B без единого изменения записи.
	//
	// Второй результат — «строка БЫЛА и снята этим вызовом». Он несущий: снятие
	// идемпотентно (повтор на уже исключённом проходит), а вызывающему нужно
	// отличить «исключил» от «его здесь не было» для журнала и для снятия
	// указателя области — эмитировать снятие того, чего не снимали, значило бы
	// писать в журнал прав утверждение о действии, которого не было.
	//
	// ПОРЯДОК ДЕРЖИТ БАЗА, а не вызывающий: отложенный триггер
	// `membership_carrying_rights_is_kept` (миграция 472002) отвергает снятие
	// членства, несущего живую выдачу в этом аккаунте, — и отвергает на COMMIT,
	// а не на этом стейтменте. Значит отказ приходит из `Commit`, и отображать
	// его обязан он же (см. `writeTx.Commit`).
	RemoveMembership(ctx context.Context, userID domain.UserID, accountID domain.AccountID) (bool /*removed*/, error)
}

type ListFilter struct {
	PageSize int32
	// PageToken — токен, КАК ЕГО ПРИСЛАЛ КЛИЕНТ. Его разбирает use-case (форма
	// токена принадлежит контракту RPC, а не таблице), поэтому на пути к
	// репозиторию он пуст, а курсор приезжает разобранным в After.
	PageToken string
	Filter    string // filter-syntax: email="…" | external_id="…" | invite_status="…" | search="…"

	// AccountID — фильтр по конкретному Account (default-deny scope).
	// Пустой → no per-account filter (caller обязан добавить AccountIDs).
	AccountID domain.AccountID
	// AccountIDs — множественный фильтр (список Account'ов, где principal является
	// member; используется в `UserService.List` без explicit account_id).
	AccountIDs []domain.AccountID

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
	// ПОЛ этой поверхности — собственная строка вызывающего — приезжает сюда же,
	// в ObjectIDs, и это не хитрость, а требование: пол, применённый к уже взятой
	// странице, повторяет исходный дефект — строка становится полом, только если
	// она в страницу попала, а собственная строка вызывающего может лежать сколь
	// угодно далеко за окном.
	//
	// nil ЗНАЧИТ «не сужать», и это НЕ то же, что пустой набор: пустой не
	// называет ничего и потому не пропускает ничего.
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
