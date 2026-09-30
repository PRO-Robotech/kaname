// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// force_logout.go — InternalIAMService.ForceLogout.
//
// ForceLogout — admin force-logout: ends the target's OWN login sessions
// (`human_sessions`), records a USER-LEVEL revoke-all cutoff
// (user_token_revocations.revoke_before = now) and the audit event carrying the
// teardown's outcome — in ONE transaction of `OwnSessions` (kaname#340). Async
// per the proto envelope (returns Operation, done=true).
//
// ЧЬЮ СЕССИЮ СНИМАТЬ, БОЛЬШЕ НЕ РЕШАЕТ ПОСАДКА (kaname#363). Прежде под
// `external` снималась сессия у внешнего поставщика, отдельным действием после
// транзакции отсечки, и долговременная запись несла лишь намерение (#380).
// Поставщика у службы больше нет: сессия входа человека — всегда наша строка, и
// снимает её одна транзакция, запись которой несёт исход.
//
// ForceLogout was advertised (caller_policy + permission_catalog) but
// Unimplemented before this fix — an advertised-but-Unimplemented RPC is a
// contract gap.
package internal_iam

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/corelib/operations"

	operationpb "github.com/PRO-Robotech/corelib/api/corelib/operation"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
)

// forceLogoutOperationRepo — Operation-порт ForceLogout. Шире operations.Repo
// ровно на MetadataFinalizer: op-строку обязано создавать ДО мутации (иначе
// сбой Create оставляет закоммиченный cutoff без pollable операции), а
// объявленный контрактом ответ `ForceLogoutResult` известен только после
// записи. `MarkDone` третьим параметром берёт RESPONSE и metadata не трогает.
type forceLogoutOperationRepo interface {
	operations.Repo
	operations.MetadataFinalizer
}

// eventSessionForceLogout — audit_outbox taxonomy value for ForceLogout.
// Defined locally to keep the use-case free of a repo/pg import; must match the
// pg-side session taxonomy + audit_outbox_event_type CHECK.
const eventSessionForceLogout = "iam.session.force_logout"

// OwnSessions — НАШИ записи сессии входа (`human_sessions`), снимаемые целиком
// по личности (kaname#313).
//
// Предмет адресуется `users.id` — тем самым, который назвал распорядитель.
// Прежний второй порт — снятие сессии у внешнего поставщика по ЧУЖОМУ имени
// субъекта — снят вместе с поставщиком (kaname#363).
//
// # ПОЧЕМУ ОТСЕЧКИ НЕ ХВАТАЕТ, И ЭТО ИЗМЕРЕНО, А НЕ ПРЕДПОЛОЖЕНО
//
// Отсечка субъекта (`user_token_revocations.revoke_before`) действует на
// ВЫДАЧЕ: её читает край. Резолв нашей сессии её НЕ ПРИМЕНЯЕТ и
// объявляет это о себе прямо (`humansession/resolve.go`, §8 инв. 8) — строка
// судится по трём признакам: снята · истекла · личность неактивна. Значит
// носитель, выданный ДО принудительного выхода, резолвится и ПОСЛЕ него.
// Проверено опытом: `force_logout_own_session_integration_test.go` предъявляет
// тот же носитель до и после.
//
// ЧТО ЭТО НЕ ЗАМЕЩАЕТ. Приёмка Ф3-25 ставит отказ предъявленной сессии НА КРАЮ,
// сравнением момента аутентификации с отсечкой; про край здесь не утверждается
// ничего, и его путь остаётся. Снятие закрывает три вещи ВНУТРИ службы:
// собственный выход человека снимает строку И пишет отсечку, а тот же акт
// распорядителя писал только отсечку — след одного выхода был разным; уборка
// сносит истёкшие и СНЯТЫЕ строки, поэтому не снятая живёт до абсолютного
// срока; и «сессии нет» получал только тот читатель, кто сверх резолва спросил
// ещё и отсечку.
//
// # ПОЧЕМУ ПОРТ ОТДАЁТ ТРАНЗАКЦИЮ, А НЕ ГЛАГОЛ «СНЯТЬ» (kaname#340)
//
// Долговременная запись принудительного выхода обязана нести его ИСХОД — число
// снятых записей, — а число это существует только ПОСЛЕ снятия. Пока снятие шло
// своей транзакцией вслед за отсечкой, запись события ложилась транзакцией
// отсечки, то есть ДО снятия, и «сняли три» от «снимать было нечем» в ней не
// отличалось. Теперь снятие, отсечка и запись события ложатся ОДНОЙ
// транзакцией этого порта.
//
// Операторы в ней идут так: снятие записей, затем отсечка, затем событие.
//
// # ПОРЯДОК ЗАХВАТА СТРОК: ЛИЧНОСТЬ → СЕССИИ → ОТСЕЧКА
//
// Транзакция открывается УЖЕ держащей строку личности (`FOR KEY SHARE`) — до
// любой строки сессии. Это порядок каскада удаления личности: удаление берёт
// строку `users` и затем её записи сессии. Без этого замка строку личности брала
// проверка внешнего ключа отсечки — ПОСЛЕ строк сессии, то есть навстречу
// удалению, и сцена «выход × удаление личности» давала взаимную блокировку в
// 6 прогонах из 6, жертвой каждый раз удаление
// (`force_logout_identity_deletion_race_integration_test.go`).
//
// Снятие (`EndOtherSessions`) поднимает замок той же строки до замка писателя
// нескольких сессий (`FOR NO KEY UPDATE`) — раньше первой строки сессии. Им
// сериализуются все, кто снимает записи человека через эту дверь; перепись
// писателей нескольких строк сессии, и тех, кто в эту сериализацию не входит
// (уборка — она занятых строк не ждёт), — у `lockPersonForSessionSetSQL`
// (`repo/kaname/pg`). Без него
// смена пароля брала строки сессии «прочие → своя», а выход — все в порядке
// просмотра, и сцена «смена пароля первой → выход» давала взаимную блокировку в
// 3 прогонах из 3, жертвой каждый раз выход
// (`force_logout_concurrent_teardown_integration_test.go`).
//
// Каждое ожидание замка в транзакции ограничено `lockWait` (`lock_timeout`
// самой транзакции), а не сроком вызова. Ограничено каждое ожидание ОТДЕЛЬНО, а
// не их сумма: транзакция, ждущая по очереди нескольких держателей, может ждать
// кратно дольше `lockWait`.
//
// Реализуется `*repo/kaname/pg.HumanSessionRepo` — ТОЙ ЖЕ транзакцией записи,
// которой снимает свои записи полоса входа. Два писателя одной таблицы зовут один
// оператор (`endSessionsOfSQL`).
type OwnSessions interface {
	ForceLogoutWriter(ctx context.Context, subject domain.UserID, lockWait time.Duration) (OwnSessionsWriter, error)
}

// OwnSessionsWriter — ОДНА транзакция принудительного выхода:
// снятие наших записей, отсечка, запись события. Вызывающий обязан Commit либо
// Rollback.
type OwnSessionsWriter interface {
	// EndOtherSessions снимает живые записи личности, кроме keep, и отзывает
	// выданное в них; пустой keep снимает ВСЕ. Отвечает числом снятых.
	EndOtherSessions(ctx context.Context, userID domain.UserID, keep domain.HumanSessionID, at time.Time, reason string) (int, error)
	// UpsertCutoff — обе записи отсечки субъекта одной дверью.
	UpsertCutoff(ctx context.Context, u domain.UserTokenRevocation, revokedBy domain.UserID) error
	// EmitAudit — запись события в очередь аудита той же транзакцией.
	EmitAudit(ctx context.Context, ev outboxtypes.AuditEvent) error
	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
}

// WithOwnSessions — привязывает снятие НАШИХ записей сессии входа.
// Composition-root only.
//
// Непровязанный порт — закрытый отказ глагола (Unavailable), а не отсечка без
// снятия: «выведен» при стоящей сессии хуже, чем «повторите».
func (h *Handler) WithOwnSessions(s OwnSessions) *Handler {
	h.ownSessions = s
	return h
}

// WithOperations — attaches the Operation repository ForceLogout persists its
// operation row in. Composition-root only. A nil repo stays fail-closed
// (ForceLogout returns Unavailable): handing back an operation id that names no
// row is the very defect this wiring exists to prevent, so a wiring omission
// must refuse rather than answer with an unqueryable id.
func (h *Handler) WithOperations(r forceLogoutOperationRepo) *Handler {
	h.operations = r
	return h
}

// WithAdminChecker — attaches the defense-in-depth ReBAC system_admin@cluster
// gate enforced on ForceLogout. Composition-root only. nil checker stays
// fail-closed (requireSystemAdmin denies).
func (h *Handler) WithAdminChecker(c authzguard.RelationChecker) *Handler {
	h.adminCheck = c
	return h
}

// requireSystemAdmin — defense-in-depth in-iam gate for the privileged admin
// RPCs. Requires an authenticated principal holding system_admin@cluster in
// ReBAC. Additive to the gateway caller-policy (AuthN+AuthZ on every RPC,
// internal included, runs its own per-RPC Check — the caller-policy only proves
// WHO dialed :9091, not that the END USER is a cluster admin).
//
// Fail-closed everywhere — the revoke never runs unless the model said yes; the
// ANSWER still says what happened: anonymous / empty principal, nil checker or
// not-allowed → PermissionDenied; a checker that could not be reached →
// Unavailable (nothing was decided, an identical retry is worth making). Both are
// verbatim and non-leaking.
//
// acr step-up (required_acr_min) is enforced separately by the internal acr-floor
// (authzguard.ACRFloor) chained on the :9091 listener BEFORE this handler: when
// ForceLogout's catalog acr_min>0 (latent-until-policy today), the trusted
// forwarded acr (corelib grpcsrv x-kacho-token-acr) must satisfy it or the call
// is rejected with a step-up signal. This gate stays the per-user ReBAC Check;
// acr is no longer a gap on the internal route.
// The subject is named by SubjectFromPrincipal, not by joining "user:" to the id.
// `PrincipalUserID` deliberately admits `service_account` and `system` as well as
// `user`, so prefixing its result with "user:" asked the store about a subject that
// cannot exist whenever the caller was non-interactive — a machine cluster-admin was
// refused by construction, however it was granted. Found by census of this class
// after the same spelling was fixed in the invite gate; no e2e case covers this
// route, which is why it survived there.
func (h *Handler) requireSystemAdmin(ctx context.Context) error {
	subject, ok := authzguard.PrincipalSubject(ctx)
	if !ok {
		return status.Error(codes.PermissionDenied, "permission denied")
	}
	if h.adminCheck == nil {
		return status.Error(codes.PermissionDenied, "permission denied")
	}
	allowed, err := h.adminCheck.Check(ctx,
		subject, "system_admin", "cluster:"+domain.ClusterSingletonID)
	if err != nil {
		return authzguard.AuthzBackendUnavailable()
	}
	if !allowed {
		return status.Error(codes.PermissionDenied, "permission denied")
	}
	return nil
}

// ForceLogout — end the target's own login sessions and record a user-level
// revoke-all cutoff, with the audit event carrying the teardown's outcome.
//
// We set revoke_before = now(): a reader of the cutoff refuses any token whose
// session authenticated at or before it. Once the user re-authenticates, the
// authentication instant advances past the cutoff and new sessions are allowed
// again (no permanent lockout).
func (h *Handler) ForceLogout(ctx context.Context, req *iamv1.ForceLogoutRequest) (*operationpb.Operation, error) {
	// Defense-in-depth authZ FIRST: require an authenticated principal holding
	// system_admin@cluster (fail-closed). This RPC was previously ungated
	// (catalog `<exempt>`) — relying solely on the gateway caller-policy.
	if err := h.requireSystemAdmin(ctx); err != nil {
		return nil, err
	}
	userID := strings.TrimSpace(req.GetUserId())
	if userID == "" {
		return nil, shared.InvalidArg("user_id", "required")
	}
	// Отсечку, снятие наших записей и запись события кладёт ОДНА транзакция
	// (kaname#340). Непровязанный исполнитель — отказ до всякой записи.
	if h.ownSessions == nil {
		return nil, status.Error(codes.Unavailable, "login-session teardown not configured")
	}
	if h.operations == nil {
		return nil, status.Error(codes.Unavailable, "operation repository not configured")
	}

	// Свободная причина отсечки и события. Её умолчание — то же слово, что
	// причина снятия записи сессии (Р1): предмет у обеих записей один. Но
	// сама эта переменная в снятие не идёт — см. commitOwnForceLogout.
	reason := strings.TrimSpace(req.GetReason())
	if reason == "" {
		reason = domain.RevokeReasonAdminForceLogout
	}
	now := time.Now().UTC()

	marker := domain.UserTokenRevocation{
		UserID:       domain.UserID(userID),
		RevokeBefore: now,
		Reason:       reason,
	}
	if err := marker.Validate(); err != nil {
		return nil, shared.InvalidArg("user_token_revocation", err.Error())
	}

	// Audit actor (revoked_by) is sourced from the VERIFIED principal — never
	// from req.GetActorId(), which is client-supplied and spoofable. A non-empty
	// body actor_id that disagrees with the verified principal is a spoof
	// attempt → reject (InvalidArgument), rather than silently recording a
	// falsified audit actor. The gate above already guarantees a non-empty
	// authenticated principal.
	actor := authzguard.PrincipalUserID(ctx)
	if bodyActor := strings.TrimSpace(req.GetActorId()); bodyActor != "" && bodyActor != actor {
		return nil, status.Error(codes.InvalidArgument,
			"actor_id must match the authenticated principal")
	}
	revokedBy := domain.UserID(actor)

	// Persist the Operation (done=false) BEFORE the mutation — mirroring every
	// other mutation in this service, so the operation id the admin receives is
	// ALWAYS durably queryable. It used to be built in memory, stamped
	// done=true and returned without ever reaching the operations table: the
	// force-logout was invisible to OperationService.Get, to every operation
	// list and to every audit that reads operations.
	op, err := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Force logout user %s", userID),
		&iamv1.ForceLogoutMetadata{UserId: userID},
	)
	if err != nil {
		return nil, fmt.Errorf("build force-logout operation: %w", err)
	}
	if err := h.operations.Create(ctx, op); err != nil {
		return nil, fmt.Errorf("persist operation: %w", err)
	}

	// Отсечку, снятие наших записей и запись события кладёт ОДНА транзакция
	// (`forceLogoutOwnSessions`): запись события обязана лечь ПОСЛЕ снятия и
	// нести его исход (kaname#340).
	if err := h.forceLogoutOwnSessions(ctx, op.ID, marker, revokedBy); err != nil {
		return nil, err
	}

	// Complete the Operation: done=true, metadata + the declared response.
	//
	// revoked_count counts the revocation records this call committed — one
	// user-level cutoff, which denies every live token of the subject. It is
	// deliberately not 0: an inert 0-with-success is how the earlier
	// synthetic-jti implementation reported doing nothing, and the sibling
	// Revoke(revoke_all) path counts its cutoff the same way for the same reason.
	//
	// Контракт теперь говорит то же самое: комментарий поля объявляет, что
	// считаются ЗАПИСИ ОТЗЫВА, а не токены, — прежняя редакция описывала
	// пер-jti модель, которой у этого RPC нет (kacho#2486). Утверждение здесь и
	// в контракте — одно, и расходиться им больше негде.
	meta, resp, merr := forceLogoutOperationPayload(userID)
	if merr != nil {
		return nil, merr
	}
	// Отметка идёт на контексте, отвязанном от отмены запроса и ограниченном
	// своим сроком (`forceLogoutRecordBudget`): выход уже зафиксирован, и уход
	// вызывающего после этого не вправе оставить операцию вечно незавершённой.
	markCtx, cancelMark := forceLogoutRecordContext(ctx)
	defer cancelMark()
	if err := h.operations.MarkDoneWithMetadata(markCtx, op.ID, meta, resp); err != nil {
		// Non-fatal for the caller: the cutoff committed and the row exists, so
		// a poll answers (done=false) and never NotFound. Nothing finishes it
		// afterwards, so it is logged loudly, never swallowed (CWE-390).
		slog.ErrorContext(ctx, "ForceLogout: operation complete failed",
			"operation_id", op.ID, "err", err.Error())
	}
	op.Done = true
	op.Metadata = meta
	op.Response = resp

	return shared.OperationToProto(&op), nil
}

// failForceLogout — терминальный отказ на уже сохранённой операции: опрос видит
// настоящую ошибку, а не NotFound и не вечное done=false. Возвращает ту же
// ошибку для ответа вызывающему; сбой самой отметки пишется в журнал громко.
//
// Отметка идёт на контексте, отвязанном от отмены запроса: отказ, вызванный
// концом срока запроса, иначе не отмечался бы НИКОГДА — отметка на том же
// истёкшем сроке не доходит до базы.
func (h *Handler) failForceLogout(ctx context.Context, opID string, gerr error) error {
	markCtx, cancel := forceLogoutRecordContext(ctx)
	defer cancel()
	if merr := h.operations.MarkError(markCtx, opID, status.Convert(gerr).Proto()); merr != nil {
		slog.ErrorContext(ctx, "ForceLogout: operation error-mark failed",
			"operation_id", opID, "err", merr.Error())
	}
	return gerr
}

// Сроки принудительного выхода (kaname#340). Их два, и
// отношение между ними несущее.
const (
	// forceLogoutLockWait — предел ОДНОГО ожидания замка в транзакции выхода
	// (`lock_timeout`). Ограничено каждое ожидание отдельно, а не их сумма:
	// оператор, ждущий по очереди нескольких держателей, ждёт каждого до этого
	// предела. Строку сессии держат короткие транзакции — выдача кода,
	// перепредъявление, уборка, свой выход; операторы выдачи идут около
	// миллисекунды (замер у `lockUserForKeySQL`, `oauth_ceremony_repo.go`).
	//
	// Предел короче пяти секунд — срока одного вызова, который край ставит своим
	// обращениям к службе (`callTimeout` клиента субъектов и `backendCallTimeout`
	// посредника операций, `kacho/gateway`), — настолько, чтобы после ОДНОГО
	// ожидания, кончившегося отказом снятия, в тот же срок поместилась и запись
	// частичного исхода. Два и более последовательных ожидания в срок
	// вызывающего могут не уложиться; частичный исход ляжет и тогда — его
	// запись идёт на своём сроке (`forceLogoutRecordBudget`), — опоздать может
	// только ответ. Вызывающего самого принудительного выхода этот дом не знает,
	// и срока у него может не быть вовсе: тогда без своего предела ожидание
	// ограничивал бы только потолок оператора пула (30 с).
	forceLogoutLockWait = 2 * time.Second
	// forceLogoutRecordBudget — срок записей, отвязанных от отмены запроса:
	// частичного исхода и отметок операции. Отвязка снимает отмену, но не время:
	// повисшая база иначе держала бы обработчик без предела. Величина — та же,
	// что у прочих отвязанных записей службы (`refusalWriteBudget`,
	// `providerReleaseTimeout`), и каждая запись получает её целиком, а не
	// остаток.
	forceLogoutRecordBudget = 5 * time.Second
)

// forceLogoutRecordContext — контекст записи, отвязанный от отмены запроса и
// ограниченный `forceLogoutRecordBudget`. Значения запроса (принципал, след)
// сохраняются.
func forceLogoutRecordContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), forceLogoutRecordBudget)
}

// Шаг транзакции принудительного выхода, на котором она
// отказала (kaname#340). Словарь ЗАКРЫТ: шагов ровно пять, и у каждого СВОЙ
// контекст исполнения — от него и судится, кончился ли срок к моменту отказа.
type ownForceLogoutStep int

const (
	// ownStepOpen — открытие транзакции с замком строки личности; контекст попытки.
	ownStepOpen ownForceLogoutStep = iota + 1
	// ownStepTeardown — снятие наших записей; контекст попытки.
	ownStepTeardown
	// ownStepCutoff — отсечка; контекст попытки.
	ownStepCutoff
	// ownStepAudit — запись события; контекст попытки.
	ownStepAudit
	// ownStepCommit — фиксация; СВОЙ контекст, отвязанный от попытки
	// (`forceLogoutRecordContext`).
	ownStepCommit
)

// String — имя шага для журнала.
func (s ownForceLogoutStep) String() string {
	switch s {
	case ownStepOpen:
		return "open"
	case ownStepTeardown:
		return "teardown"
	case ownStepCutoff:
		return "cutoff"
	case ownStepAudit:
		return "audit"
	case ownStepCommit:
		return "commit"
	}
	return fmt.Sprintf("step(%d)", int(s))
}

// ownForceLogoutRefusal — отказ одной транзакции принудительного выхода: шаг,
// причина и сама ошибка хранилища. На любом шаге, кроме фиксации, транзакция
// откачена и не легло ничего; у отказа фиксации исход может быть НЕИЗВЕСТЕН —
// при конце её срока или обрыве соединения транзакция могла зафиксироваться на
// сервере, пока драйвер отвечал отказом.
type ownForceLogoutRefusal struct {
	step ownForceLogoutStep
	// contextEnded — к моменту отказа кончился контекст, на котором исполнялся
	// ЭТОТ шаг: у фиксации — её собственный срок, у прочих — контекст попытки.
	//
	// Судится по состоянию контекста, а не по ошибке, и форм у такого отказа
	// ДВЕ: до отправки оператора драйвер отвечает ошибкой контекста, а во время
	// исполнения пул службы доводит отмену до сервера (`CancelRequest`,
	// `corelib/db.NewPool`), и оператор снимается там строкой состояния `57014`,
	// без ошибки контекста в цепочке. Обе формы значат одно: контекст шага
	// кончился. Ошибка контекста в цепочке без конца контекста шага — не его
	// срок (так фиксация, исчерпавшая СВОЙ срок, выглядела бы концом запроса),
	// и признаком конца она не служит.
	//
	// Отказ кодом хранилища, пришедший в тот миг, когда контекст шага уже
	// кончился, читается концом контекста: различить их по ошибке нельзя
	// (вторая форма сама есть код хранилища), и решение правдиво в обе стороны —
	// вторая транзакция на своём сроке либо ляжет, либо упрётся в тот же отказ.
	contextEnded bool
	err          error
}

// refusalAt — отказ шага step, судимый по контексту stepCtx, на котором шаг
// исполнялся.
func refusalAt(step ownForceLogoutStep, stepCtx context.Context, err error) *ownForceLogoutRefusal {
	return &ownForceLogoutRefusal{step: step, contextEnded: stepCtx.Err() != nil, err: err}
}

// warrantsPartialOutcome — ведёт ли отказ ПЕРВОЙ транзакции ко второй: отсечке
// и записи «снятие не состоялось».
//
//	снятие                         — всегда: отказала сама половина, которую
//	                                 вторая не повторяет;
//	открытие · отсечка · событие   — только если кончился контекст попытки:
//	                                 вторая идёт на своём сроке и ляжет; отказ
//	                                 кодом хранилища она повторила бы;
//	фиксация                       — никогда: её исход может быть неизвестен, и
//	                                 вторая запись события легла бы поверх,
//	                                 возможно, состоявшегося выхода.
func (r *ownForceLogoutRefusal) warrantsPartialOutcome() bool {
	switch r.step {
	case ownStepTeardown:
		return true
	case ownStepOpen, ownStepCutoff, ownStepAudit:
		return r.contextEnded
	case ownStepCommit:
		return false
	}
	// Нулевого шага не производит ни один путь; неизвестный шаг ко второй
	// транзакции не ведёт — поверх неизвестного исхода её не кладут.
	return false
}

// answer — ответ вызывающему на этот отказ. Конец контекста шага — состояние,
// которое проходит, а не поломка службы: `Unavailable`, а не `Internal`,
// который дал бы общий перевод. Отказ замка в собственном пределе транзакции
// (`55P03`) переводит в недоступность уже хранилище. Остальное — общий перевод
// кода хранилища.
func (r *ownForceLogoutRefusal) answer() error {
	if r.contextEnded {
		return status.Error(codes.Unavailable, shared.UnavailableMessage)
	}
	return shared.MapRepoErr(r.err)
}

// Исход снятия в записи события принудительного выхода (kaname#340). Словарь
// ЗАКРЫТ и несёт ровно два слова: запись кладётся только там, где снятие
// пробовали, и третьего исхода — «не спрашивали» — у неё нет.
const (
	// forceLogoutTeardownEnded — снятие состоялось; число снятых названо рядом,
	// и ноль — законное значение: у человека могло не быть живой сессии.
	forceLogoutTeardownEnded = "ended"
	// forceLogoutTeardownFailed — снятие не состоялось: отказало само либо
	// откатилось вместе с первой транзакцией; отсечка легла, числа нет.
	forceLogoutTeardownFailed = "failed"
)

// forceLogoutAuditEvent — запись события принудительного выхода.
//
// Состав — четыре величины записи отсечки (актор · вид субъекта · субъект ·
// причина), те же, что кладёт дверь отзыва всех токенов, и сверх них ИСХОД
// снятия. Число снятых кладётся ТОЛЬКО при исходе «снято»: его отсутствие и есть
// утверждение «не дошло», а ноль остаётся отличимым от него значением. Материала
// удостоверений здесь нет — ни носителей, ни их свёрток.
//
// Прежде запись этого вида клала и та дверь — на посадке `external`, четырьмя
// величинами, без исхода. Посадка снята (kaname#363), и вида записи дверь
// больше не берёт (kaname#380): без исхода эта запись через неё непредставима.
func forceLogoutAuditEvent(marker domain.UserTokenRevocation, revokedBy domain.UserID,
	teardown string, ended int,
) outboxtypes.AuditEvent {
	payload := map[string]any{
		"actor":            string(revokedBy),
		"subject_type":     "user",
		"subject_id":       string(marker.UserID),
		"reason":           marker.Reason,
		"session_teardown": teardown,
	}
	if teardown == forceLogoutTeardownEnded {
		payload["sessions_ended"] = ended
	}
	return outboxtypes.AuditEvent{EventType: eventSessionForceLogout, Payload: payload}
}

// commitOwnForceLogout — ОДНА транзакция: [снятие наших записей] → отсечка →
// запись события → фиксация. withTeardown=false кладёт запись частичного исхода:
// отсечку и событие «снятие не состоялось».
//
// Отвечает числом снятых и nil либо отказом с его шагом; число значимо только
// без отказа. Отказ снятия не имеет представления на успешном пути — иначе он
// слился бы с «снимать было нечего».
//
// ФИКСАЦИЯ ИДЁТ НА СВОЁМ СРОКЕ, А НЕ НА СРОКЕ ПОПЫТКИ. Когда все операторы
// прошли, отмена во время `COMMIT` оставила бы исход неизвестным: транзакция
// могла зафиксироваться на сервере, пока драйвер отвечал отменой. Поэтому
// фиксация отвязана от отмены попытки и ограничена `forceLogoutRecordBudget`,
// как прочие записи, пережившие вызывающего, — и её отказ судится по ЭТОМУ
// сроку. Исход отказавшей фиксации может быть неизвестен (конец её срока,
// обрыв соединения), поэтому частичного исхода поверх отказа фиксации не
// кладётся ни при какой его причине (`warrantsPartialOutcome`): запись «снятие
// не состоялось» легла бы второй записью события, возможно ложной.
//
// ПРИЧИНА СНЯТИЯ — КОНСТАНТА ДОМЕНА, А НЕ ПРИЧИНА ИЗ ЗАПРОСА (kaname#334, Р2).
// Словарь `human_sessions_ended_reason_check` закрыт, и перечень его значений
// живёт только в домене (`domain.HumanSessionEndReasons`). Свободная причина
// распорядителя (`marker.Reason`) идёт в отсечку и в событие, а в снятие — нет:
// значение вне словаря база отвергла бы, и всякая причина, отличная от слова
// словаря, стоила бы самого снятия.
//
// Различение двух выходов несёт САМА СТРОКА СЕССИИ, а не журнал событий:
// выход человека кладёт событие `iam.session.logged_out`, и его состав НЕСЁТ
// `session_id` (`humansession/logout.go`); запись принудительного выхода несёт
// субъекта, причину и исход снятия (`forceLogoutAuditEvent`), а идентификатора
// сессии в ней НЕТ. От строки сессии к событию дороги нет, поэтому «человек
// вышел сам» от «его вывел распорядитель» отличает причина в самой строке
// (`ended_reason`).
func (h *Handler) commitOwnForceLogout(ctx context.Context, marker domain.UserTokenRevocation,
	revokedBy domain.UserID, withTeardown bool,
) (int, *ownForceLogoutRefusal) {
	w, err := h.ownSessions.ForceLogoutWriter(ctx, marker.UserID, forceLogoutLockWait)
	if err != nil {
		return 0, refusalAt(ownStepOpen, ctx, err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = w.Rollback(ctx)
		}
	}()

	outcome, ended := forceLogoutTeardownFailed, 0
	if withTeardown {
		n, terr := w.EndOtherSessions(ctx, marker.UserID, "", marker.RevokeBefore, domain.RevokeReasonAdminForceLogout)
		if terr != nil {
			return 0, refusalAt(ownStepTeardown, ctx, terr)
		}
		outcome, ended = forceLogoutTeardownEnded, n
	}
	if err := w.UpsertCutoff(ctx, marker, revokedBy); err != nil {
		return 0, refusalAt(ownStepCutoff, ctx, err)
	}
	if err := w.EmitAudit(ctx, forceLogoutAuditEvent(marker, revokedBy, outcome, ended)); err != nil {
		return 0, refusalAt(ownStepAudit, ctx, err)
	}
	commitCtx, cancelCommit := forceLogoutRecordContext(ctx)
	defer cancelCommit()
	if err := w.Commit(commitCtx); err != nil {
		return 0, refusalAt(ownStepCommit, commitCtx, err)
	}
	committed = true
	return ended, nil
}

// forceLogoutOwnSessions — принудительный выход: снятие наших
// записей сессии входа, отсечка и запись события с ИСХОДОМ снятия (kaname#340).
// nil — выход состоялся; иначе — ошибка для ответа, уже отмеченная на операции.
//
// # ПОРЯДОК: ЗАПИСЬ СОБЫТИЯ — ПОСЛЕ СНЯТИЯ, ВСЁ — ОДНОЙ ТРАНЗАКЦИЕЙ
//
// Снятие и отсечка лежат в ОДНОЙ базе, и делить их на две транзакции незачем:
// запись события, положенная транзакцией отсечки, ложилась до снятия и исхода
// нести не могла. Одна транзакция делает «сняли N» и «записано, что сняли N»
// одним фактом — и не оставляет закоммиченной отсечки без записи события.
//
// # РЕШЕНИЕ О ЧАСТИЧНОМ ИСХОДЕ: СНЯТИЕ ОТКАЗАЛО
//
// Отсечка ОСТАЁТСЯ. Это прежнее решение и прежний довод: она держится без
// чьего-либо содействия и идемпотентна, а откатить её вслед за снятием значило
// бы превратить отказ одной половины в отказ обеих — ровно в том случае, когда
// защита нужнее всего. Поэтому после отката первой транзакции ложится ВТОРАЯ:
// отсечка и запись события «снятие не состоялось» (`session_teardown: failed`,
// числа нет). Распорядителю отвечается отказом, а не «выведен», и операция
// отмечается ошибкой: он не должен считать выведенным того, чья сессия стоит.
//
// Между двумя транзакциями закоммиченного состояния нет, поэтому отсечка без
// записи события не существует ни в одном исходе. Если вторая отказывает до
// фиксации, не легло ничего — ни отсечки, ни записи; если отказывает её
// фиксация, легла она целиком либо не легла вовсе, и какое из двух — служба
// знать не может. Ответ в обоих случаях называет её отказ. Повтор
// глагола заново накладывает ту же отсечку (монотонно) и заново пробует снятие;
// каждая попытка оставляет свою запись со своим исходом.
//
// # ВТОРАЯ ТРАНЗАКЦИЯ НЕ ПРИНАДЛЕЖИТ СРОКУ ЗАПРОСА
//
// Снятие отказывает и оттого, что кончился срок самого запроса: оно ждало замка
// строки сессии или шло дольше, чем вызывающий готов ждать. Вторая транзакция
// на том же истёкшем сроке не открылась бы вовсе, и не легло бы НИЧЕГО — хуже
// прежнего порядка, где отсечка фиксировалась до снятия. Поэтому она идёт на
// контексте, отвязанном от отмены запроса и ограниченном своим сроком
// (`forceLogoutRecordBudget`), — при ЛЮБОЙ причине отказа снятия. Каждое
// ожидание замка в первой транзакции ограничено `forceLogoutLockWait`, и в
// сцене с одним держателем ответ приходит в срок вызывающего; при нескольких
// последовательных ожиданиях опоздать может ответ, но не частичный исход.
//
// # РЕШЕНИЕ О ЧАСТИЧНОМ ИСХОДЕ: СРОК ЗАПРОСА КОНЧИЛСЯ ПОСЛЕ СНЯТИЯ
//
// Снятие могло пройти, а срок запроса — кончиться на отсечке или записи
// события первой транзакции. Откатывается тогда вся она, снятие в том числе, и
// положение то же, что при отказе снятия: снятия нет, а защитная половина
// лечь может — вторая транзакция идёт на своём сроке. Поэтому отказ открытия,
// отсечки или записи события, пришедший, когда кончился срок запроса, ведёт ко
// второй так же, как отказ снятия: без второй транзакции не ложилось бы
// ничего — хуже порядка, где отсечка шла первой.
//
// # БЕЗ ЧАСТИЧНОГО ИСХОДА
//
// Отказ открытия, отсечки или записи события КОДОМ ХРАНИЛИЩА при живом сроке
// запроса — не частичный исход: откатывается всё, не ложится ничего, и ответ —
// общий перевод отказа хранилища; вторая транзакция упёрлась
// бы в тот же отказ. Так и с замком строки личности при открытии: не выдан он
// потому, что строку держит удаление личности, а отсечка без того же замка не
// ложится (её внешний ключ берёт его сам), и вторая транзакция упёрлась бы в
// ту же строку.
//
// Отказ ФИКСАЦИИ первой транзакции — не частичный исход ни при какой причине и
// ни при каком сроке запроса: её исход может быть неизвестен
// (`commitOwnForceLogout`). Ответ судится по её собственному сроку: конец его —
// недоступность, отказ кодом хранилища — его перевод. Повтор глагола заново
// накладывает ту же отсечку и заново пробует снятие.
//
// Во всех трёх случаях ответ вызывающему причины не несёт, и её вместе с шагом
// называет журнал.
func (h *Handler) forceLogoutOwnSessions(ctx context.Context, opID string,
	marker domain.UserTokenRevocation, revokedBy domain.UserID,
) error {
	ended, first := h.commitOwnForceLogout(ctx, marker, revokedBy, true)
	if first == nil {
		slog.InfoContext(ctx, "ForceLogout: own login sessions ended",
			"operation_id", opID, "user_id", string(marker.UserID), "sessions_ended", ended)
		return nil
	}
	if !first.warrantsPartialOutcome() {
		slog.ErrorContext(ctx, "ForceLogout: own force-logout transaction refused; no partial outcome is recorded",
			"operation_id", opID, "user_id", string(marker.UserID),
			"step", first.step.String(), "context_ended", first.contextEnded, "err", first.err.Error())
		return h.failForceLogout(ctx, opID, first.answer())
	}

	slog.ErrorContext(ctx, "ForceLogout: own login-session teardown did not land",
		"operation_id", opID, "user_id", string(marker.UserID),
		"step", first.step.String(), "err", first.err.Error())
	recordCtx, cancel := forceLogoutRecordContext(ctx)
	defer cancel()
	if _, partial := h.commitOwnForceLogout(recordCtx, marker, revokedBy, false); partial != nil {
		msg := "ForceLogout: the partial outcome could not be recorded; nothing was committed"
		if partial.step == ownStepCommit {
			msg = "ForceLogout: the partial outcome's commit was refused; whether it landed is unknown"
		}
		slog.ErrorContext(ctx, msg, "operation_id", opID, "user_id", string(marker.UserID),
			"step", partial.step.String(), "err", partial.err.Error())
		return h.failForceLogout(ctx, opID, partial.answer())
	}
	return h.failForceLogout(ctx, opID, status.Error(codes.Unavailable, "could not end the login session"))
}

// forceLogoutOperationPayload — the terminal (metadata, response) pair declared
// by `InternalIAMService.ForceLogout` (metadata: ForceLogoutMetadata,
// response: ForceLogoutResult).
func forceLogoutOperationPayload(userID string) (meta, resp *anypb.Any, err error) {
	meta, err = anypb.New(&iamv1.ForceLogoutMetadata{UserId: userID})
	if err != nil {
		return nil, nil, fmt.Errorf("marshal force-logout metadata: %w", err)
	}
	resp, err = anypb.New(&iamv1.ForceLogoutResult{RevokedCount: 1})
	if err != nil {
		return nil, nil, fmt.Errorf("marshal force-logout response: %w", err)
	}
	return meta, resp, nil
}
