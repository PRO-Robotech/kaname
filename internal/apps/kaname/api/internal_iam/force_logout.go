// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// force_logout.go — InternalIAMService.ForceLogout.
//
// ForceLogout — admin force-logout: records a USER-LEVEL revoke-all cutoff
// (user_token_revocations.revoke_before = now) for the target subject so the
// refresh-hook denies ALL of the user's currently-live tokens (it compares the
// token's session auth_time against the cutoff). Reuses the SAME adapter as the
// user-logout / Revoke(revoke_all) paths. Async per the proto envelope (returns
// Operation, done=true). The earlier per-jti synthetic-jti write was inert — a
// synthetic jti can never match the target's real live-token jti.
//
// СНЯТИЕ САМОЙ СЕССИИ ВХОДА — второе действие, и ЧЬЮ сессию снимать, решает
// посадка (kaname#313): под `external` — сессию у внешнего поставщика
// (`ProviderSessions`), после транзакции отсечки; под `own` — НАШУ строку
// `human_sessions` (`OwnSessions`), в ОДНОЙ транзакции с отсечкой и записью
// события, которая несёт исход снятия (kaname#340). Провязан ровно один из
// двух: провязать оба значило бы на каждой посадке звать одного впустую, а под
// `own` — звать дорогу, которой нет, и отказывать всему глаголу за её
// отсутствием.
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

// sessionRevoker — narrow write port for ForceLogout.
// Implemented by *repo/kaname/pg.SessionRevocationsAdapter — the SAME adapter
// the user-logout Revoke path and the refresh-hook share.
//
// ForceLogout writes a USER-LEVEL revoke-all cutoff (the gate the refresh-hook
// actually enforces against the token's real session auth_time), NOT a per-jti
// row. The previous per-jti synthetic-jti approach was inert: the synthetic
// "force-logout:<user>:<unixnano>" never equals the target's real live-token
// jti, so the refresh-hook jti gate (WHERE token_jti=$1) never matched.
//
// The tx-scoped RevokeAllUserTokensTx commits the cutoff AND the durable
// iam.session.force_logout audit_outbox row in ONE transaction
// (commit-together-or-rollback-together, запрет #10). eventType selects the
// audit taxonomy value (force_logout for this RPC).
//
// ForceLogout зовёт его там, где НАШИХ записей сессии нет, — на посадке
// `external` и там, где исполнитель снятия не провязан вовсе. Под `own` отсечку
// кладёт транзакция снятия (`OwnSessionsWriter`, kaname#340): запись события
// обязана лечь ПОСЛЕ снятия и нести его исход, а транзакция этого порта снятия
// не видит.
type sessionRevoker interface {
	RevokeAllUserTokensTx(ctx context.Context, userID domain.UserID, revokeBefore time.Time, reason string, revokedBy domain.UserID, eventType string) error
}

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

// ProviderSessions — the identity provider's login-session surface.
//
// Force-logout writes a cutoff that stops tokens from being ISSUED. That is the
// authoritative half, and on its own it leaves the person's browser holding a
// live session: when that session asks again it presents its ORIGINAL
// authentication instant, which the cutoff refuses — correctly, and forever,
// with nothing prompting the re-authentication that would clear it. Ending the
// session is what turns a standing refusal into a logout.
//
// Реализуется `*clients.HydraAdminClient`. Пусто на посадке, которая внешнего
// поставщика не объявляет вовсе: там сессия входа — НАША строка, и снимает её
// `OwnSessions` ниже. Пусто и тогда, когда административная поверхность
// поставщика просто не настроена; там отсечка по-прежнему пишется и
// по-прежнему действует.
//
// ИМЕНОВАН НАРУЖУ: провязывается он теперь ПО ПОСАДКЕ, и композиционный корень
// обязан уметь вернуть «никого» ЧИСТЫМ nil. Возврат типизированного nil мимо
// интерфейса прошёл бы страж провязки насквозь — и снятие сессии падало бы на
// разыменовании вместо честного «на этой посадке снимать нечего» (kaname#313).
type ProviderSessions interface {
	DeleteLoginSessions(ctx context.Context, subject string) error
}

// ExternalIDResolver maps a kacho user id to the identity the provider knows.
//
// The two are different namespaces and neither substitutes for the other:
// force-logout names a `users.id`, the provider keys its sessions on the
// subject it issued. Passing one where the other belongs would delete nothing
// and report success.
//
// Именован наружу по той же причине, что и порт выше.
type ExternalIDResolver interface {
	ExternalIDOf(ctx context.Context, id domain.UserID) (string, error)
}

// WithProviderSessions — attaches the provider's login-session surface and the
// resolver that names a user to it. Both or neither: a teardown that cannot
// resolve its subject is not a teardown.
func (h *Handler) WithProviderSessions(p ProviderSessions, r ExternalIDResolver) *Handler {
	if p == nil || r == nil {
		return h
	}
	h.providerSessions = p
	h.externalIDs = r
	return h
}

// OwnSessions — НАШИ записи сессии входа (`human_sessions`), снимаемые целиком
// по личности (kaname#313).
//
// # ПОЧЕМУ ЭТО ВТОРОЙ ПОРТ, А НЕ ВТОРАЯ РЕАЛИЗАЦИЯ ПЕРВОГО
//
// `ProviderSessions` адресует субъекта ЧУЖИМИ именами: снятие идёт по внешнему
// субъекту, которого на посадке `own` не существует вовсе, и резолвер этого
// имени там отказывает by construction. Здесь предмет адресуется `users.id` —
// тем самым, который назвал распорядитель. Подставить один порт под другой
// значило бы подставить и разрешение имени, которого нет.
//
// # ПОЧЕМУ ОТСЕЧКИ НЕ ХВАТАЕТ, И ЭТО ИЗМЕРЕНО, А НЕ ПРЕДПОЛОЖЕНО
//
// Отсечка субъекта (`user_token_revocations.revoke_before`) действует на
// ВЫДАЧЕ: её читают хуки выдачи и край. Резолв нашей сессии её НЕ ПРИМЕНЯЕТ и
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

// OwnSessionsWriter — ОДНА транзакция принудительного выхода на посадке `own`:
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
// Composition-root only, посадка `own`.
//
// nil оставляет прежнее поведение: отсечка пишется, наши записи не трогаются.
// Это законно ровно там, где наших записей и нет, — под `external` полоса входа
// не поднимается вовсе, и снимать нечего.
func (h *Handler) WithOwnSessions(s OwnSessions) *Handler {
	if s == nil {
		return h
	}
	h.ownSessions = s
	return h
}

// WithSessionRevoker — attaches the session-revocation writer used by
// ForceLogout. Composition-root only (cmd/kaname/wiring.go).
func (h *Handler) WithSessionRevoker(r sessionRevoker) *Handler {
	h.sessionRevoker = r
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

// ForceLogout — record a user-level revoke-all cutoff for the target subject so
// the refresh-hook denies ALL of the user's currently-live tokens.
//
// We set revoke_before = now(): the refresh-hook denies any token whose session
// authenticated at or before this cutoff (compared against the Hydra session
// auth_time). Once the user re-authenticates, auth_time advances past the cutoff
// and new sessions are allowed again (no permanent lockout). This actually
// denies live tokens — unlike the old per-jti synthetic-jti row, which was inert
// (a synthetic jti never matches the target's real token jti).
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
	// Писатель отсечки выбирается посадкой: под `own` её кладёт транзакция
	// снятия наших записей (kaname#340), на прочих — `sessionRevoker`. Отказ
	// здесь — ровно тогда, когда нет НИ ОДНОГО из двух.
	if h.ownSessions == nil && h.sessionRevoker == nil {
		return nil, status.Error(codes.Unavailable, "session revocation writer not configured")
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

	// ЧЕЙ ПИСАТЕЛЬ КЛАДЁТ ОТСЕЧКУ, РЕШАЕТ ПОСАДКА (kaname#340).
	//
	// Под `own` отсечку, снятие наших записей и запись события кладёт ОДНА
	// транзакция (`forceLogoutOwnSessions`): запись события обязана лечь ПОСЛЕ
	// снятия и нести его исход. На прочих посадках наших записей нет, и отсечку
	// вместе с записью события кладёт `sessionRevoker` — как и прежде, до снятия
	// у поставщика: исход снятия у поставщика числом не выражается.
	if h.ownSessions != nil {
		if err := h.forceLogoutOwnSessions(ctx, op.ID, marker, revokedBy); err != nil {
			return nil, err
		}
	} else {
		if err := h.sessionRevoker.RevokeAllUserTokensTx(ctx, marker.UserID, marker.RevokeBefore, marker.Reason, revokedBy, eventSessionForceLogout); err != nil {
			// Record the terminal failure on the already-persisted op so a poll sees
			// a real error, not NotFound; still surface the gRPC error to the caller.
			return nil, h.failForceLogout(ctx, op.ID, shared.MapRepoErr(err))
		}

		// НИ ОДНОГО ИСПОЛНИТЕЛЯ СНЯТИЯ — ЗАКРЫТЫЙ ОТКАЗ, А НЕ МОЛЧАЛИВОЕ
		// НИЧЕГОНЕДЕЛАНИЕ (задача kaname#313).
		//
		// Исполнителей снятия два, и посадка выбирает РОВНО ОДНОГО: под `own` —
		// наши записи, под `external` — сессию у поставщика. Ни одного не провязано
		// — значит глагол пишет отсечку и НЕ СНИМАЕТ НИЧЕГО, отвечая успехом.
		// Регрессия провязки в этом состоянии неотличима от исправной работы: тот
		// же код ответа, то же тело операции, та же запись журнала, — и увидеть
		// разницу можно только запросом в базу.
		//
		// Довод тот же, которым закрыт читатель отсечки у соседа: непровязка,
		// отвечающая успехом, молча снимает контроль.
		//
		// СТОИТ ЗДЕСЬ, А НЕ ВЫШЕ, НАМЕРЕННО: отсечка уже закоммичена и остаётся —
		// она защитна сама по себе и идемпотентна. Теряется только ложное
		// «выведен», а повтор глагола после починки провязки доснимет сессию.
		//
		// ОДНА НОГА ЭТОГО ДОВОДА НЕ ПЕРЕМЕРЕНА ЗДЕСЬ, и сказано это затем, чтобы
		// через месяц довод не прочли как доказанный целиком. «Отсечка защитна сама
		// по себе» опирается на то, ЧТО С НЕЙ ДЕЛАЮТ ЧИТАТЕЛИ: хуки выдачи и край.
		// Край живёт в другом доме, и настоящий дифф его поведения не измеряет —
		// измерено здесь только то, что записи кладутся и что по ним судит
		// авторитет отзыва на пути запроса. Если читатель отсечку не применит,
		// защитной она не будет, и этот довод рухнет вместе с ним.
		//
		// ПРЕДИКАТ ПРОВЕРКИ: сквозная проба, предъявляющая носитель КРАЮ до и после
		// глагола. Её здесь нет и быть не может — дом другой.
		if h.providerSessions == nil {
			gerr := status.Error(codes.Unavailable,
				"no login-session teardown is wired: the cutoff alone does not end a session")
			slog.ErrorContext(ctx, "ForceLogout: no login-session teardown is wired",
				"operation_id", op.ID, "user_id", userID)
			return nil, h.failForceLogout(ctx, op.ID, gerr)
		}
	}

	// End the session at the provider, now that the cutoff is durable.
	//
	// Order is deliberate. The cutoff goes first because it is the half that
	// holds without anyone's cooperation; the teardown follows because it is the
	// half that makes the refusal recoverable. If the provider cannot be reached
	// the cutoff STAYS — it is protective and idempotent — but the call reports
	// failure: an administrator told "logged out" while the session is still
	// standing is worse off than one told to retry. Retrying re-applies the same
	// cutoff and re-attempts the same teardown, both idempotent.
	if h.providerSessions != nil {
		if err := h.endProviderSession(ctx, marker.UserID); err != nil {
			gerr := status.Error(codes.Unavailable, "could not end the session at the identity provider")
			slog.ErrorContext(ctx, "ForceLogout: provider session teardown failed",
				"operation_id", op.ID, "user_id", userID, "err", err.Error())
			return nil, h.failForceLogout(ctx, op.ID, gerr)
		}
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

// Сроки принудительного выхода на посадке `own` (kaname#340). Их два, и
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

// Шаг транзакции принудительного выхода на посадке `own`, на котором она
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

// forceLogoutAuditEvent — запись события принудительного выхода на посадке `own`.
//
// Состав — те же четыре величины, что кладёт транзакция отсечки на прочих
// посадках (актор · вид субъекта · субъект · причина), и сверх них ИСХОД
// снятия. Число снятых кладётся ТОЛЬКО при исходе «снято»: его отсутствие и есть
// утверждение «не дошло», а ноль остаётся отличимым от него значением. Материала
// удостоверений здесь нет — ни носителей, ни их свёрток.
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

// forceLogoutOwnSessions — принудительный выход на посадке `own`: снятие наших
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
// перевод отказа хранилища, как на прочих посадках; вторая транзакция упёрлась
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

// endProviderSession resolves the target to the identity the provider knows and
// ends every login session it holds for them.
//
// A subject that cannot be resolved is an error, not a skip: silently doing
// nothing here is exactly the shape of the defect this closes.
func (h *Handler) endProviderSession(ctx context.Context, userID domain.UserID) error {
	subject, err := h.externalIDs.ExternalIDOf(ctx, userID)
	if err != nil {
		return fmt.Errorf("resolve external subject of %s: %w", userID, err)
	}
	if subject == "" {
		return fmt.Errorf("user %s has no external subject to end sessions for", userID)
	}
	return h.providerSessions.DeleteLoginSessions(ctx, subject)
}
