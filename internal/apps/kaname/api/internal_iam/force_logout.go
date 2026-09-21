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
// СНЯТИЕ САМОЙ СЕССИИ ВХОДА ИДЁТ ВТОРЫМ ДЕЙСТВИЕМ, и ЧЬЮ сессию снимать, решает
// посадка (kaname#313): под `external` — сессию у внешнего поставщика
// (`ProviderSessions`), под `own` — НАШУ строку `human_sessions`
// (`OwnSessions`). Провязан ровно один из двух: провязать оба значило бы на
// каждой посадке звать одного впустую, а под `own` — звать дорогу, которой нет,
// и отказывать всему глаголу за её отсутствием.
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
// Реализуется `*repo/kaname/pg.HumanSessionRepo` — ТЕМ ЖЕ адаптером, которым
// снимает свои записи полоса входа. Два писателя одной таблицы зовут один
// оператор (`endSessionsOfSQL`).
type OwnSessions interface {
	EndAllSessions(ctx context.Context, userID domain.UserID, at time.Time, reason string) (int, error)
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
	if h.sessionRevoker == nil {
		return nil, status.Error(codes.Unavailable, "session revocation writer not configured")
	}
	if h.operations == nil {
		return nil, status.Error(codes.Unavailable, "operation repository not configured")
	}

	reason := strings.TrimSpace(req.GetReason())
	if reason == "" {
		reason = "admin-force-logout"
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

	if err := h.sessionRevoker.RevokeAllUserTokensTx(ctx, marker.UserID, marker.RevokeBefore, marker.Reason, revokedBy, eventSessionForceLogout); err != nil {
		// Record the terminal failure on the already-persisted op so a poll sees
		// a real error, not NotFound; still surface the gRPC error to the caller.
		gerr := shared.MapRepoErr(err)
		if merr := h.operations.MarkError(ctx, op.ID, status.Convert(gerr).Proto()); merr != nil {
			slog.ErrorContext(ctx, "ForceLogout: operation error-mark failed",
				"operation_id", op.ID, "err", merr.Error())
		}
		return nil, gerr
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
	if h.ownSessions == nil && h.providerSessions == nil {
		gerr := status.Error(codes.Unavailable,
			"no login-session teardown is wired: the cutoff alone does not end a session")
		slog.ErrorContext(ctx, "ForceLogout: no login-session teardown is wired",
			"operation_id", op.ID, "user_id", userID)
		if merr := h.operations.MarkError(ctx, op.ID, status.Convert(gerr).Proto()); merr != nil {
			slog.ErrorContext(ctx, "ForceLogout: operation error-mark failed",
				"operation_id", op.ID, "err", merr.Error())
		}
		return nil, gerr
	}

	// СНЯТЬ НАШУ ЗАПИСЬ СЕССИИ ВХОДА, теперь когда отсечка устойчива
	// (kaname#313).
	//
	// Порядок тот же и по той же причине, что у снятия у чужого поставщика:
	// отсечка идёт первой, потому что держится без чьего-либо содействия;
	// снятие следует, потому что оно и превращает вечный отказ в выход.
	//
	// ПРИЧИНА СНЯТИЯ — `logout`, И ЭТО ЗАПИСАННЫЙ ОСТАТОК, А НЕ РЕШЕНИЕ ПО
	// СУЩЕСТВУ. Словарь `human_sessions_ended_reason_check` ЗАКРЫТ (`logout` ·
	// `password-change` · `second-factor-removed`), значения «выведен
	// распорядителем» в нём нет, а значение вне словаря база отвергла бы — то
	// есть попытка записать более точную причину стоила бы самого выхода.
	//
	// # ЧЕТВЁРТОЕ ЗНАЧЕНИЕ НУЖНО, И ЭТО ИЗМЕРЕНО, А НЕ ПРЕДПОЧТЕНО
	//
	// Довод «административную природу несёт журнал» ПРОВЕРЕН и оказался неверен
	// ровно наполовину — в той половине, которая нужна расследованию:
	//
	//   · выход человека кладёт событие `iam.session.logged_out`, и его состав
	//     НЕСЁТ `session_id` (`humansession/logout.go`);
	//   · принудительный выход кладёт `iam.session.force_logout`, и его состав —
	//     `actor`, `subject_type`, `subject_id`, `reason`
	//     (`pg.SessionRevocationsAdapter.RevokeAllUserTokensTx`). Идентификатора
	//     сессии в нём НЕТ.
	//
	// Значит от СТРОКИ СЕССИИ к событию дороги нет: обе записи несут `logout`,
	// и различить «человек вышел сам» от «его вывел распорядитель» можно только
	// совпадением моментов. Совпадение моментов — не свидетельство, а догадка, и
	// расследование инцидента платит эту цену ровно тогда, когда вопрос стоит
	// «кто оборвал эту сессию».
	//
	// РЕШЕНО: нужна миграция, добавляющая в словарь `admin-force-logout`.
	// Довод — безопасность, а не удобство: недозапись ПРИВИЛЕГИРОВАННОГО
	// действия над чужой сессией есть та сторона ошибки, которая подводит именно
	// в разборе происшествия. Сейчас она к тому же дёшева и однозначна:
	// значение ДОБАВЛЯЕТСЯ, обратное заполнение не нужно и не осмысленно — до
	// этой полосы принудительный выход не писал в эту колонку ВООБЩЕ, поэтому ни
	// одна лежащая строка не помечена неверно. Отложенная, та же миграция
	// потребует решения о прошлом, у которого верного ответа не будет.
	//
	// НОМЕРА У ЗАДАЧИ ПОКА НЕТ: задачи заводит не эта полоса, и до заведения
	// адресом остатка служит эта координата.
	//
	// ПРЕДИКАТ СНЯТИЯ ОСТАТКА: словарь
	// `human_sessions_ended_reason_check` несёт `admin-force-logout` — тогда
	// значение здесь меняется на него ОДНОЙ правкой, и пробы этого файла
	// краснеют, пока она не сделана.
	//
	// Ноль снятых записей — законный исход, а не отказ: у человека могло не быть
	// ни одной живой сессии, и требовать её значило бы отказывать в выходе тому,
	// кто уже вышел.
	if h.ownSessions != nil {
		ended, err := h.ownSessions.EndAllSessions(ctx, marker.UserID, now,
			domain.RevokeReasonLogout)
		if err == nil {
			// ЧИСЛО СНЯТОГО НАЗЫВАЕТСЯ НА УСПЕШНОМ ПУТИ (задача kaname#313).
			//
			// Без него «сняли три» и «снимать было нечем» наблюдаются
			// одинаково: тело операции несёт объявленную контрактом величину
			// ЗАПИСЕЙ ОТЗЫВА, а не число сессий, и по нему регрессию не видно.
			// Строка журнала — единственное место, где это число сегодня
			// наблюдаемо, и потому она стоит на успешном пути, а не только на
			// отказе.
			//
			// ОСТАТОК НАЗВАН, НОМЕРА У ЗАДАЧИ ПОКА НЕТ (заводит не эта полоса;
			// до заведения адресом служит эта координата): запись события
			// кладётся транзакцией отсечки, то
			// есть ДО снятия, и числа в себе не несёт. Свести их — менять
			// порядок, в котором отсечка идёт первой; это свой предмет.
			slog.InfoContext(ctx, "ForceLogout: own login sessions ended",
				"operation_id", op.ID, "user_id", userID, "sessions_ended", ended)
		}
		if err != nil {
			gerr := status.Error(codes.Unavailable, "could not end the login session")
			slog.ErrorContext(ctx, "ForceLogout: own login-session teardown failed",
				"operation_id", op.ID, "user_id", userID, "err", err.Error())
			if merr := h.operations.MarkError(ctx, op.ID, status.Convert(gerr).Proto()); merr != nil {
				slog.ErrorContext(ctx, "ForceLogout: operation error-mark failed",
					"operation_id", op.ID, "err", merr.Error())
			}
			return nil, gerr
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
			if merr := h.operations.MarkError(ctx, op.ID, status.Convert(gerr).Proto()); merr != nil {
				slog.ErrorContext(ctx, "ForceLogout: operation error-mark failed",
					"operation_id", op.ID, "err", merr.Error())
			}
			return nil, gerr
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
	if err := h.operations.MarkDoneWithMetadata(ctx, op.ID, meta, resp); err != nil {
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
