// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// revoke.go — RevokeUseCase: record a session revocation.
//
// Writes one session_revocations row via the existing SessionRevocationsWriter
// adapter (RevokeWithAdmin → ON CONFLICT (token_jti) DO UPDATE — idempotent,
// ban #10 within-DB invariant on the table PK) and returns a synchronous
// Operation (done=true). No async worker is needed: the write is a single fast
// upsert and the LISTEN/NOTIFY fan-out to api-gateway pods is driven by the
// table trigger, not by an LRO worker.
//
// The Operation row is PERSISTED before the mutation and completed after it
// (same shape as InternalClusterService.GrantAdmin/RevokeAdmin). It used to be
// constructed in memory, stamped done=true and returned without ever touching
// the operations table: the id the caller was handed answered NotFound forever,
// the revocation appeared in no operation list and in no audit of operations,
// and `done=true` described nothing that had been written down.
package session_revocations

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/PRO-Robotech/kacho/pkg/operations"
	"github.com/PRO-Robotech/kacho/pkg/tokenpolicy"

	operationpb "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/operation"
	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// DefaultRevocationTTL — fallback retention when the caller omits ttl_expires_at.
// Must be ≥ the token's exp so the cache stays authoritative for the token's
// lifetime; 30d mirrors the proto docstring + the api-gateway logout handler.
//
// Экспортирована с задачи #1292: она — слагаемое ПОТОЛКА (ниже), и потолок
// проверяется пробой. Копия величины в пробе разошлась бы с продуктом молча.
//
// Названное и НЕ решённое здесь: 30 сут против потолка срока токена
// `MaxTokenTTL` в 30 мин — расхождение в 1440 раз, то есть строка держится на
// три порядка дольше, чем может жить токен, который она отвергает. Это не
// предмет уборки, а вопрос о том, какие токены адресует отзыв по `jti`;
// заведён задачей-преемником (§9 приёмки). Здесь важно лишь то, что величина
// ОБЪЯВЛЕНА и КОНЕЧНА.
const DefaultRevocationTTL = 30 * 24 * time.Hour

// MaxRevocationTTL — потолок срока строки отзыва.
//
// # Зачем потолок вообще
//
// Уборка НЕ ограничивает рост, пока срок строки называет вызывающий и потолка у
// него нет: строка с далёким горизонтом не удовлетворяет порогу
// `ttl_expires_at <= now()` НИКОГДА и переживает всякий проход при любом выборе
// интервала. Поверхность здесь Internal, но темп всё равно задаёт не iam.
//
// # Почему величина ВЫЧИСЛЯЕТСЯ, а не выбирается
//
// Новое число пришлось бы выбирать, а выбирать не из чего: контракт говорит
// «should be ≥ original token's exp», а `exp` вызывающий не присылает. Поэтому
// потолок — объявленный срок хранения продукта плюс допуск на расхождение
// часов. Вызывающий вправе УКОРОТИТЬ срок, но не удлинить его сверх того, что
// продукт объявил своим.
//
// # Слагаемое ClockSkew — не украшение
//
// Единственный вызывающий дерева (выход с края) присылает ровно
// `DefaultRevocationTTL`, но ЧАСАМИ КРАЯ. Потолок, вычисленный часами iam без
// запаса, отверг бы этот запрос всякий раз, когда часы края идут вперёд хоть на
// миллисекунду, — и отверг бы ТИХО: край логирует отказ предупреждением,
// отвечает 200 и кладёт текст в поле, у которого во всём дереве один писатель и
// ни одного читателя. Дефект был бы строго хуже того, который чинится: рост
// ограничен, отзыв не работает, следа нет.
const MaxRevocationTTL = DefaultRevocationTTL + tokenpolicy.ClockSkew

// eventSessionAllRevoked — audit_outbox taxonomy value for the
// revoke-all session path. Defined locally so the use-case stays free of a
// repo/pg import (clean-arch boundary); it must match the pg-side session
// taxonomy + audit_outbox_event_type CHECK. The single-jti path's event_type
// (iam.session.revoked) is owned by the tx-scoped RevokeTx adapter (always the
// same value, so it is not threaded through the port).
const eventSessionAllRevoked = "iam.session.all_revoked"

// sessionRevocationWriter — narrow write port. Implemented
// by *repo/kaname/pg.SessionRevocationsAdapter (the SAME adapter the refresh-hook
// reads through), so writer and reader share one table.
//
// Both methods are the tx-scoped *Tx variants — they commit the
// revocation AND the durable audit_outbox compliance row in ONE transaction
// (commit-together-or-rollback-together, запрет #10). eventType selects the
// audit taxonomy value (revoked / all_revoked).
//
//   - RevokeTx              — per-jti session_revocations row (single-token logout)
//   - iam.session.revoked audit row, atomically.
//   - RevokeAllUserTokensTx — per-user revoke-all cutoff (user_token_revocations)
//   - iam.session.all_revoked audit row, atomically. The cutoff is the gate the
//     refresh-hook enforces against the token's session auth_time.
type sessionRevocationWriter interface {
	RevokeTx(ctx context.Context, rev domain.SessionRevocation, revokedBy domain.UserID) error
	RevokeAllUserTokensTx(ctx context.Context, userID domain.UserID, revokeBefore time.Time, reason string, revokedBy domain.UserID, eventType string) error
}

// operationRepo — Operation-порт Revoke. Шире operations.Repo ровно на
// MetadataFinalizer, и это не удобство: `RevokeMetadata.revoked_count` знает
// только состоявшаяся запись (сколько ветвей реально отработало), а саму
// op-строку обязано создавать ДО мутации — иначе сбой Create оставит
// закоммиченную ревокацию без pollable операции. `MarkDone` третьим параметром
// берёт RESPONSE и metadata не трогает, то есть досчитать ею объявленное поле
// нельзя.
//
// Порт объявлен здесь, а не подменён type-assert'ом в рантайме, чтобы
// composition root не мог собраться с репозиторием, который эту запись не
// умеет: operations.NewRepo возвращает FullRepo, и несоответствие поймает
// компилятор.
type operationRepo interface {
	operations.Repo
	operations.MetadataFinalizer
}

// RevokeInput — transport-agnostic input the handler passes to the use-case.
type RevokeInput struct {
	TokenJTI            string
	UserID              string
	Reason              string
	TTLExpiresAt        *timestamppb.Timestamp
	RevokeAllUserTokens bool

	// RevokedBy — admin/actor who triggered the revocation (audit). "" for
	// user-self logout / system paths.
	RevokedBy string
}

// RevokeUseCase — orchestrates the single-row revocation write + Operation.
type RevokeUseCase struct {
	writer  sessionRevocationWriter
	opsRepo operationRepo
	now     func() time.Time
}

// NewRevokeUseCase — constructor. writer may be nil; the handler guards against
// a nil writer (fail-closed Unavailable) before calling Execute.
//
// opsRepo is a REQUIRED constructor parameter rather than a With…-option: an
// operation id that names no row is precisely the defect this use-case was
// fixed for, so a wiring omission must not be able to reintroduce it silently.
// A nil repo still fails closed at Execute (Unavailable) — the caller is told
// the mutation did not happen instead of receiving an unqueryable id.
func NewRevokeUseCase(writer sessionRevocationWriter, opsRepo operationRepo) *RevokeUseCase {
	return &RevokeUseCase{writer: writer, opsRepo: opsRepo, now: time.Now}
}

// Execute validates, writes the revocation(s), and returns a done Operation.
//
//   - revoke_all_user_tokens=true → write a per-user revoke-all cutoff
//     (revoke_before = now). This denies ALL the user's currently-live tokens at
//     refresh (the refresh-hook compares the token's session auth_time against
//     the cutoff). Previously the flag was silently ignored and one empty-jti
//     row was written (revoked_count=0) → a no-op reported as success.
//   - a per-jti token revoke (token_jti set) → write the single
//     session_revocations row, as before. Both may be set together.
func (uc *RevokeUseCase) Execute(ctx context.Context, in RevokeInput) (*operationpb.Operation, error) {
	if uc.writer == nil {
		// Defensive: an unwired writer must fail closed, never panic.
		return nil, status.Error(codes.Unavailable, "session revocation writer not configured")
	}
	if uc.opsRepo == nil {
		// Same fail-closed reasoning: without somewhere to persist the operation
		// the caller would get an id that answers NotFound forever. Refusing is
		// the honest answer.
		return nil, status.Error(codes.Unavailable, "operation repository not configured")
	}
	now := uc.now().UTC()
	revokedBy := domain.UserID(in.RevokedBy)

	reason := in.Reason
	if reason == "" {
		if in.RevokeAllUserTokens {
			reason = "admin-revoke"
		} else {
			reason = "user-logout"
		}
	}

	// ── Sync validation, BEFORE the operation row exists ────────────────────
	// A request that cannot be executed must be refused synchronously and leave
	// no trace, exactly as every other mutation in this service does.
	var marker *domain.UserTokenRevocation
	if in.RevokeAllUserTokens {
		m := domain.UserTokenRevocation{
			UserID:       domain.UserID(in.UserID),
			RevokeBefore: now,
			Reason:       reason,
		}
		if err := m.Validate(); err != nil {
			return nil, shared.InvalidArg("user_token_revocation", err.Error())
		}
		marker = &m
	}

	var rev *domain.SessionRevocation
	if in.TokenJTI != "" {
		// Присланная величина ПРИНИМАЕТСЯ ИЛИ ОТВЕРГАЕТСЯ — третьего исхода нет.
		//
		// Здесь стояло `if t.After(now) { ttl = t }`: момент в прошлом молча
		// выбрасывался, подставлялось умолчание, и вызывающий получал успех,
		// будучи уверен, что его величина применена. Проверка на этот случай
		// уже существовала и была НЕДОСТИЖИМА — `domain.SessionRevocation.
		// Validate` отвергает `ttl_expires_at <= revoked_at` каноничным
		// текстом, но до неё значение уже заменялось. Подстановка снята:
		// значение уходит в Validate, и отказ производит существующее правило.
		ttl := now.Add(DefaultRevocationTTL)
		if in.TTLExpiresAt != nil {
			ttl = in.TTLExpiresAt.AsTime().UTC()
			if ceiling := now.Add(MaxRevocationTTL); ttl.After(ceiling) {
				return nil, shared.InvalidArg("ttl_expires_at", fmt.Sprintf(
					"Illegal argument ttl_expires_at: must be at most %s from now (%s); "+
						"a row the sweep can never reach is not retention, it is unbounded growth",
					MaxRevocationTTL, ceiling.Format(time.RFC3339)))
			}
		}
		r := domain.SessionRevocation{
			TokenJTI:     in.TokenJTI,
			RevokedAt:    now,
			Reason:       reason,
			UserID:       domain.UserID(in.UserID),
			TTLExpiresAt: ttl,
		}
		if err := r.Validate(); err != nil {
			return nil, shared.InvalidArg("session_revocation", err.Error())
		}
		rev = &r
	}

	// ── Persist the Operation (done=false) BEFORE the mutation ──────────────
	// revoked_count is not knowable yet (it counts the branches that actually
	// commit), so the initial metadata carries only user_id; the full metadata
	// and the declared response are written by the terminal transition below.
	op, err := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Revoke session for user %s", in.UserID),
		&iamv1.RevokeMetadata{UserId: in.UserID},
	)
	if err != nil {
		return nil, fmt.Errorf("build revoke operation: %w", err)
	}
	if err := uc.opsRepo.Create(ctx, op); err != nil {
		return nil, fmt.Errorf("persist operation: %w", err)
	}

	// ── Mutate ──────────────────────────────────────────────────────────────
	revokedCount := int32(0)

	// User-level revoke-all cutoff — the gate the refresh-hook actually enforces.
	if marker != nil {
		if err := uc.writer.RevokeAllUserTokensTx(ctx, marker.UserID, marker.RevokeBefore, marker.Reason, revokedBy, eventSessionAllRevoked); err != nil {
			return nil, uc.failOperation(ctx, op.ID, err)
		}
		// A user-level revoke-all is a real, non-no-op revocation. Report ≥1 so
		// the metadata reflects reality (not the inert 0-with-success).
		revokedCount++
	}

	// Per-jti revoke — single-token logout path.
	if rev != nil {
		if err := uc.writer.RevokeTx(ctx, *rev, revokedBy); err != nil {
			return nil, uc.failOperation(ctx, op.ID, err)
		}
		revokedCount++
	}

	// ── Complete the Operation: done=true, full metadata + declared response ─
	meta, resp, merr := revokeOperationPayload(in.UserID, revokedCount, rev, marker)
	if merr != nil {
		return nil, merr
	}
	if err := uc.opsRepo.MarkDoneWithMetadata(ctx, op.ID, meta, resp); err != nil {
		// Non-fatal for the caller: the revocation committed and the operation
		// row exists, so a poll answers (done=false) and never NotFound. It is
		// NOT self-healing — no reconciler arm knows how to finish a session
		// revocation — so this is logged loudly, never swallowed (CWE-390).
		slog.ErrorContext(ctx, "session Revoke: operation complete failed",
			"operation_id", op.ID, "err", err.Error())
	}
	op.Done = true
	op.Metadata = meta
	op.Response = resp

	return shared.OperationToProto(&op), nil
}

// failOperation records the terminal failure on the already-persisted row so a
// poll sees a real error instead of a row nobody will ever finish, and returns
// the gRPC error the caller gets.
func (uc *RevokeUseCase) failOperation(ctx context.Context, opID string, cause error) error {
	gerr := shared.MapRepoErr(cause)
	if err := uc.opsRepo.MarkError(ctx, opID, status.Convert(gerr).Proto()); err != nil {
		slog.ErrorContext(ctx, "session Revoke: operation error-mark failed",
			"operation_id", opID, "err", err.Error())
	}
	return gerr
}

// revokeOperationPayload — the terminal (metadata, response) pair declared by
// `InternalSessionRevocationsService.Revoke` (metadata: RevokeMetadata,
// response: SessionRevocation).
//
// The declared response names the revocation that was recorded. On the per-jti
// path that is the row itself. On the bulk path there is no single token — the
// cutoff is user-level — so the response carries the user, the cutoff instant
// and the reason with an EMPTY token_jti, which is what was actually written.
// Leaving the response unset there would make the bulk revoke-all the one
// mutation in this service whose operation says nothing about its subject.
func revokeOperationPayload(
	userID string,
	revokedCount int32,
	rev *domain.SessionRevocation,
	marker *domain.UserTokenRevocation,
) (meta, resp *anypb.Any, err error) {
	meta, err = anypb.New(&iamv1.RevokeMetadata{
		RevokedCount: revokedCount,
		UserId:       userID,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("marshal revoke metadata: %w", err)
	}

	recorded := domain.SessionRevocation{}
	switch {
	case rev != nil:
		recorded = *rev
	case marker != nil:
		recorded = domain.SessionRevocation{
			UserID:    marker.UserID,
			RevokedAt: marker.RevokeBefore,
			Reason:    marker.Reason,
		}
	}
	resp, err = anypb.New(toProto(recorded))
	if err != nil {
		return nil, nil, fmt.Errorf("marshal revoke response: %w", err)
	}
	return meta, resp, nil
}
