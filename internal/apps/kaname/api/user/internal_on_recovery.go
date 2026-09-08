// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package user

// internal_on_recovery.go — InternalUserService.OnRecoveryCompleted.
//
// Ory Kratos delivers this webhook (via api-gateway) after a successful
// self-service password-recovery flow. kaname:
//
//   1. validates the payload (all three fields required + length) — sync,
//      before spawning the Operation (malformed → INVALID_ARGUMENT);
//   2. resolves the User-row(s) by external_id among ACTIVE/BLOCKED — sync,
//      so unknown identity (NOT_FOUND) and email-mismatch (FAILED_PRECONDITION)
//      fail BEFORE any side-effect / Operation spawn;
//   3. async (Operation worker), in ONE writer-tx (запрет #10):
//        a. INSERT recovery_completions (recovery_jti, …, revoked_session_count)
//           ON CONFLICT DO NOTHING — the DB-level idempotency gate; 0-rows →
//           idempotent no-op (replay stored user_id / revoked_session_count, no
//           side-effects);
//        b. revoke-all cutoff (reason=password-change) for every affected row;
//        c. emit iam.user.recovery_completed audit (tenant_account_id =
//           primary User.AccountID);
//        d. commit (all-or-nothing — a mid-tx failure leaves no stuck key).
//
// Восстановление возвращает УЧЁТНЫЕ ДАННЫЕ, но не право пользоваться ими.
// Прежде тот же шаг переводил каждую заблокированную строку личности в
// действующую — то есть самостоятельное действие отменяло административное.
// Основанием служило «строка есть в {действующая, заблокированная}», хотя
// предметом было её состояние; выходило, что две половины одного пути
// компрометации смотрели в противоположные стороны: выдача токена
// заблокированному отказывала, а восстановление возвращало его в строй.
// Блокировка — административный акт; снимает её администратор. Самостоятельное
// восстановление доказывает владение почтовым ящиком — ровно то, чего
// администратор, ставя запрет, под сомнение не ставил.
//
// Отсечка (b) остаётся на КАЖДОЙ затронутой строке, включая заблокированную:
// обрубить живые сессии личности, чьи учётные данные только что сменили,
// полезно независимо от того, разрешено ли ей входить. Энфорсится она там, где
// токены ВЫДАЮТСЯ (internal/handler/iamhooks) — на обновлении одного её мало:
// у персонального токена доступа нет хука обновления, и такой токен не
// пересматривался бы вовсе.
//
// The idempotency key is the flow-scoped recovery_jti (one Kratos recovery flow
// = one event), NOT (user_id): one identity may own N User-rows across N
// Accounts, and recovery changes the identity credential as a whole → revoke
// touches all its live sessions.
//
// metadata.user_id is resolved synchronously (deterministic primary row = first
// by created_at ASC, mirroring UpsertFromIdentity.resolveUserID).
// metadata.revoked_session_count is the realized cutoff count, computed
// synchronously as the number of affected rows (one per-user cutoff each); on a
// duplicate delivery it is the stored count from the ledger.

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/kacho/pkg/operations"
	"github.com/PRO-Robotech/kacho/pkg/safeconv"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// auditEventUserRecoveryCompleted — audit_outbox taxonomy value for the recovery
// webhook (matches `iam.<resource>.<action>` + the
// audit_outbox_event_type CHECK).
const auditEventUserRecoveryCompleted = "iam.user.recovery_completed"

// recoveryRevokeReason — the user_token_revocations reason for a recovery-driven
// revoke-all (per proto docstring: password recovery == credential change).
const recoveryRevokeReason = "password-change"

// OnRecoveryCompletedInput — transport-agnostic input.
type OnRecoveryCompletedInput struct {
	ExternalID  domain.ExternalSubject
	RecoveryJTI string
	Email       domain.Email
}

// OnRecoveryCompletedUseCase — orchestrates the recovery webhook.
type OnRecoveryCompletedUseCase struct {
	repo    Repo
	opsRepo operations.Repo

	now    func() time.Time
	logger *slog.Logger
}

// NewOnRecoveryCompletedUseCase — constructor.
func NewOnRecoveryCompletedUseCase(r Repo, opsRepo operations.Repo) *OnRecoveryCompletedUseCase {
	return &OnRecoveryCompletedUseCase{repo: r, opsRepo: opsRepo, now: time.Now}
}

// WithLogger wires a logger for non-fatal warnings (composition root).
func (uc *OnRecoveryCompletedUseCase) WithLogger(logger *slog.Logger) *OnRecoveryCompletedUseCase {
	uc.logger = logger
	return uc
}

// recoveryStatuses — recovery resolves rows in ACTIVE or BLOCKED (PENDING rows
// hold external_id="" and can never be found by external_id).
var recoveryStatuses = []domain.InviteStatus{domain.InviteStatusActive, domain.InviteStatusBlocked}

func (uc *OnRecoveryCompletedUseCase) Execute(ctx context.Context, in OnRecoveryCompletedInput) (*operations.Operation, error) {
	// ── 1. Sync validation (before Operation spawn) ──────────────────────────
	if in.ExternalID == "" {
		return nil, shared.InvalidArg("external_id", "external_id required")
	}
	if in.RecoveryJTI == "" {
		return nil, shared.InvalidArg("recovery_jti", "recovery_jti required")
	}
	if in.Email == "" {
		return nil, shared.InvalidArg("email", "email required")
	}
	// Proto field caps (internal_user_service.proto): external_id <=128,
	// recovery_jti <=128, email <=320. The domain newtype validators are stricter
	// in places (ExternalSubject <=256), so enforce the proto contract explicitly
	// here (the length checks) before the cheaper format validation.
	if l := len(in.ExternalID); l > 128 {
		return nil, shared.InvalidArg("external_id", "external_id length must be <=128")
	}
	if l := len(in.RecoveryJTI); l > 128 {
		return nil, shared.InvalidArg("recovery_jti", "recovery_jti length must be <=128")
	}
	if l := len(in.Email); l > 320 {
		return nil, shared.InvalidArg("email", "email length must be <=320")
	}
	if err := in.ExternalID.Validate(); err != nil {
		return nil, shared.MapValidationErr(err)
	}
	if err := in.Email.Validate(); err != nil {
		return nil, shared.MapValidationErr(err)
	}

	// ── 2. Sync lookup + identity/email gate (no side-effects on rejection) ──
	rows, err := uc.findIdentity(ctx, in.ExternalID)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, shared.MapRepoErr(iamerr.Wrapf(iamerr.ErrNotFound, "User %s not found", in.ExternalID))
	}
	// Email must match the user (case-insensitive, as IAM matches email).
	matched := matchByEmail(rows, in.Email)
	if len(matched) == 0 {
		return nil, shared.MapRepoErr(iamerr.Wrapf(iamerr.ErrFailedPrecondition,
			"recovery email does not match user"))
	}
	// Deterministic primary row (first by created_at ASC, as findIdentity orders).
	primary := matched[0]
	matchedIDs := make([]domain.UserID, 0, len(matched))
	for _, m := range matched {
		matchedIDs = append(matchedIDs, m.ID)
	}

	// metadata.revoked_session_count: one per-user cutoff per affected row. The
	// matched set is deterministic by (external_id, email), so this count is
	// stable across a duplicate delivery (it equals the value stored in the
	// ledger at first processing) — no need to read the ledger synchronously.
	revokedCount := safeconv.IntToInt32(len(matchedIDs))

	// ── 3. Spawn Operation, run the writer-tx async ──────────────────────────
	op, err := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Recovery completed for identity %s", in.ExternalID),
		&iamv1.OnRecoveryCompletedMetadata{UserId: string(primary.ID), RevokedSessionCount: revokedCount},
	)
	if err != nil {
		return nil, err
	}
	if err := uc.opsRepo.Create(ctx, op); err != nil {
		return nil, err
	}

	operations.Run(ctx, uc.opsRepo, op.ID, func(ctx context.Context) (*anypb.Any, error) {
		return uc.doRecovery(ctx, in, primary, matchedIDs)
	})
	return &op, nil
}

// findIdentity returns the ACTIVE/BLOCKED rows of the identity ordered by
// created_at ASC (BLOCKED-aware reader — ground-truth nuance: ACTIVE-only
// FindActiveByExternalID would silently miss BLOCKED rows).
func (uc *OnRecoveryCompletedUseCase) findIdentity(ctx context.Context, ext domain.ExternalSubject) ([]domain.User, error) {
	rd, err := uc.repo.Reader(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	defer func() { _ = rd.Rollback(ctx) }()
	rows, err := rd.Users().FindByExternalIDInStatuses(ctx, ext, recoveryStatuses)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	return rows, nil
}

// matchByEmail keeps the rows whose email matches the recovery email
// (case-insensitive). Credential is an identity attribute; only rows sharing the
// external_id AND the matching email are recovered.
func matchByEmail(rows []domain.User, email domain.Email) []domain.User {
	out := make([]domain.User, 0, len(rows))
	for _, r := range rows {
		if strings.EqualFold(string(r.Email), string(email)) {
			out = append(out, r)
		}
	}
	return out
}

// doRecovery — the single writer-tx: idempotency-gate → revoke-all
// → audit → commit. On the conflict (already-processed) path it runs NONE of the
// side-effects and replays the stored metadata.
func (uc *OnRecoveryCompletedUseCase) doRecovery(
	ctx context.Context, in OnRecoveryCompletedInput, primary domain.User, matchedIDs []domain.UserID,
) (*anypb.Any, error) {
	now := uc.now().UTC()

	user, err := shared.DoWithWriteTx(ctx, uc.repo,
		func(ctx context.Context, w kanamerepo.Writer) (domain.User, error) {
			// (a) idempotency gate — ON CONFLICT DO NOTHING. revoked_session_count
			// is recorded with the ledger row so a duplicate replays it.
			rc := domain.RecoveryCompletion{
				RecoveryJTI:         in.RecoveryJTI,
				ExternalID:          in.ExternalID,
				UserID:              primary.ID,
				RevokedSessionCount: safeconv.IntToInt32(len(matchedIDs)),
			}
			_, inserted, err := w.InsertRecoveryCompletion(ctx, rc)
			if err != nil {
				return domain.User{}, err
			}
			if !inserted {
				// Already processed → idempotent no-op: run NO side-effects.
				return primary, nil
			}

			// (b) revoke-all cutoff (reason=password-change) per affected row.
			//
			// Один и тот же момент для всех строк — момент смены учётных данных
			// личности. Сессия, аутентифицировавшаяся до него, на выдаче
			// отвергается; тот, кто завершает восстановление, аутентифицируется
			// после и обслуживается. Заблокированная строка отсекается наравне с
			// прочими: её состояние решает, пустят ли её дальше, а не нужно ли
			// обрубать её старые сессии.
			var revokedCount int32
			for _, id := range matchedIDs {
				marker := domain.UserTokenRevocation{
					UserID:       id,
					RevokeBefore: now,
					Reason:       recoveryRevokeReason,
				}
				if verr := marker.Validate(); verr != nil {
					return domain.User{}, iamerr.Wrapf(iamerr.ErrInvalidArg, "%s", verr.Error())
				}
				if uerr := w.UpsertUserTokenRevokeAll(ctx, marker, ""); uerr != nil {
					return domain.User{}, uerr
				}
				revokedCount++
			}

			// (c) audit — same writer-tx (запрет #10). tenant_account_id =
			// primary User.AccountID. No secrets in payload.
			//
			// Поля «сняли ли блокировку» здесь больше нет: восстановление её не
			// снимает, и признак, который всегда ложь, — не запись о событии, а
			// обещание возможности, которой нет.
			if aerr := w.EmitAuditEvent(ctx, service.AuditEvent{
				EventType:       auditEventUserRecoveryCompleted,
				TenantAccountID: string(primary.AccountID),
				Payload: map[string]any{
					"actor":                 "system",
					"user_id":               string(primary.ID),
					"external_id":           string(in.ExternalID),
					"email":                 string(in.Email),
					"recovery_jti":          in.RecoveryJTI,
					"revoked_session_count": revokedCount,
				},
			}); aerr != nil {
				return domain.User{}, aerr
			}

			return primary, nil
		})
	if err != nil {
		return nil, err
	}
	return marshalUser(user)
}
