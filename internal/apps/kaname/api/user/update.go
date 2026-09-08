// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package user

// update.go — UpdateUserUseCase (новый публичный UpdateUser RPC, T3.3 D-1a).
//
// Единственное mutable поле User через этот Update — `labels` (tenant-facing
// метки, делающие User label-selectable). Identity-поля hard-immutable:
// `external_id` (IdP `sub`) и его camelCase-алиас — их наличие в update_mask →
// sync INVALID_ARGUMENT "externalId is immutable after User.Create" (первым
// стейтментом, до writer-tx). Мутация async → Operation (как все мутации).
//
// Изменение labels co-commit'ит reconcile-event на own-resource label-change в той
// же writer-tx (запрет #10) — reconciler ре-оценивает iam.user selector-биндинги
// (label add → грант появляется; label remove/change → eager fall-out), iam-direct
// аналог mirror-change-триггера.

import (
	"context"
	"fmt"
	"log/slog"

	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// UpdateUserInput — вход UpdateUser. `Labels` — единственное mutable-поле
// (flat-форма request'а несет только его). identity-поля User (external_id и пр.)
// в request не переносятся: их единственный путь — `update_mask`, где они
// reject'атся как hard-immutable.
type UpdateUserInput struct {
	ID         domain.UserID
	Labels     domain.Labels
	UpdateMask []string
}

// userMutableFields — поля, допустимые в update_mask UpdateUser.
var userMutableFields = map[string]struct{}{
	"labels": {},
}

// userImmutableFields — hard-immutable identity-поля: их наличие в update_mask →
// INVALID_ARGUMENT с per-field сообщением (паритет с остальными ресурсами).
var userImmutableFields = map[string]string{
	"external_id": "externalId is immutable after User.Create",
	"externalId":  "externalId is immutable after User.Create",
	"id":          "id is immutable after User.Create",
	"account_id":  "accountId is immutable after User.Create",
	"accountId":   "accountId is immutable after User.Create",
	"email":       "email is immutable after User.Create",
	"created_at":  "createdAt is immutable after User.Create",
	"createdAt":   "createdAt is immutable after User.Create",

	// invite_status НЕ является immutable — оно меняется, но ДЕЙСТВИЯМИ
	// (`UserService.Block` / `Unblock`), а не маской. Поэтому сообщение называет
	// путь, вместо того чтобы обещать неизменяемость: «immutable after Create»
	// было бы ложью и отправило бы читателя искать несуществующий обход.
	//
	// Запись живёт здесь, а не в списке mutable, потому что общий отказ
	// «неизвестное поле маски» формально верен и практически бесполезен: тот, кто
	// ищет, как приостановить участие, узнаёт лишь, что этот путь не тот. Обе
	// формы имени — маска приходит в proto-форме, но клиенты, транслирующие
	// JSON-имена буквально, присылают camelCase, и объяснение обязано быть одним.
	"invite_status": "inviteStatus is not updatable; use UserService.Block / UserService.Unblock",
	"inviteStatus":  "inviteStatus is not updatable; use UserService.Block / UserService.Unblock",
}

// ObjectForwardReconciler — narrow post-commit port: re-materialize the per-object
// access of ONE iam-native object across the bindings whose selectors match it.
// Deliberately narrower than the invite-flow ObjectReconciler (which also carries
// ReconcileBinding): this path never materializes a binding, only an object.
// Implemented by reconcile.Reconciler (the SAME single materialization path the
// reconcile worker and the cross-service RegisterResource drive). nil-safe: when
// unwired, the co-committed reconcile event + the periodic sweep remain the
// at-least-once backstop.
type ObjectForwardReconciler interface {
	// ReconcileObjectForward is the ADDITIVE forward fast-path for one object: it
	// materializes ONLY that object's per-object tuples across the matching bindings
	// while holding NO advisory lock at all (neither EXCLUSIVE nor SHARE, no O(scope)
	// recompute). It transparently
	// delegates to the FULL ReconcileObject when the object already has members
	// (delete-stale guard) — which is the branch a REVOCATION takes.
	ReconcileObjectForward(ctx context.Context, objectType, objectID string) error
	// ReconcileObject is the FULL EXCLUSIVE object-fan-out (async at-least-once backstop
	// — delete-stale / audit / sweep), driven by the reconcile worker off the
	// co-committed reconcile-outbox event.
	ReconcileObject(ctx context.Context, objectType, objectID string) error
}

type UpdateUserUseCase struct {
	repo    Repo
	opsRepo operations.Repo
	// Optional post-commit per-object materializer. A LABEL change flips iam-direct
	// selector membership, so the object must be re-materialized; nil-safe, the
	// co-committed reconcile event + periodic sweep remain the backstop.
	reconciler ObjectForwardReconciler
	logger     *slog.Logger
}

func NewUpdateUserUseCase(r Repo, opsRepo operations.Repo) *UpdateUserUseCase {
	return &UpdateUserUseCase{repo: r, opsRepo: opsRepo}
}

// WithObjectReconciler wires the post-commit per-object materializer used on a LABEL
// change (parity with the cross-service RegisterResource re-register path — see
// doUpdate). Optional; nil keeps the queue-only behaviour. The logger is used only to
// report a failed pass (the durable event + sweep still re-converge).
func (u *UpdateUserUseCase) WithObjectReconciler(r ObjectForwardReconciler, logger *slog.Logger) *UpdateUserUseCase {
	u.reconciler = r
	u.logger = logger
	return u
}

func (u *UpdateUserUseCase) Execute(ctx context.Context, in UpdateUserInput) (*operations.Operation, error) {
	// malformed id → sync INVALID_ARGUMENT первым стейтментом.
	if err := shared.ValidateResourceID(string(in.ID), domain.PrefixUser, "user"); err != nil {
		return nil, err
	}
	// update_mask discipline: immutable identity-поле → INVALID_ARGUMENT; unknown →
	// INVALID_ARGUMENT; пустой mask = full-PATCH над mutable labels.
	if err := shared.ValidateUpdateMask(in.UpdateMask, userMutableFields, userImmutableFields); err != nil {
		return nil, err
	}

	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	current, err := rd.Users().Get(ctx, in.ID)
	_ = rd.Rollback(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	// Anti-anon floor only. WHO may update this user is decided by the MODEL:
	// the api-gateway Checks `record_writer@iam_user:<user_id>` before iam is dialed
	// (каталог прав, `UserService/Update`). Здесь стояло `v_update` — отношение,
	// СНЯТОЕ с этого типа вместе со своим читателем (#1128, #1258).
	// The former in-service owner-equality check against the owning account's
	// owner_user_id was narrower than that per-object relation and unsatisfiable
	// by a machine principal — security.md «Авторизация живёт в МОДЕЛИ, а не в
	// самодельных проверках».
	if err := authzguard.RequireAuthenticated(ctx); err != nil {
		return nil, err
	}

	// Определяем применяемый labels-набор. labels применяются, только если mask их
	// разрешает (или пустой mask = full-PATCH). immutable identity-поля тела не
	// применяются ни при каком mask.
	target := current
	var changed []string
	if newLabels, apply := shared.ResolveLabelsUpdate(in.UpdateMask, in.Labels); apply && !shared.LabelsEqual(newLabels, current.Labels) {
		target.Labels = newLabels
		changed = append(changed, "labels")
	}
	if err := target.Validate(); err != nil {
		return nil, shared.MapValidationErr(err)
	}

	actor := authzguard.PrincipalUserID(ctx)

	op, err := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Update user %s", in.ID),
		// account_id from the loaded user → account-scoped operation listing.
		&iamv1.UpdateUserMetadata{UserId: string(in.ID), AccountId: string(current.AccountID)},
	)
	if err != nil {
		return nil, err
	}
	if err := u.opsRepo.Create(ctx, op); err != nil {
		return nil, err
	}
	labelsCopy := target.Labels
	changedCopy := append([]string{}, changed...)
	operations.Run(ctx, u.opsRepo, op.ID, func(ctx context.Context) (*anypb.Any, error) {
		return u.doUpdate(ctx, in.ID, labelsCopy, actor, changedCopy)
	})
	return &op, nil
}

// doUpdate applies the mutation in one writer-tx and, when the change can flip
// iam-direct selector membership (a LABEL change — the only mutable field here),
// re-materializes the object.
//
// WHY THE IN-PROCESS PASS. iam.user is label-selectable, so clearing a matching label
// is a REVOCATION. Its cross-service twin gets that for free: vpc/compute/nlb re-call
// InternalIAMService.RegisterResource on a label update, and RegisterResource runs
// ReconcileObjectForward in-process — the forward's delete-stale guard sees the object
// already has members, hands it to the FULL ReconcileObject, and the stale grant dies
// there. The iam-native path had no such pass: it enqueued a resource_reconcile_outbox
// event and returned, which made revoke latency the DEPTH OF THE GLOBAL RECONCILE
// QUEUE. That queue is strictly FIFO and drained by a single worker at ~5 events/s,
// each event a FULL O(scope) recompute, while the e2e suite produces 5-8 events/s — so
// it runs a multi-minute backlog. Measured on the stand for the sibling iam.project
// path: the label-clear event was enqueued at 19:59:18.97 and drained at 20:06:49.82
// (7m30s); the tuple survived until the 30s periodic sweep reached that binding at
// 20:00:23, 65s after the clear, long past any client budget.
//
// OFF THE done-PATH (ban #9). The pass is scheduled detached: Operation.done reports
// that the user row is durable, never that its tuples converged. The co-committed
// reconcile event above and the periodic sweep stay the at-least-once backstop, so this
// changes WHEN the revoke is observed, not WHETHER it happens.
func (u *UpdateUserUseCase) doUpdate(ctx context.Context, id domain.UserID, labels domain.Labels, actor string, changed []string) (*anypb.Any, error) {
	updated, err := shared.DoWithWriteTx(ctx, u.repo,
		func(ctx context.Context, w Writer) (domain.User, error) {
			if len(changed) == 0 {
				// Нечего применять (labels не изменились) — read-back актуального row.
				rd := w.Users()
				return rd.Get(ctx, id)
			}
			upd, uerr := w.UsersW().UpdateLabels(ctx, id, labels)
			if uerr != nil {
				return domain.User{}, uerr
			}
			if aerr := w.EmitAuditEvent(ctx, service.AuditEvent{
				EventType:       auditEventUserUpdated,
				TenantAccountID: string(upd.AccountID),
				Payload: map[string]any{
					"actor":          actor,
					"resource_type":  "user",
					"resource_id":    string(upd.ID),
					"account_id":     string(upd.AccountID),
					"changed_fields": changed,
				},
			}); aerr != nil {
				return domain.User{}, aerr
			}
			// Own-resource label-change co-commit reconcile-триггер в ЭТОЙ writer-tx
			// (запрет #10): reconciler ре-оценит iam.user selector-биндинги (≤2s) —
			// label add → грант появляется, label remove/change → eager fall-out.
			if rerr := w.EmitReconcileEvent(ctx, shared.ReconcileEventUpsert, "iam.user", string(upd.ID)); rerr != nil {
				return domain.User{}, rerr
			}
			return upd, nil
		})
	if err != nil {
		return nil, err
	}
	// Label change ⇒ selector membership may have flipped ⇒ re-materialize this ONE
	// object now instead of waiting out the FIFO reconcile queue (see the doc above).
	// ReconcileObjectForward is the same entry point the cross-service register path
	// uses: its delete-stale guard finds the existing members and delegates to the FULL
	// ReconcileObject, which is what actually revokes a now-unmatched grant.
	if labelsChanged(changed) && u.reconciler != nil {
		uid := string(updated.ID)
		shared.GoPostCommit(ctx, u.logger, "user label re-materialization", func(ctx context.Context) {
			if rerr := u.reconciler.ReconcileObjectForward(ctx, "iam.user", uid); rerr != nil && u.logger != nil {
				u.logger.Error("user update: label re-materialization failed (reconcile event + sweep will retry)",
					"user_id", uid, "err", rerr)
			}
		})
	}
	return marshalUser(updated)
}

// labelsChanged reports whether "labels" is among the changed fields of a User.Update.
// Today labels are the only mutable field, so this is equivalent to len(changed) > 0 —
// it is written explicitly so that adding a further mutable field cannot silently start
// paying (or, worse, start skipping) the O(scope) re-materialization pass.
func labelsChanged(changed []string) bool {
	for _, f := range changed {
		if f == "labels" {
			return true
		}
	}
	return false
}
