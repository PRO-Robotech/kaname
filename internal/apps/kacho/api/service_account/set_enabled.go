// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package service_account

// set_enabled.go — Disable / Enable: the two explicit actions over the state
// that decides whether a service account may authenticate.
//
// WHY NOT A FIELD ON Update. Three reasons, each on its own sufficient:
//
//  1. An empty `update_mask` means full-object replacement by platform
//     convention, and a proto3 `bool` is indistinguishable from unset. A client
//     that simply did not fill the field in would disable the account —
//     silently, and for every account it touched. An action has no mask, so
//     there is nothing to forget.
//  2. "This account was taken out of service" is an EVENT, not the editing of an
//     attribute, and the audit trail has to be able to say so. A year from now
//     "who disabled the CI bot" must not be a question you answer by reading
//     diffs.
//  3. It is a change of security posture, which is the band where step-up
//     authentication applies. Routine lifecycle is not in that band, and the two
//     cannot share one RPC.
//
// IDEMPOTENT. The input is the STATE, not a transition: disabling an already
// disabled account succeeds and reports it disabled. The direction that makes a
// system safer must never be the one that fails on retry.
//
// WHAT IT DOES NOT DO. Access tokens already minted are not invalidated here;
// they run out on their own schedule. What stops at once is every path that
// mints a NEW one — the token hook (client_credentials and federated
// assertion), key issuance, and the docker-registry token endpoint. This is
// stated because the difference matters to whoever reaches for the control in
// an incident.

import (
	"context"
	"fmt"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// SetEnabledServiceAccountUseCase carries both directions. They differ in
// exactly two values — the state written and the event recorded — so they share
// one implementation rather than two that can drift apart. The constructors
// below are the public surface; nothing outside this file chooses the bool.
type SetEnabledServiceAccountUseCase struct {
	repo    Repo
	opsRepo operations.Repo
	enabled bool
}

// NewDisableServiceAccountUseCase — the account may no longer authenticate.
func NewDisableServiceAccountUseCase(r Repo, opsRepo operations.Repo) *SetEnabledServiceAccountUseCase {
	return &SetEnabledServiceAccountUseCase{repo: r, opsRepo: opsRepo, enabled: false}
}

// NewEnableServiceAccountUseCase — the account may authenticate again.
func NewEnableServiceAccountUseCase(r Repo, opsRepo operations.Repo) *SetEnabledServiceAccountUseCase {
	return &SetEnabledServiceAccountUseCase{repo: r, opsRepo: opsRepo, enabled: true}
}

func (u *SetEnabledServiceAccountUseCase) Execute(ctx context.Context, id domain.ServiceAccountID) (*operations.Operation, error) {
	// Anti-anonymous floor only. WHO may take this service account out of
	// service is decided by the MODEL: the api-gateway Checks
	// `v_update@iam_service_account:<service_account_id>` (plus the step-up
	// floor) before iam is dialed — security.md «Авторизация живёт в МОДЕЛИ, а
	// не в самодельных проверках». A second, hand-rolled rule here would not be
	// grantable, scopable, revocable or auditable, and it would lock machine
	// principals out of a control they are entitled to operate.
	if err := authzguard.RequireAuthenticated(ctx); err != nil {
		return nil, err
	}
	if err := shared.ValidateResourceID(string(id), domain.PrefixServiceAccount, "service account"); err != nil {
		return nil, err
	}

	// Existence + owning account, read before the Operation is minted: the
	// Operation metadata carries `account_id` so the account-scoped operations
	// feed includes this action, and an id that names nothing gets a synchronous
	// answer instead of an Operation that fails somewhere the caller has to go
	// and interpret.
	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	current, err := rd.ServiceAccounts().Get(ctx, id)
	_ = rd.Rollback(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}

	verb, eventType := "Disable", auditEventServiceAccountDisabled
	if u.enabled {
		verb, eventType = "Enable", auditEventServiceAccountEnabled
	}

	op, err := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("%s service account %s", verb, id),
		u.metadata(id, current.AccountID),
	)
	if err != nil {
		return nil, err
	}
	if err := u.opsRepo.Create(ctx, op); err != nil {
		return nil, err
	}

	actor := authzguard.PrincipalUserID(ctx)
	operations.Run(ctx, u.opsRepo, op.ID, func(ctx context.Context) (*anypb.Any, error) {
		return u.doSetEnabled(ctx, id, actor, eventType)
	})
	return &op, nil
}

// metadata picks the per-direction Operation metadata message. Two messages
// rather than one with a flag: the operations feed is read by people, and
// «Disable» and «Enable» are different things to find in it.
func (u *SetEnabledServiceAccountUseCase) metadata(id domain.ServiceAccountID, accountID domain.AccountID) proto.Message {
	if u.enabled {
		return &iamv1.EnableServiceAccountMetadata{
			ServiceAccountId: string(id), AccountId: string(accountID),
		}
	}
	return &iamv1.DisableServiceAccountMetadata{
		ServiceAccountId: string(id), AccountId: string(accountID),
	}
}

// doSetEnabled writes the state and records the event in the SAME writer-tx.
//
// Same transaction on purpose: a state change nobody can account for is worse
// than no state change, and an audit row for a write that rolled back is a lie
// in the opposite direction. Either both land or neither does.
//
// The audit row is emitted on every accepted call, including one that finds the
// account already in the requested state. Someone with the authority to do this
// asked for it, and «who tried, and when» is precisely what the trail is for —
// a repeat that leaves no trace is a repeat nobody can see.
func (u *SetEnabledServiceAccountUseCase) doSetEnabled(ctx context.Context, id domain.ServiceAccountID, actor, eventType string) (*anypb.Any, error) {
	updated, err := shared.DoWithWriteTx(ctx, u.repo,
		func(ctx context.Context, w Writer) (domain.ServiceAccount, error) {
			sa, serr := w.ServiceAccountsW().SetEnabled(ctx, id, u.enabled)
			if serr != nil {
				return domain.ServiceAccount{}, serr
			}
			if aerr := w.EmitAuditEvent(ctx, service.AuditEvent{
				EventType:       eventType,
				TenantAccountID: string(sa.AccountID),
				Payload: map[string]any{
					// WHO. The verified caller identity, never a value from the
					// request body.
					"actor": actor,
					// WHOM. The account acted upon, and the tenancy it belongs to.
					"resource_type": "service_account",
					"resource_id":   string(sa.ID),
					"account_id":    string(sa.AccountID),
					// The state the account was left in. Not the name of the
					// account: `name` is a mutable label and would date the
					// record; the id is what stays true.
					"enabled": sa.Enabled,
				},
			}); aerr != nil {
				return domain.ServiceAccount{}, aerr
			}
			return sa, nil
		})
	if err != nil {
		return nil, err
	}
	return marshalSA(updated)
}
