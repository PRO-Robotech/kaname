// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package user

// set_blocked.go — Block / Unblock: the two explicit actions over the state that
// decides whether a person still participates in an Account.
//
// ЧЕГО ЭТО КАСАЕТСЯ — ЛИЧНОСТИ ЦЕЛИКОМ, а не одного аккаунта (kacho#470/#981).
//
// Строка `users` БОЛЬШЕ НЕ ЕСТЬ ЧЛЕНСТВО. У человека одна строка на всю
// платформу — это держат глобальные ключи `users_identity_email_uniq` и
// `users_identity_external_id_uniq` (миграция 20260823050000), — а
// принадлежность аккаунтам выражается строками `memberships`, которых у него
// может быть несколько. Значит запрет, записанный в состояние строки, достаёт
// до КАЖДОГО аккаунта человека, и администратор одного аккаунта отключает его
// везде.
//
// Это следствие решения владельца «блокировка есть свойство личности»
// (вопрос В-8 приёмки IAM-ID-1), а не побочный эффект: членства при запрете НЕ
// трогаются, и снятие запрета их тоже не трогает.
//
// > [!warning] Здесь стояло обратное, и оно пережило свой предмет
// > Прежняя редакция объявляла запрет пер-аккаунтным: «a block belongs to the
// > Account that issued it, and the admin of Account A cannot switch a person
// > off in Account B». Это было верно ровно до того, как строка перестала быть
// > членством. Утверждение опасно не само по себе, а тем, что читается как
// > действующее ограничение безопасности: следующий, кто придёт сюда за
// > радиусом запрета, принял бы его за факт.
// >
// > Пробы, которые прежняя редакция называла «пиннящими» это свойство
// > (`internal_upsert_blocked_test.go`), идут на подставных портах и потому
// > глобального ключа не видят — зелёными они останутся при любой модели.
// > Радиус запрета утверждается там, где его видно: на настоящей базе
// > (`internal/apps/kaname/api/audit`).
//
// Выдача токена по-прежнему перебирает набор членств и обслуживает первое, что
// может аутентифицироваться (`internal/service/token_enrichment_service.go`,
// `internal/handler/iamhooks`), отказывая, когда не может ни одно, — но теперь
// «не может ни одно» наступает разом, потому что состояние одно на человека.
//
// WHY NOT A FIELD ON Update. Three reasons, each on its own sufficient:
//
//  1. An empty `update_mask` means full-object replacement by platform
//     convention, and a proto3 enum is indistinguishable from unset. Had the
//     state been added as a maskable field — the obvious design — a client that
//     simply did not fill it in would have blocked the membership, silently and
//     for every user it touched. The field was therefore never added; an action
//     has no mask, so there is nothing to forget.
//  2. "This membership was suspended" is an EVENT, not the editing of an
//     attribute, and the audit trail has to be able to say so. A year from now
//     "who blocked this person, and when" must not be a question you answer by
//     reading diffs.
//  3. It is a change of security posture, and the permission catalog classifies
//     it as such. Routine lifecycle is not in that band, and the two cannot share
//     one RPC. (The step-up floor that classification carries is INTERACTIVE-only
//     — a machine principal is exempt from it by platform rule. It sets what a
//     PERSON must do, not who may do it: that stays `v_update`, decided by the
//     model.)
//
// IDEMPOTENT. The input is the STATE, not a transition: blocking an
// already-blocked membership succeeds and reports it blocked. The direction that
// makes a system safer must never be the one that fails on retry.
//
// ORDER IS NOT GUARANTEED BETWEEN TWO IN-FLIGHT REQUESTS, and the reason is the
// Operation, not the database. The write is handed to a background worker, so
// request order does not decide commit order: an Unblock requested BEFORE a Block
// can commit AFTER it. The operator-visible remedy is the same as everywhere else
// in this platform — read the state back (`Get` reports `inviteStatus`) rather
// than assume the last request sent is the last one applied.
//
// WHAT IT DOES NOT DO. Access tokens already minted are not invalidated here;
// they run out on their own schedule. What stops at once is every path that mints
// a NEW one — the token hook, the refresh hook, personal-token issuance and
// subject resolution at the edge. The identity-wide session cutoff
// (`user_token_revocations`) is deliberately NOT used: its scope is the whole
// identity, so applying it here would cut the sessions of someone who is legally
// active in another Account. Ending every session of a person is a different act
// with a different tool (`ForceLogout`).

import (
	"context"
	"fmt"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// setInviteStatusUseCase carries both directions. They differ in exactly two
// values — the state written and the event recorded — so they share one
// implementation rather than two that can drift apart.
//
// It is UNEXPORTED, and the two directions are distinct exported types below.
// That is not ceremony: a single exported type would make the two use-cases
// interchangeable to the compiler, and the composition root passes them
// adjacently into the handler. Swapped there, everything still builds, every test
// in this package still passes (they construct the use-cases directly), and
// `:block` quietly becomes `:unblock` — the one mistake that turns the control
// into its own opposite. Distinct types make that a compile error.
type setInviteStatusUseCase struct {
	repo    Repo
	opsRepo operations.Repo
	target  domain.InviteStatus
}

// BlockUserUseCase — the membership may no longer authenticate into its Account.
type BlockUserUseCase struct {
	setInviteStatusUseCase
}

// UnblockUserUseCase — the membership may authenticate again.
type UnblockUserUseCase struct {
	setInviteStatusUseCase
}

// NewBlockUserUseCase — the membership may no longer authenticate.
func NewBlockUserUseCase(r Repo, opsRepo operations.Repo) *BlockUserUseCase {
	return &BlockUserUseCase{setInviteStatusUseCase{
		repo: r, opsRepo: opsRepo, target: domain.InviteStatusBlocked,
	}}
}

// NewUnblockUserUseCase — the membership may authenticate again.
func NewUnblockUserUseCase(r Repo, opsRepo operations.Repo) *UnblockUserUseCase {
	return &UnblockUserUseCase{setInviteStatusUseCase{
		repo: r, opsRepo: opsRepo, target: domain.InviteStatusActive,
	}}
}

func (u *setInviteStatusUseCase) Execute(ctx context.Context, id domain.UserID) (*operations.Operation, error) {
	// Anti-anonymous floor only. WHO may suspend this membership is decided by
	// the MODEL: the api-gateway Checks `identity_suspender@iam_user:<user_id>`
	// (plus the step-up floor) before iam is dialed — каталог прав,
	// `UserService/Block` и `/Unblock`. Здесь стояло `v_update`, отношение,
	// СНЯТОЕ с этого типа вместе со своим читателем (#1102, #1128, #1258) — security.md «Авторизация живёт в
	// МОДЕЛИ, а не в самодельных проверках». A second, hand-rolled rule here
	// would not be grantable, scopable, revocable or auditable, and it would lock
	// machine principals out of a control they are entitled to operate.
	if err := authzguard.RequireAuthenticated(ctx); err != nil {
		return nil, err
	}
	if err := shared.ValidateResourceID(string(id), domain.PrefixUser, "user"); err != nil {
		return nil, err
	}

	// Existence + owning account + current state, read before the Operation is
	// minted. Three things depend on it: the Operation metadata carries
	// `account_id` so the account-scoped operations feed includes this action; an
	// id that names nothing gets a synchronous answer instead of an Operation the
	// caller has to go and interpret; and a PENDING invitation is refused
	// synchronously with the reason in words rather than asynchronously from
	// inside a worker.
	//
	// This read is NOT the gate. The invariant it anticipates lives in the write
	// statement itself (`SetInviteStatus`), which is what makes the concurrent
	// case correct — a row that changes underneath this read still cannot be
	// written wrongly.
	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	current, err := rd.Users().Get(ctx, id)
	_ = rd.Rollback(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	if current.InviteStatus == domain.InviteStatusPending {
		return nil, shared.MapRepoErr(pendingRefusal(id))
	}

	verb, eventType := "Block", auditEventUserBlocked
	if u.target == domain.InviteStatusActive {
		verb, eventType = "Unblock", auditEventUserUnblocked
	}

	op, err := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("%s user %s", verb, id),
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
		return u.doSetInviteStatus(ctx, id, actor, eventType)
	})
	return &op, nil
}

// metadata picks the per-direction Operation metadata message. Two messages
// rather than one with a flag: the operations feed is read by people, and
// «Block» and «Unblock» are different things to find in it.
func (u *setInviteStatusUseCase) metadata(id domain.UserID, accountID domain.AccountID) proto.Message {
	if u.target == domain.InviteStatusActive {
		return &iamv1.UnblockUserMetadata{UserId: string(id), AccountId: string(accountID)}
	}
	return &iamv1.BlockUserMetadata{UserId: string(id), AccountId: string(accountID)}
}

// doSetInviteStatus writes the state and records the event in the SAME writer-tx.
//
// Same transaction on purpose: a state change nobody can account for is worse
// than no state change, and an audit row for a write that rolled back is a lie in
// the opposite direction. Either both land or neither does.
//
// The audit row is emitted on every accepted call, including one that finds the
// membership already in the requested state. Someone with the authority to do
// this asked for it, and «who tried, and when» is precisely what the trail is for
// — a repeat that leaves no trace is a repeat nobody can see.
func (u *setInviteStatusUseCase) doSetInviteStatus(ctx context.Context, id domain.UserID, actor, eventType string) (*anypb.Any, error) {
	updated, err := shared.DoWithWriteTx(ctx, u.repo,
		func(ctx context.Context, w Writer) (domain.User, error) {
			row, serr := w.UsersW().SetInviteStatus(ctx, id, u.target)
			if serr != nil {
				return domain.User{}, serr
			}
			if aerr := w.EmitAuditEvent(ctx, service.AuditEvent{
				EventType:       eventType,
				TenantAccountID: string(row.AccountID),
				Payload: map[string]any{
					// WHO. The verified caller identity, never a value from the
					// request body.
					"actor": actor,
					// WHOM. The membership acted upon, and the tenancy it is in.
					"resource_type": "user",
					"resource_id":   string(row.ID),
					"account_id":    string(row.AccountID),
					// The state the membership was left in. Not the email or the
					// display name: those are mutable and personal — the trail
					// carries no PII and keys on the id, which stays true.
					"invite_status": string(row.InviteStatus),
				},
			}); aerr != nil {
				return domain.User{}, aerr
			}
			return row, nil
		})
	if err != nil {
		return nil, err
	}
	return marshalUser(updated)
}
