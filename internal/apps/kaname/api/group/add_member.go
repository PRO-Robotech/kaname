// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package group

// add_member.go — AddMemberUseCase.
//
// Синхронно, до операции: форма → существование группы → вид участника → право
// выдавать на каждой области действующих выдач группы (Р3). В операции, одной
// транзакцией записи: принадлежность участника аккаунту группы (Д-3) → INSERT
// INTO group_members ON CONFLICT DO NOTHING (DB-триггер
// group_members_member_exists_trg проверяет существование участника).
//
// Участник не из аккаунта группы и несуществующий участник завершают операцию
// ОДНОЙ формой: FAILED_PRECONDITION с общим текстом «ссылки нет» (`pgmaperr.go`,
// неразобранная связь 23503) — без вида и идентификатора участника. Различие
// «нет такого» и «есть в другом аккаунте» было бы оракулом существования чужих
// субъектов.

import (
	"context"
	"fmt"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/PRO-Robotech/corelib/operations"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	abrepo "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	"github.com/PRO-Robotech/kaname/internal/service"
)

type AddMemberInput struct {
	GroupID    domain.GroupID
	MemberType domain.SubjectType
	MemberID   domain.SubjectID
}

type AddMemberUseCase struct {
	repo    Repo
	opsRepo operations.Repo
	// authority — право добавляющего выдавать на областях действующих выдач
	// группы (Р3, kaname#1037). Без провязки добавление отказывает (fail-closed):
	// контроль, которому нечем исполниться, не должен молча пропускать.
	authority MembersGrantAuthority
}

func NewAddMemberUseCase(r Repo, opsRepo operations.Repo) *AddMemberUseCase {
	return &AddMemberUseCase{repo: r, opsRepo: opsRepo}
}

// WithGrantAuthority — проверка Р3 перед добавлением участника. Провязывает
// корень службы (`access_binding.NewScopeGrantAuthority`).
func (u *AddMemberUseCase) WithGrantAuthority(a MembersGrantAuthority) *AddMemberUseCase {
	u.authority = a
	return u
}

// requireMembersGrantAuthority — проверка Р3. Непровязанный порт — отказ, а не
// пропуск; текст наружу фиксированный (§Hardening #1), причина — в журнал.
func (u *AddMemberUseCase) requireMembersGrantAuthority(ctx context.Context, id domain.GroupID) error {
	if u.authority == nil {
		slog.ErrorContext(ctx, "group add member: members grant authority is not wired — refusing the add", "group_id", string(id))
		return status.Error(codes.Internal, "internal error")
	}
	return u.authority.RequireForGroup(ctx, id)
}

func (u *AddMemberUseCase) Execute(ctx context.Context, in AddMemberInput) (*operations.Operation, error) {
	if err := shared.ValidateResourceID(string(in.GroupID), domain.PrefixGroup, "group"); err != nil {
		return nil, err
	}
	if in.MemberID == "" {
		return nil, shared.InvalidArg("member_id", "member_id required")
	}
	// Anti-anon floor only. Adding SELF to someone else's group (privilege
	// escalation via group bindings) is prevented by the MODEL: the api-gateway
	// Checks `v_update@iam_group:<group_id>` — membership changes ride the
	// group's update verb — before iam is dialed. The former in-service
	// owner-equality check re-decided that from the owning account's
	// owner_user_id, denying owner-granted delegates and every machine principal
	// (§«Авторизация живёт в МОДЕЛИ, а не в самодельных проверках»).
	if err := authzguard.RequireAuthenticated(ctx); err != nil {
		return nil, err
	}
	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	g, err := rd.Groups().Get(ctx, in.GroupID)
	_ = rd.Rollback(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	if err := in.MemberType.Validate(); err != nil {
		return nil, shared.MapValidationErr(err)
	}
	switch in.MemberType {
	case domain.SubjectTypeUser, domain.SubjectTypeServiceAccount:
		// OK
	default:
		return nil, shared.InvalidArg("member_type",
			"member_type must be 'user' or 'service_account'")
	}
	// Р3 (kaname#1037): участник в группу с действующими выдачами — только с
	// правом выдавать на каждой их области. Порядок несущий (Д-4): форма,
	// существование группы и вид участника уже проверены, об участнике отказ не
	// говорит ничего. Отказ синхронный, операции нет.
	if err := u.requireMembersGrantAuthority(ctx, in.GroupID); err != nil {
		return nil, err
	}

	op, err := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Add member %s/%s to group %s", in.MemberType, in.MemberID, in.GroupID),
		// account_id from the group loaded sync for authz (g.AccountID) so member-
		// change ops also surface in the account-scoped list.
		&iamv1.AddGroupMemberMetadata{GroupId: string(in.GroupID), MemberId: string(in.MemberID), AccountId: string(g.AccountID)},
	)
	if err != nil {
		return nil, err
	}
	if err := u.opsRepo.Create(ctx, op); err != nil {
		return nil, err
	}
	operations.Run(ctx, u.opsRepo, op.ID, func(ctx context.Context) (*anypb.Any, error) {
		return u.doAdd(ctx, in)
	})
	return &op, nil
}

func (u *AddMemberUseCase) doAdd(ctx context.Context, in AddMemberInput) (*anypb.Any, error) {
	m := domain.GroupMember{
		GroupID:    in.GroupID,
		MemberType: in.MemberType,
		MemberID:   in.MemberID,
	}
	if err := shared.DoWithWriteTxVoid(ctx, u.repo,
		func(ctx context.Context, w Writer) error {
			// Д-3 (kaname#1037): участник — только из аккаунта группы. Той же
			// транзакцией, что вставка, и под FOR SHARE строки, на которой
			// держится ответ: снятое конкурентно членство не проходит в группу.
			if err := w.GroupsW().RequireMemberOfGroupAccount(ctx, m); err != nil {
				return err
			}
			if err := w.GroupsW().AddMember(ctx, m); err != nil {
				return err
			}
			// Co-commit the FGA `group:<gid>#member` userset member-tuple INTENT in
			// the SAME writer-tx (запрет #10). Without it a GROUP-subject
			// AccessBinding's `@group:<gid>#member` userset resolves to EMPTY —
			// members get no real access and ExpandAccess finds no members (the bug
			// this guards). The journal row becomes a direct fact by trigger, in the
			// same commit, so the intent needs no delivery of its own; rollback of this
			// tx discards both the membership row and the tuple intent (no orphan).
			// Object type is `group` (the userset type
			// the binding points at), NOT iam_group (group's object-scope type).
			if err := w.EmitFGARelationWrite(ctx, []service.RelationTuple{memberFGATuple(m)}); err != nil {
				return err
			}
			// Drop the member's cached verdicts. The tuple intent above travels to
			// the relation store; it reaches NO verdict cache, and verdict caches are
			// dropped by exactly one path — a subject_change_outbox row drained to the
			// journal read by the edge itself. Same writer-tx as the membership DML (ban #10):
			// a rolled-back change must not announce an invalidation that had no cause.
			//
			// The subject is the MEMBER: the edge keys cached verdicts by whoever
			// presented the token, and the member is who gains or loses access through
			// the `group:<gid>#member` userset.
			return w.AccessBindingsW().EmitSubjectChangeEvent(ctx, abrepo.SubjectChangeEvent{
				SubjectID:   string(in.MemberID),
				SubjectType: string(in.MemberType),
				EventType:   "group_member_change",
				Op:          "group_member_change",
			})
		}); err != nil {
		return nil, err
	}
	return anypb.New(&emptypb.Empty{})
}
