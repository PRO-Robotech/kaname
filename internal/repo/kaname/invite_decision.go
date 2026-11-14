// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package kaname

import (
	"context"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
	ab "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	person "github.com/PRO-Robotech/kaname/internal/repo/kaname/user"
	"time"
)

// Intent не несёт разрешения, режима протокола или готового proof.
type InviteDecisionIntent struct {
	Actor           domain.Subject
	CandidateUserID domain.UserID
	AccountID       domain.AccountID
	Email           domain.Email
	ProjectID       domain.ProjectID
	RoleID          domain.RoleID
	BindingID       domain.AccessBindingID
	InvitedBy       domain.UserID
	GrantedBy       domain.UserID
}

// PreparedInvite создаёт только runner после protected reread своей попытки.
type PreparedInvite interface {
	RecipientID() domain.UserID
	Binding() domain.AccessBinding
	DecisionAt() time.Time
}

// Порт тела не раскрывает Commit/Rollback, pgx.Tx или semantic checker.
type InviteMutationWriter interface {
	UsersW() person.WriterIface
	Users() person.ReaderIface
	AccessBindingsW() ab.WriterIface
	EmitReconcileEvent(context.Context, string, string, string) error
	EmitFGARelationWrite(context.Context, []outboxtypes.RelationTuple) error
	EmitInviteMail(context.Context, outboxtypes.InviteMailIntent) (bool, error)
}
type InviteDecisionRunner interface {
	RunInviteDecision(context.Context, InviteDecisionIntent, func(context.Context, InviteMutationWriter, PreparedInvite) error) error
}
