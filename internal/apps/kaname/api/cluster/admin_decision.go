// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package cluster

import (
	"context"
	"strings"

	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// AdminAction закрывает конкретное намерение, не произвольную callback authority.
type AdminAction string

const (
	AdminActionGrant  AdminAction = "grant"
	AdminActionRevoke AdminAction = "revoke"
)

type AdminDecisionIntent struct {
	Action AdminAction
	Actor  domain.Subject
	Target domain.Subject
}

// AdminDecisionRunner повторяет OLD decision, body и Commit целиком. Begin
// остаётся совместимым participant портом, но публичные UC выбирают этот порт.
type AdminDecisionRunner interface {
	RunAdminDecision(context.Context, AdminDecisionIntent, func(context.Context, service.Tx) (domain.ClusterAdminGrant, error)) (domain.ClusterAdminGrant, error)
}
type AdminSubjectState interface {
	UserInviteStatus(context.Context, string) (domain.InviteStatus, error)
	ServiceAccountEnabled(context.Context, string) (bool, error)
}

func adminMutationIntent(ctx context.Context, action AdminAction, typ domain.GrantSubjectType, id domain.SubjectID) (AdminDecisionIntent, error) {
	subject, ok := authzguard.PrincipalSubject(ctx)
	kind, actorID, split := strings.Cut(subject, ":")
	if !ok || !split {
		return AdminDecisionIntent{}, iamerr.ErrPermissionDenied
	}
	return AdminDecisionIntent{Action: action, Actor: domain.Subject{Type: domain.SubjectType(kind), ID: domain.SubjectID(actorID)}, Target: domain.Subject{Type: domain.SubjectType(typ), ID: id}}, nil
}
