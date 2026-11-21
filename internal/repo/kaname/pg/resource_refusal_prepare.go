// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"strings"

	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// Отказ — отдельное аудиторское намерение после rollback отвергнутой записи.
// Этот capture не требует права fga_writer, installation grant или admission
// новой регистрации: именно их отсутствие могло стать причиной отказа.
// Ни один отказный manifest не даёт права изменить authority tables.
type resourceRefusalPreparation struct {
	audit       *resourceRegistrationPreparation
	auditID     string
	actor       string
	serviceName string
}

func prepareResourceRefusal(ctx context.Context, parents *resourceParentCapture, in kaname.ResourceDecisionIntent) (*resourceRefusalPreparation, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if parents == nil || parents.source == nil || parents.source.sealed || in.Action != kaname.ResourceDecisionRecordRefusal {
		return nil, kaname.ErrSourceUnconfirmed
	}
	if in.RefusalOutcome != kaname.ResourceRefusalPermissionDenied && in.RefusalOutcome != kaname.ResourceRefusalFailedPrecondition {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	actor, serviceName, verified := authzguard.ModuleActor(ctx)
	if !verified {
		return nil, kaname.ErrSourceUnconfirmed
	}
	typ, id, _ := strings.Cut(in.Tuple.Object, ":")
	// Как в прежнем audit mapper: неизвестное имя сохраняется для описания отказа,
	// а поля Mirror области и parent claim не используются в каноническом аудите.
	p := &resourceRegistrationPreparation{input: in.Snapshot(), parents: parents, row: service.ResourceMirrorRow{ObjectType: typ, ObjectID: id, SourceVersion: in.Mirror.SourceVersion}}
	if nativeQuestionToken(typ) {
		captured, err := parents.catalog(ctx, typ)
		if err != nil {
			return nil, err
		}
		selected, known := captured.selected()
		if known {
			p.catalog = selected
			if !strings.Contains(typ, ".") {
				p.row.ObjectType = selected.identity.Dotted
			}
		}
		if known && selected.live && nativeQuestionToken(id) {
			anchors, err := parents.pointers(ctx, typ, id, selected.policy, false)
			if err != nil {
				return nil, err
			}
			for _, anchor := range anchors {
				h, found, err := parents.auditHierarchy(ctx, anchor)
				if err != nil {
					return nil, err
				}
				if found {
					p.hierarchies = []domain.ParentHierarchy{h}
					p.row.ParentAccountID = h.AccountID
					break
				}
			}
		}
	}
	if err := parents.source.budget.Charge(1, 0); err != nil {
		return nil, err
	}
	return &resourceRefusalPreparation{audit: p, auditID: newAuditEventID(), actor: actor, serviceName: serviceName}, nil
}

func (p *resourceRefusalPreparation) apply(ctx context.Context, tx *resourceDecisionTx) (kaname.ResourceDecisionResult, error) {
	if p == nil || p.audit == nil || p.audit.input.Action != kaname.ResourceDecisionRecordRefusal {
		return kaname.ResourceDecisionResult{}, kaname.ErrSourceUnconfirmed
	}
	if err := p.audit.assertBody(ctx, tx); err != nil {
		return kaname.ResourceDecisionResult{}, err
	}
	// Даже отказный audit исполняет только prepared exact row: никаких новых
	// IDs/часов/tenant lookup после final decision.
	return p.audit.applyPreparedDirect(ctx, tx)
}
