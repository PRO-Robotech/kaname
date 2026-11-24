// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// Ни причина отказа, ни caller Mirror scope не являются audit authority.
// SQL выводит tenant/H из exact held graph и принимает только два отрицательных
// outcome; этот proposal переносит результат для независимого сравнения.
type resourceRefusalEffectProposal struct {
	AuditID     string                    `json:"audit_id"`
	Row         service.ResourceMirrorRow `json:"row"`
	Hierarchies []domain.ParentHierarchy  `json:"hierarchies"`
}

func makeResourceRefusalProposal(in kaname.ResourceDecisionIntent, parents *resourceParentCapture, footprint resourceFenceFootprint, refusal *resourceRefusalPreparation) (*resourceDecisionProposal, error) {
	if in.Action != kaname.ResourceDecisionRecordRefusal || refusal == nil || refusal.audit == nil ||
		refusal.audit.parents != parents || refusal.auditID == "" || refusal.serviceName == "" ||
		!strings.HasPrefix(refusal.actor, "service_account:") || footprint.plan.Mode != kaname.AuthorityFenceGlobal {
		return nil, kaname.ErrSourceUnconfirmed
	}
	intent, err := json.Marshal(in)
	if err != nil {
		return nil, err
	}
	envelope, catalogs, err := makeResourceProposalEnvelope(intent, parents, footprint)
	if err != nil {
		return nil, err
	}
	envelope.Service = refusal.serviceName
	envelope.Actor = strings.TrimPrefix(refusal.actor, "service_account:")
	envelope.RefusalEffects = &resourceRefusalEffectProposal{AuditID: refusal.auditID, Row: refusal.audit.row, Hierarchies: refusal.audit.hierarchies}
	// Empty capture remains a complete explicit collection, not an omitted
	// predicate. Unknown/malformed types are certified separately by SQL.
	if envelope.Sources == nil {
		envelope.Sources = []resourceProposalSource{}
	}
	if envelope.Catalogs == nil {
		envelope.Catalogs = []resourceProposalCatalog{}
	}
	return finishResourceDecisionProposal(envelope, parents.source.lifetime, catalogs)
}

// The generic registration executor has exactly one audit-only refusal command.
// Its owner-private guard still verifies the complete row and consumes its ID.
func (p *resourceRegistrationPreparation) executePreparedRefusalAudit(ctx context.Context, tx *resourceDecisionTx, row json.RawMessage, transactionAt time.Time) error {
	if p == nil || p.input.Action != kaname.ResourceDecisionRecordRefusal ||
		(p.input.RefusalOutcome != kaname.ResourceRefusalPermissionDenied && p.input.RefusalOutcome != kaname.ResourceRefusalFailedPrecondition) {
		return kaname.ErrSourceUnconfirmed
	}
	var value resourceObjectAuditValue
	if err := json.Unmarshal(row, &value.Row); err != nil {
		return err
	}
	event := "iam.resource_registration.registered"
	if p.input.RefusalUnregister {
		event = "iam.resource_registration.unregistered"
	}
	var payload struct {
		Outcome string `json:"outcome"`
	}
	if err := json.Unmarshal(value.Row.Payload, &payload); err != nil {
		return err
	}
	if value.Row.ID == "" || value.Row.EventType != event || payload.Outcome != string(p.input.RefusalOutcome) ||
		!value.Row.CreatedAt.Equal(transactionAt) || !value.Row.NextAttemptAt.Equal(transactionAt) {
		return kaname.ErrSourceUnconfirmed
	}
	_, err := tx.Exec(ctx, `INSERT INTO kaname.audit_outbox
(id,event_type,tenant_account_id,event_payload,status,attempts,created_at,next_attempt_at)
VALUES ($1,$2,$3,$4::jsonb,'pending',0,$5,$6)`, value.Row.ID, value.Row.EventType, value.Row.TenantAccountID, value.Row.Payload, value.Row.CreatedAt, value.Row.NextAttemptAt)
	return err
}
