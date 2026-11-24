// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/PRO-Robotech/kaname/internal/authzguard"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// Проверка не получает новые locks и не обновляет clock: сервер сверяет private
// final manifest с неизменным intent, backend/fullxid/invoker/nonce. Наличие
// одного Go wrapper либо совпадение connection не даёт права вызвать body.
func (p *resourceRegistrationPreparation) assertBody(ctx context.Context, tx *resourceDecisionTx) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if p == nil || p.parents == nil || p.parents.source == nil || !p.parents.source.sealed || tx == nil || tx.registrationBody != nil ||
		tx.lifetime != p.parents.source.lifetime || tx.lifetime == nil || !tx.lifetime.valid(tx.owner, tx.lifetime.bundle) {
		return kaname.ErrSourceUnconfirmed
	}
	intent, err := json.Marshal(p.input)
	if err != nil {
		return err
	}
	var admitted bool
	if err = tx.QueryRow(ctx, `SELECT kaname.authority_resource_assert_body_v2($1::jsonb)`, intent).Scan(&admitted); err != nil {
		return err
	}
	if !admitted {
		return kaname.ErrSourceUnconfirmed
	}
	tx.registrationBody = p
	return nil
}

// Тело регистрации выполняет только заранее названный сценарий. Область,
// hierarchy и исходное наличие tuple берутся из RR capture, подтверждённого
// после всех ожиданий; внутри тела нет live admission или повторного clock.
func (p *resourceRegistrationPreparation) applyRegister(ctx context.Context, tx *resourceDecisionTx) (kaname.ResourceDecisionResult, error) {
	var out kaname.ResourceDecisionResult
	if p == nil || p.input.Action != kaname.ResourceDecisionRegister {
		return out, kaname.ErrSourceUnconfirmed
	}
	if err := p.assertBody(ctx, tx); err != nil {
		return out, err
	}
	return p.applyPreparedDirect(ctx, tx)
}

func (p *resourceRegistrationPreparation) registrationAudit(ctx context.Context, event, outcome string) service.AuditEvent {
	actor, module, verified := authzguard.ModuleActor(ctx)
	if !verified {
		actor = authzguard.PrincipalUserID(ctx)
	}
	payload := map[string]any{"actor": actor, "module": module, "object": map[string]any{"type": p.row.ObjectType, "id": p.row.ObjectID},
		"relation": p.input.Tuple.Relation, "subject": p.input.Tuple.User, "outcome": outcome, "parent_chain": nil}
	if !p.row.SourceVersion.IsZero() {
		payload["source_version"] = p.row.SourceVersion.UTC().Format(time.RFC3339Nano)
	}
	if len(p.hierarchies) > 0 {
		links := p.hierarchies[0].Links
		payload["parent_chain"] = links
		if len(links) > 0 {
			typ, id, _ := strings.Cut(links[0], ":")
			payload["parent"] = map[string]any{"type": typ, "id": id}
		}
	}
	return service.AuditEvent{EventType: event, TenantAccountID: p.row.ParentAccountID, Payload: payload}
}

// Публикация не трогает mirror/parent projection и не запускает сведение.
// Водяной знак владельца и receipt меняются в той же TX, только если намерение
// действительно применилось; старый replay не создаёт новый источник.
func (p *resourceRegistrationPreparation) applyPublication(ctx context.Context, tx *resourceDecisionTx) (kaname.ResourceDecisionResult, error) {
	var out kaname.ResourceDecisionResult
	if p == nil || (p.input.Action != kaname.ResourceDecisionPublish && p.input.Action != kaname.ResourceDecisionUnpublish) {
		return out, kaname.ErrSourceUnconfirmed
	}
	if err := p.assertBody(ctx, tx); err != nil {
		return out, err
	}
	return p.applyPreparedDirect(ctx, tx)
}
