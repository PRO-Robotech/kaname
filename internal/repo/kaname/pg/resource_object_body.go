// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/catalog"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// Body не вызывает live ReconcileObject, не получает callback и не открывает
// новую TX. Все команды получены общим чистым diff, а возможность выполнять
// каждую из них принадлежит private SQL manifest после полного preflight.
func (p *resourceObjectPreparation) apply(ctx context.Context, tx *resourceDecisionTx, facts *catalog.Facts) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if p == nil || p.source == nil || !p.source.sealed || p.root == nil || facts == nil || tx == nil || tx.lifetime != p.lifetime || p.lifetime == nil || !p.lifetime.valid(tx.owner, p.lifetime.bundle) {
		return kaname.ErrSourceUnconfirmed
	}
	intent, err := p.intent()
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
	values, err := readResourceObjectBodyValues(ctx, tx)
	if err != nil {
		return err
	}
	tx.accessLabelPending = *values.AccessLabelPending
	store := &resourceObjectBodyStore{reconcileStore: &reconcileStore{tx: tx, cat: facts, decisionAt: p.lifetime.at}, transactionAt: values.TransactionAt, decisionAt: values.DecisionAt}
	audits := make(map[int]*resourceObjectAuditValue, len(values.Audits))
	for i := range values.Audits {
		audit := &values.Audits[i]
		if audit.Command < 1 || audit.Command > len(values.Commands) || audits[audit.Command] != nil || values.Commands[audit.Command-1].Kind != "audit" {
			return kaname.ErrSourceUnconfirmed
		}
		audits[audit.Command] = audit
	}
	for i := range values.Commands {
		command, stepErr := readResourceObjectStep(ctx, tx, i+1)
		if stepErr != nil {
			return stepErr
		}
		store.audit = audits[i+1]
		if err = command.Apply(ctx, store); err != nil {
			return err
		}
	}
	return ctx.Err()
}
