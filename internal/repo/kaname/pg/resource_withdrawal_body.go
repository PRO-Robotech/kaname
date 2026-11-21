// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/PRO-Robotech/kaname/internal/catalog"

	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/fga_outbox"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/PRO-Robotech/kaname/internal/resourceeffect"
)

// Результат pure compiler дополняется до final clock точными retained meta
// projections. Пустой slice означает доказанное отсутствие retained прав;
// отсутствующая запись означает незавершённый compiler и запрещает body.
// Индекс шага нужен: несколько ключей последовательно сужают одну роль.
type resourceWithdrawalBody struct {
	preparation *resourceRegistrationPreparation
	outputs     []*resourceOutputCapture
	plan        resourceeffect.WithdrawalPlan
	retained    map[resourceWithdrawalRoleStep][]domain.GrantCapabilityRule
}
type resourceWithdrawalRoleStep struct {
	step int
	role domain.RoleID
}

func (b *resourceWithdrawalBody) apply(ctx context.Context, tx *resourceDecisionTx) error {
	if b == nil || b.preparation == nil || b.preparation.input.Action != kaname.ResourceDecisionUnregister {
		return kaname.ErrSourceUnconfirmed
	}
	// Внешний Unregister уже вошёл в одноразовый SQL body. Вложенный шаг
	// не получает второе разрешение и не обновляет clock; он связан с тем же
	// immutable preparation и ещё действующим writer этой попытки.
	if tx == nil || tx.registrationBody != b.preparation || tx.lifetime == nil || !tx.lifetime.valid(tx.owner, tx.lifetime.bundle) {
		return kaname.ErrSourceUnconfirmed
	}
	for index, step := range b.plan.Steps {
		for _, change := range step.Bindings {
			if err := ctx.Err(); err != nil {
				return err
			}
			before, err := relverdict.EncodeTarget(change.BeforeTarget)
			if err != nil {
				return err
			}
			switch change.Action {
			case resourceeffect.BindingRevoke:
				tag, err := tx.Exec(ctx, `UPDATE kaname.access_bindings SET status='REVOKED',revoked_at=$4,revocation_reason=$5
WHERE id=$1 AND revoked_at IS NULL AND status=$2 AND target=$3::jsonb`, string(change.ID), string(change.BeforeStatus), before, tx.lifetime.at, change.RevocationReason)
				if err != nil {
					return err
				}
				if tag.RowsAffected() != 1 {
					return kaname.ErrAuthorityClassificationChanged
				}
				tuples := make([]clients.RelationTuple, len(change.TupleDeletes))
				for i, t := range change.TupleDeletes {
					tuples[i] = clients.RelationTuple{User: t.User, Relation: t.Relation, Object: t.Object}
				}
				if err = fga_outbox.EmitDecisionTx(ctx, tx, fga_outbox.EventTypeDelete, tuples, tx.lifetime.at); err != nil {
					return err
				}
			case resourceeffect.BindingNarrow:
				target, err := relverdict.EncodeTarget(change.Target)
				if err != nil {
					return err
				}
				if len(change.Target.Resources) == 0 {
					return kaname.ErrSourceUnconfirmed
				}
				tag, err := tx.Exec(ctx, `UPDATE kaname.access_bindings SET target=$4::jsonb,target_digest=$5,narrowed_at=$6
WHERE id=$1 AND revoked_at IS NULL AND status=$2 AND target=$3::jsonb`, string(change.ID), string(change.BeforeStatus), before, target, change.Target.Digest(), tx.lifetime.at)
				if err != nil {
					return err
				}
				if tag.RowsAffected() != 1 {
					return kaname.ErrAuthorityClassificationChanged
				}
			default:
				return kaname.ErrSourceUnconfirmed
			}
			for _, event := range change.SubjectChanges {
				if err := tx.owner.AccessBindingsW().EmitSubjectChangeEvent(ctx, event); err != nil {
					return err
				}
			}
			for _, event := range change.Audits {
				if err := tx.owner.AccessBindingsW().EmitAuditEvent(ctx, event); err != nil {
					return err
				}
			}
		}
		for _, change := range step.Roles {
			if err := ctx.Err(); err != nil {
				return err
			}
			// Никакого live RetainGrantCapabilities: его lifecycle/catalog waits уже
			// выполнены в preflight, а exact retained rows вычислены из capture.
			if change.Retain != nil {
				retained, ok := b.retained[resourceWithdrawalRoleStep{step: index, role: change.ID}]
				if !ok {
					return kaname.ErrSourceUnconfirmed
				}
				if err := tx.owner.RolesW().ReplaceGrantCapabilities(ctx, change.ID, retained); err != nil {
					return err
				}
			}
			before, err := rulesToJSON(change.BeforeRules)
			if err != nil {
				return err
			}
			rules, err := rulesToJSON(change.Rules)
			if err != nil {
				return err
			}
			perms, err := json.Marshal(stringSlice(change.Permissions))
			if err != nil {
				return err
			}
			tag, err := tx.Exec(ctx, `UPDATE kaname.roles SET rules=$3::jsonb,permissions=$4::jsonb,updated_at=$5 WHERE id=$1 AND rules=$2::jsonb`, string(change.ID), before, rules, perms, tx.lifetime.at)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 1 {
				return kaname.ErrAuthorityClassificationChanged
			}
			if err = tx.owner.RolesW().ReplaceRuleSelectors(ctx, change.ID, change.Selectors); err != nil {
				return err
			}
			if err = tx.owner.RolesW().ReplaceRoleVerbs(ctx, change.ID, change.Verbs); err != nil {
				return err
			}
			if err = tx.owner.RolesW().ReplaceRuleRefs(ctx, change.ID, change.Refs); err != nil {
				return err
			}
			if err = tx.owner.EmitAuditEvent(ctx, change.Audit); err != nil {
				return err
			}
		}
	}
	return nil
}

// Подготовка связывает pure compiler со снимком этой попытки. Ошибка снимка
// остаётся ошибкой источника; это не отказ полномочий и не пустой успешный план.
func prepareResourceWithdrawalBody(ctx context.Context, p *resourceRegistrationPreparation, keys []domain.ResourceRef, actor string, facts *catalog.Facts) (*resourceWithdrawalBody, error) {
	if p == nil || p.parents == nil || p.input.Action != kaname.ResourceDecisionUnregister {
		return nil, kaname.ErrSourceUnconfirmed
	}
	capture, err := captureResourceWithdrawal(ctx, p.parents, keys)
	if err != nil {
		return nil, err
	}
	if err = capture.addFootprint(ctx, p.parents, p.footprint); err != nil {
		return nil, err
	}
	snapshot, err := capture.snapshot()
	if err != nil {
		return nil, err
	}
	plan, err := resourceeffect.CompileWithdrawal(keys, actor, snapshot, facts)
	if err != nil {
		if errors.Is(err, resourceeffect.ErrInvalidSnapshot) {
			return nil, errors.Join(kaname.ErrSourceUnconfirmed, err)
		}
		return nil, err
	}
	outputs, err := capture.captureOutputs(ctx, p.parents, p.footprint)
	if err != nil {
		return nil, err
	}
	retained, err := capture.compileRetention(ctx, p.parents, plan)
	if err != nil {
		return nil, err
	}
	return &resourceWithdrawalBody{preparation: p, plan: plan, retained: retained, outputs: outputs}, nil
}
