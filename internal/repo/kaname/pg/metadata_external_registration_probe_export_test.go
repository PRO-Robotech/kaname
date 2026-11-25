// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/jackc/pgx/v5"
)

type ExternalRegistrationReceiptTrace struct {
	RRClosed bool
	Mode     kaname.AuthorityFenceMode
	Owners   []kaname.AuthorityOwnerRef
	Accounts []domain.AccountID
	Prepared json.RawMessage
	Held     json.RawMessage
}

// Проба использует настоящий FULL entry и owner prepare. Ни packet, ни
// attestation, ни receipt не собираются в Go; транзакция всегда откатывается.
func ProbeExternalRegistrationReceipt(ctx context.Context, p *MetadataMutationWriters, dotted, id, otherModel string, actor domain.Subject, fullReplay bool, finish ...string) (trace ExternalRegistrationReceiptTrace, err error) {
	if p == nil || p.policy == nil || p.policy.repo == nil || !nativeQuestionToken(id) {
		return trace, kaname.ErrSourceUnconfirmed
	}
	repo := p.policy.repo
	conn, err := repo.master.Acquire(ctx)
	if err != nil {
		return trace, err
	}
	defer conn.Release()
	var active pgx.Tx
	defer func() {
		if active != nil {
			err = errors.Join(err, policyRollback(ctx, active))
		}
	}()
	rr, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return trace, err
	}
	active = rr
	request := metadataMutation{
		kind: dotted, table: "resource_mirror", id: id, mode: metadataMutationAccessLabels,
		accessLabels: domain.Labels{"team": "after"}, mask: []string{"access_labels"},
	}
	patch, err := prepareMetadataMutationPatch(request)
	if err != nil {
		return trace, err
	}
	stage, err := p.stage(ctx, rr, request, actor, patch)
	if err != nil {
		return trace, fmt.Errorf("external repeatable read preparation: %w", err)
	}
	if stage.grant == nil {
		return trace, kaname.ErrSourceUnconfirmed
	}
	defer stage.grant.source.lifetime.close()
	if stage.request.typ == otherModel || !slices.Contains(stage.changed, "access_labels") {
		return trace, kaname.ErrSourceUnconfirmed
	}
	plan := stage.plan
	intent := plan.intent(p.policy.bundle)
	if err = validateAuthorityIntent(intent); err != nil {
		return trace, err
	}
	encodedOwners, err := json.Marshal(intent.Owners)
	if err != nil {
		return trace, err
	}
	// Этот узкий режим пользуется тем же настоящим pending FULL entry.
	// Обычную авторизацию и конечную команду он не имитирует.
	ordinaryRoot := len(finish) == 2 && finish[0] == "ordinary-root"
	if ordinaryRoot {
		if err = chargeNativePolicyBudget(plan.nativeBudget, 24, 24); err != nil {
			return trace, err
		}
		err = rr.QueryRow(ctx, `SELECT kaname.authority_metadata_mirror_ordinary_identity_v1($1,$2)`,
			dotted, id).Scan(&trace.Prepared)
		if err != nil {
			return trace, err
		}
	}
	if err = policyRollback(ctx, rr); err != nil {
		return trace, err
	}
	active = nil
	trace.RRClosed = true
	rc, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return trace, err
	}
	active = rc
	purpose := "decision"
	if repo.fullContract == nil {
		purpose = "participant"
	}
	writer, err := repo.enterAuthority(ctx, rc, intent, encodedOwners, intent.Plan.Mode, intent.Plan.Accounts, false, purpose, plan)
	if err != nil {
		return trace, err
	}
	trace.Mode = writer.AuthorityFence().Mode()
	trace.Owners = slices.Clone(intent.Owners)
	trace.Accounts = slices.Clone(writer.AuthorityFence().Accounts())
	if ordinaryRoot {
		err = rc.QueryRow(ctx, `SELECT kaname.test_external_ordinary_root($1,$2,$3,$4,$5,$6,$7)`,
			dotted, id, trace.Prepared, finish[1], plan.nativeBudget.RemainingRows(),
			plan.nativeBudget.RemainingReads(), metadataProtectedWorkLimit).Scan(&trace.Held)
		return trace, err
	}
	if len(finish) > 0 {
		if len(finish) != 1 {
			return trace, kaname.ErrInvalidAuthorityFencePlan
		}
		work := metadataProtectedWorkLimit
		if err = stage.prepareProtected(ctx, rc, patch.AccessLabels, &work); err != nil {
			return trace, err
		}
		if err = p.policy.protectPolicyPlanAt(ctx, writer, plan, policyPlanBeforeMetadataFreeze); err != nil {
			return trace, err
		}
		encoded, err := json.Marshal(patch)
		if err != nil {
			return trace, err
		}
		if err = stage.freezeProtected(ctx, rc, p.policy.bundle, actor, encoded, &work); err != nil {
			return trace, err
		}
		semantic, err := p.finalizeMetadataAuthorization(ctx, writer, stage, policyPlanBeforeMetadataWrite)
		if err != nil {
			return trace, err
		}
		if err = stage.approveProtectedApply(ctx, semantic, &work); err != nil {
			return trace, err
		}
		if finish[0] != "omit" {
			err = rc.QueryRow(ctx, `SELECT kaname.test_external_metadata_write($1,$2)`, dotted, id).Scan(&trace.Held)
			if err != nil {
				return trace, err
			}
		}
		switch finish[0] {
		case "rollback":
			err = policyRollback(ctx, rc)
		case "commit", "omit":
			err = rc.Commit(ctx)
		default:
			return trace, kaname.ErrInvalidAuthorityFencePlan
		}
		active = nil
		return trace, err
	}
	writes := []string{}
	if !plan.global {
		for key := range plan.exclusive {
			writes = append(writes, key)
		}
		slices.Sort(writes)
	}
	const workLimit = 400000
	err = rc.QueryRow(ctx, `SELECT kaname.test_external_registration_prepare(
 $1,$2,$3,$4::jsonb,$5::jsonb,$6::text[],$7,$8,$9)`, dotted, id, stage.xmin, stage.old,
		plan.epochs, writes, plan.nativeBudget.RemainingRows(), plan.nativeBudget.RemainingReads(), workLimit).Scan(&trace.Prepared)
	if err != nil {
		return trace, fmt.Errorf("external owner prepare: %w", err)
	}
	var cost struct {
		Rows  int `json:"rows"`
		Reads int `json:"reads"`
		Work  int `json:"work"`
	}
	if err = json.Unmarshal(trace.Prepared, &cost); err != nil {
		return trace, err
	}
	if cost.Rows <= 0 || cost.Reads <= 0 || cost.Work <= 0 || cost.Work >= workLimit {
		return trace, kaname.ErrSourceUnconfirmed
	}
	if err = chargeNativePolicyBudget(plan.nativeBudget, cost.Rows, cost.Reads); err != nil {
		return trace, err
	}
	if err = p.policy.protectPolicyPlan(ctx, writer, plan); err != nil {
		return trace, fmt.Errorf("external first policy protection: %w", err)
	}
	remainingWork := workLimit - cost.Work
	if fullReplay {
		err = rc.QueryRow(ctx, `SELECT kaname.test_external_registration_full_hold($1,$2,$3,$4,$5,$6)`,
			plan.nativeBudget.RemainingRows(), plan.nativeBudget.RemainingReads(), remainingWork,
			string(stage.auditID), string(actor.Type), string(actor.ID)).Scan(&trace.Held)
	} else {
		err = rc.QueryRow(ctx, `SELECT kaname.test_external_registration_receipt($1,$2,$3,$4)`,
			otherModel, plan.nativeBudget.RemainingRows(), plan.nativeBudget.RemainingReads(), remainingWork).Scan(&trace.Held)
	}
	if err != nil {
		return trace, fmt.Errorf("external binding receipt: %w", err)
	}
	if err = json.Unmarshal(trace.Held, &cost); err != nil {
		return trace, err
	}
	if cost.Rows <= 0 || cost.Reads <= 0 || cost.Work <= 0 || cost.Work > remainingWork {
		return trace, kaname.ErrSourceUnconfirmed
	}
	if err = chargeNativePolicyBudget(plan.nativeBudget, cost.Rows, cost.Reads); err != nil {
		return trace, err
	}
	err = policyRollback(ctx, rc)
	active = nil
	return trace, err
}
