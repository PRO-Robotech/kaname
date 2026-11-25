// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/jackc/pgx/v5"
)

type MetadataOwnerPrefinalProbe struct {
	Status             string               `json:"status"`
	Invoker            string               `json:"invoker"`
	ConsumerFinalized  *bool                `json:"consumer_finalized"`
	FenceChecked       bool                 `json:"fence_checked"`
	Accounts           []domain.AccountID   `json:"accounts"`
	HistoricalBindings []string             `json:"historical_bindings"`
	Outputs            []domain.ResourceRef `json:"outputs"`
	SourceGuards       map[string]string    `json:"source_guards"`
	Rows               int                  `json:"rows"`
	Reads              int                  `json:"reads"`
	Work               int                  `json:"work"`
}

type MetadataOwnerHeldReplayProbe struct {
	Status             string          `json:"status"`
	Invoker            string          `json:"invoker"`
	ConsumerFinalized  *bool           `json:"consumer_finalized"`
	StashPrivate       bool            `json:"stash_private"`
	ScalarUnselected   bool            `json:"scalar_unselected"`
	CensusMatched      bool            `json:"census_matched"`
	AncestorCapture    json.RawMessage `json:"ancestor_capture"`
	AncestorProjection json.RawMessage `json:"ancestor_projection"`
	Sources            int             `json:"sources"`
	Frontiers          int             `json:"frontiers"`
	HeldRows           int             `json:"held_rows"`
	EmptyPredicates    int             `json:"empty_predicates"`
	Kinds              []int           `json:"kinds"`
	Rows               int             `json:"rows"`
	Reads              int             `json:"reads"`
	Work               int             `json:"work"`
}

type MetadataRetainedRRProbe struct {
	OwnerHeldReplay    *MetadataOwnerHeldReplayProbe
	OwnerPrefinal      *MetadataOwnerPrefinalProbe
	Intent             kaname.AuthorityWriteIntent
	SignedMode         kaname.AuthorityFenceMode
	SignedAccounts     []domain.AccountID
	RRClosed           bool
	HistoricalBindings []string
	RetainedBindings   []string
	RetainedAccounts   []domain.AccountID
	Outputs            []domain.ResourceRef
}

// Только test build: настоящий stage и настоящий signed entry на том же LOGIN.
// Не подменяет source reads, не добавляет grants и не вызывает protected write.
func ProbeMetadataRetainedRRAdmission(ctx context.Context, p *MetadataMutationWriters, root domain.Account, actor domain.Subject) (MetadataRetainedRRProbe, error) {
	return probeMetadataRetainedRR(ctx, p, root, actor, false, nil)
}

func ProbeMetadataRetainedOwnerHeldReplay(ctx context.Context, p *MetadataMutationWriters, root domain.Account, actor domain.Subject) (MetadataRetainedRRProbe, error) {
	return probeMetadataRetainedRR(ctx, p, root, actor, true, nil)
}

type metadataHeldProbe func(pgx.Tx, *metadataStage, metadataMutationPatch, int) error

func probeMetadataRetainedRR(ctx context.Context, p *MetadataMutationWriters, root domain.Account, actor domain.Subject, heldReplay bool, afterPolicy metadataHeldProbe) (trace MetadataRetainedRRProbe, err error) {
	if p == nil || p.policy == nil || p.policy.repo == nil {
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
	request := metadataMutation{kind: "account", table: "accounts", typ: "account", id: string(root.ID), name: string(root.Name), description: string(root.Description), labels: root.Labels, accessLabels: root.AccessLabels, mode: metadataMutationAccessLabels, mask: []string{"access_labels"}}
	patch, err := prepareMetadataMutationPatch(request)
	if err != nil {
		return trace, err
	}
	stage, err := p.stage(ctx, rr, request, actor, patch)
	if err != nil {
		return trace, err
	}
	if stage.grant == nil || stage.grant.retained == nil {
		return trace, kaname.ErrSourceUnconfirmed
	}
	defer stage.grant.source.lifetime.close()
	for key, rows := range stage.grant.source.entries {
		if key.kind != resourceSourceMetadataHistoricalCarriers {
			continue
		}
		for _, row := range rows {
			var v struct {
				Binding string `json:"binding_id"`
			}
			if json.Unmarshal(row.value, &v) != nil {
				return trace, kaname.ErrSourceUnconfirmed
			}
			trace.HistoricalBindings = append(trace.HistoricalBindings, v.Binding)
		}
	}
	slices.Sort(trace.HistoricalBindings)
	trace.RetainedBindings = resourceSortedSet(stage.grant.retained.bindings)
	for account := range stage.grant.retained.footprint.mutation {
		trace.RetainedAccounts = append(trace.RetainedAccounts, account)
	}
	slices.Sort(trace.RetainedAccounts)
	for object := range stage.grant.retained.footprint.objects {
		trace.Outputs = append(trace.Outputs, object)
	}
	trace.Intent = stage.plan.intent(p.policy.bundle)
	if err = validateAuthorityIntent(trace.Intent); err != nil {
		return trace, err
	}
	owners, err := json.Marshal(trace.Intent.Owners)
	if err != nil {
		return trace, err
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
	writer, err := repo.enterAuthority(ctx, rc, trace.Intent, owners, trace.Intent.Plan.Mode, trace.Intent.Plan.Accounts, false, purpose, stage.plan)
	if err != nil {
		return trace, err
	}
	trace.SignedMode = writer.AuthorityFence().Mode()
	trace.SignedAccounts = writer.AuthorityFence().Accounts()

	// SOURCE/OUTPUT graph does not come from Go. Owner reads census/catalog/closure
	// in signed RC; the chain also passes the same policy snapshot and write keys
	// that real protectPolicyPlan consumes next.
	var raw json.RawMessage
	ownerWorkRemaining := 400000
	if heldReplay {
		writes := []string{}
		if !stage.plan.global {
			for key := range stage.plan.exclusive {
				writes = append(writes, key)
			}
			slices.Sort(writes)
		}
		err = rc.QueryRow(ctx, `SELECT kaname.test_metadata_owner_prepare($1,$2,$3,$4::jsonb,$5::jsonb,$6::jsonb,$7::text[],$8,$9,$10)`,
			request.kind, request.id, stage.xmin, stage.old, patch.AccessLabels, stage.plan.epochs, writes,
			stage.plan.nativeBudget.RemainingRows(), stage.plan.nativeBudget.RemainingReads(), ownerWorkRemaining).Scan(&raw)
	} else {
		err = rc.QueryRow(ctx, `SELECT kaname.test_metadata_owner_prefinal($1,$2,$3,$4::jsonb,$5::jsonb)`, request.kind, request.id, stage.xmin, stage.old, patch.AccessLabels).Scan(&raw)
	}
	if err != nil {
		return trace, fmt.Errorf("подготовка источников меток владельцем: %w", err)
	}
	var observation MetadataOwnerPrefinalProbe
	if err = json.Unmarshal(raw, &observation); err != nil {
		return trace, err
	}
	if observation.Status != "observed" || !observation.FenceChecked || observation.ConsumerFinalized == nil || *observation.ConsumerFinalized {
		return trace, kaname.ErrSourceUnconfirmed
	}
	trace.OwnerPrefinal = &observation
	if heldReplay {
		if err = chargeNativePolicyBudget(stage.plan.nativeBudget, observation.Rows, observation.Reads); err != nil {
			return trace, err
		}
		ownerWorkRemaining -= observation.Work
		if ownerWorkRemaining < 0 {
			return trace, kaname.ErrSourceUnconfirmed
		}
		// Real production policy protection; SQL finalizes the consumer and holds
		// exact policy epoch rows. The fixture does not forge its phase or clock.
		if err = p.policy.protectPolicyPlan(ctx, writer, stage.plan); err != nil {
			return trace, fmt.Errorf("подтверждение плана политики: %w", err)
		}
		if afterPolicy != nil {
			if err = afterPolicy(rc, stage, patch, ownerWorkRemaining); err != nil {
				return trace, err
			}
		} else {
			err = rc.QueryRow(ctx, `SELECT kaname.test_metadata_owner_replay($1::jsonb,$2,$3,$4)`, patch.AccessLabels,
				stage.plan.nativeBudget.RemainingRows(), stage.plan.nativeBudget.RemainingReads(), ownerWorkRemaining).Scan(&raw)
			if err != nil {
				return trace, fmt.Errorf("повторное чтение источников меток владельцем: %w", err)
			}
			var held MetadataOwnerHeldReplayProbe
			if err = json.Unmarshal(raw, &held); err != nil {
				return trace, err
			}
			if held.Status != "replayed" || held.ConsumerFinalized == nil || !*held.ConsumerFinalized || !held.StashPrivate || !held.ScalarUnselected || !held.CensusMatched {
				return trace, kaname.ErrSourceUnconfirmed
			}
			if err = chargeNativePolicyBudget(stage.plan.nativeBudget, held.Rows, held.Reads); err != nil {
				return trace, err
			}
			if held.Work > ownerWorkRemaining {
				return trace, kaname.ErrSourceUnconfirmed
			}
			trace.OwnerHeldReplay = &held
		}
	}
	err = policyRollback(ctx, rc)
	active = nil
	return trace, err
}

// ProbeMetadataRetainedOwnerCertificate выполняет компиляцию на штатном
// подписанном пути. Исходные строки остаются в закрытой таблице владельца.
func ProbeMetadataRetainedOwnerCertificate(ctx context.Context, p *MetadataMutationWriters, root domain.Account, actor domain.Subject) (json.RawMessage, error) {
	var result json.RawMessage
	_, err := probeMetadataRetainedRR(ctx, p, root, actor, true, func(tx pgx.Tx, stage *metadataStage, patch metadataMutationPatch, work int) error {
		var halves catalog.Halves
		if err := json.Unmarshal(p.policy.bundle.CanonicalCatalog(), &halves); err != nil {
			return err
		}
		facts, err := catalog.NewFacts(halves)
		if err != nil {
			return err
		}
		body, err := json.Marshal(patch)
		if err != nil {
			return err
		}
		budget := stage.plan.nativeBudget
		var envelope json.RawMessage
		err = tx.QueryRow(ctx, `SELECT kaname.test_metadata_retention_inputs($1::jsonb,$2,$3,$4,$5)`,
			body, stage.rename, budget.RemainingRows(), budget.RemainingReads(), work).Scan(&envelope)
		if err != nil {
			return fmt.Errorf("закрытая подготовка сохраняемых фактов: %w", err)
		}
		var costs struct {
			Rows  int `json:"rows"`
			Reads int `json:"reads"`
			Work  int `json:"work"`
		}
		if err = json.Unmarshal(envelope, &costs); err != nil {
			return err
		}
		if costs.Rows < 1 || costs.Reads < 1 || costs.Work < 1 || costs.Work > work {
			return kaname.ErrSourceUnconfirmed
		}
		if err = chargeNativePolicyBudget(budget, costs.Rows, costs.Reads); err != nil {
			return err
		}
		desired, err := compileMetadataAccessLabelDesired(ctx, facts, envelope, budget)
		if err != nil {
			return fmt.Errorf("компиляция новых кортежей: %w", err)
		}
		if err = chargeNativePolicyBudget(budget, 1, 1); err != nil {
			return err
		}
		err = tx.QueryRow(ctx, `SELECT kaname.test_metadata_retention_compile($1::jsonb,$2)`,
			desired, work-costs.Work).Scan(&result)
		if err != nil {
			return fmt.Errorf("подтверждение сохраняемых фактов владельцем: %w", err)
		}
		return nil
	})
	return result, err
}
