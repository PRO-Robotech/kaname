// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Compare-only порт не активирует protocol и не выдаёт signed writer identity.
// Полный read intent получает те же RR guards и population bridge, что policy
// consumer. Пустой intent разрешает только сравнение bundle: все source/native
// методы закрыты wrapper-ом, без выдуманного principal для identity probes.
func (r *Repository) PlannedSemanticAuthorityWriter(ctx context.Context, fence kaname.AuthorityFencePlan, bundle *granteffect.Bundle, read kaname.SemanticReadIntent) (kaname.SemanticAuthorityWriter, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := bundle.Validate(); err != nil {
		return nil, err
	}
	_, err := canonicalAuthorityAccounts(fence)
	if err != nil {
		return nil, err
	}
	if read.Actor == (domain.Subject{}) {
		if len(read.Native) != 0 || len(read.Roles) != 0 {
			return nil, kaname.ErrInvalidAuthorityFencePlan
		}
		opened, err := r.compareAuthorityIdentity(ctx, fence, bundle)
		if err != nil {
			return nil, err
		}
		return &plannedSemanticWriteTx{semanticAuthorityWriteTx: opened.(*semanticAuthorityWriteTx)}, nil
	}
	return r.PlannedSemanticPopulationWriter(ctx, fence, bundle, []kaname.SemanticReadIntent{read})
}

// Несколько заранее перечисленных typed principals используют один RR snapshot
// и общий бюджет. Это не разрешение на произвольный actor после entry.
func (r *Repository) PlannedSemanticPopulationWriter(ctx context.Context, fence kaname.AuthorityFencePlan, bundle *granteffect.Bundle, reads []kaname.SemanticReadIntent) (kaname.SemanticAuthorityWriter, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := bundle.Validate(); err != nil {
		return nil, err
	}
	accounts, err := canonicalAuthorityAccounts(fence)
	if err != nil {
		return nil, err
	}
	if len(reads) == 0 || len(reads) > kaname.MaxAuthorityOwnershipRefs {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	in := kaname.AuthorityWriteIntent{Kind: kaname.AuthorityBinding, Plan: fence, Bundle: bundle}
	for _, account := range accounts {
		in.Owners = append(in.Owners, kaname.AuthorityOwnerRef{Kind: "account", ID: string(account)})
	}
	requests := make([]policyWriteRequest, 0, len(reads))
	actors := map[domain.Subject]bool{}
	nativeDeclared := false
	totalRoots := 0
	for _, read := range reads {
		request, e := semanticReadRequest(in, read)
		if e != nil {
			return nil, e
		}
		if actors[read.Actor] {
			return nil, kaname.ErrInvalidAuthorityFencePlan
		}
		actors[read.Actor] = true
		request.compareGlobalAbsence = fence.Mode == kaname.AuthorityFenceGlobal
		totalRoots += len(read.Native)
		if totalRoots > nativeQuestionLimit {
			return nil, kaname.ErrSourceReadLimit
		}
		nativeDeclared = nativeDeclared || len(read.Native) != 0
		requests = append(requests, request)
	}
	factory := &GrantPolicyWriters{repo: r, bundle: bundle}
	conn, err := r.master.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	transferred := false
	defer func() {
		if !transferred {
			conn.Release()
		}
	}()
	for attempt := 0; attempt < authorityEntryAttempts; attempt++ {
		snapshot, e := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
		if e != nil {
			return nil, e
		}
		plan, e := factory.discoverSemanticCompareUnion(ctx, snapshot, requests)
		if cleanup := policyRollback(ctx, snapshot); cleanup != nil {
			return nil, errors.Join(e, cleanup)
		}
		if e != nil {
			if policyRetry(e) {
				continue
			}
			return nil, e
		}
		tx, e := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
		if e != nil {
			return nil, e
		}
		writer, e := factory.enterPlannedCompare(ctx, tx, plan)
		if e != nil {
			if cleanup := policyRollback(ctx, tx); cleanup != nil {
				return nil, errors.Join(e, cleanup)
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if policyRetry(e) {
				continue
			}
			return nil, e
		}
		writer.tx = &policyLeaseTx{Tx: tx, conn: conn}
		transferred = true
		return &plannedSemanticWriteTx{semanticAuthorityWriteTx: newSemanticAuthorityWriter(writer, bundle), additionalActors: actors, nativeDeclared: nativeDeclared}, nil
	}
	return nil, kaname.ErrAuthorityClassificationChanged
}

func (p *GrantPolicyWriters) enterPlannedCompare(ctx context.Context, tx pgx.Tx, plan *policyPlan) (*authorityWriteTx, error) {
	if plan == nil || plan.population == nil || !plan.population.valid() || plan.nativeBudget == nil || plan.producers != nil {
		return nil, kaname.ErrSourceUnconfirmed
	}
	var guards map[string]json.RawMessage
	if json.Unmarshal(plan.epochs, &guards) != nil || len(guards) == 0 || len(guards) > policyDiscoveryGuards {
		return nil, kaname.ErrSourceUnconfirmed
	}
	if err := chargeNativePolicyBudget(plan.nativeBudget, 3*len(guards), 1); err != nil {
		return nil, err
	}
	remaining := plan.nativeBudget.RemainingRows()
	if remaining == 0 {
		return nil, kaname.ErrSourceReadLimit
	}
	population, err := plan.population.json()
	if err != nil {
		return nil, err
	}
	fence := plan.intent(p.bundle).Plan
	ids := make([]string, len(fence.Accounts))
	for i, a := range fence.Accounts {
		ids[i] = string(a)
	}
	mode := "accounts"
	if fence.Mode == kaname.AuthorityFenceGlobal {
		mode = "global"
	}
	identity := p.bundle.Identity()
	var at time.Time
	var scanned int
	err = tx.QueryRow(ctx, `SELECT decision_at,population_rows FROM kaname.authority_compare_full_v2($1,$2::text[],$3,$4,$5,$6::jsonb,$7::jsonb,$8)`, mode, ids, identity.ModelID, identity.CatalogID, identity.ProjectorVersion, []byte(plan.epochs), population, remaining).Scan(&at, &scanned)
	if err != nil {
		var pgerr *pgconn.PgError
		if errors.As(err, &pgerr) && pgerr.Code == "P1036" {
			return nil, errors.Join(kaname.ErrSemanticIdentityUnavailable, err)
		}
		return nil, err
	}
	if scanned != plan.population.count || scanned > remaining {
		return nil, kaname.ErrSourceUnconfirmed
	}
	if err = chargeNativePolicyBudget(plan.nativeBudget, scanned, 0); err != nil {
		return nil, err
	}
	token := *plan.population
	writer := &authorityWriteTx{writeTx: &writeTx{readTx: readTx{tx: tx}}, fence: authorityFence{mode: fence.Mode, accounts: slices.Clone(fence.Accounts), decisionAt: at.UTC()}, population: &token, producerBudget: plan.nativeBudget, policyGuards: maps.Clone(plan.guards)}
	if plan.native != nil {
		writer.nativeRead = &protectedNativeRead{boundary: plan.native, global: plan.global, budget: plan.nativeBudget}
	}
	return writer, ctx.Err()
}

var _ kaname.PlannedSemanticAuthorityWriterFactory = (*Repository)(nil)

// Union строится в том же RR; каждый повторный census и финальный token scan
// списывают строки из уже общего budget. Exact absent keys не выкидываются.
func (p *GrantPolicyWriters) discoverSemanticCompareUnion(ctx context.Context, tx pgx.Tx, requests []policyWriteRequest) (*policyPlan, error) {
	var plan *policyPlan
	for _, request := range requests {
		var next *policyPlan
		var err error
		if plan == nil {
			next, err = p.discoverPolicyPlan(ctx, tx, request)
		} else {
			next, err = p.discoverPolicyPlanWithRows(ctx, tx, request, plan.rows, plan.nativeBudget)
		}
		if err != nil {
			return nil, err
		}
		if plan == nil {
			plan = next
			continue
		}
		plan.rows = next.rows
		plan.global = plan.global || next.global
		for account := range next.accounts {
			plan.add(account, "", false)
		}
		for key := range next.guards {
			plan.add("", key, false)
		}
		for key := range next.exclusive {
			plan.write(key)
		}
		if next.native != nil {
			if plan.native == nil {
				plan.native = next.native
			} else {
				maps.Copy(plan.native.questions, next.native.questions)
				maps.Copy(plan.native.accounts, next.native.accounts)
				maps.Copy(plan.native.guards, next.native.guards)
				maps.Copy(plan.native.globalReasons, next.native.globalReasons)
			}
		}
	}
	if plan == nil {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	if len(requests) == 1 {
		return plan, nil
	}
	plan.finishClassification()
	keys := make([]string, 0, len(plan.guards))
	for key := range plan.guards {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	if len(keys) > policyDiscoveryGuards {
		return nil, kaname.ErrSourceReadLimit
	}
	if err := chargeNativePolicyBudget(plan.nativeBudget, len(keys), 1); err != nil {
		return nil, err
	}
	query := `SELECT kaname.authority_policy_epoch_read($1::text[])`
	if plan.request.compareGlobalAbsence {
		query = `SELECT kaname.authority_compare_epoch_read_v2($1::text[])`
	}
	if err := tx.QueryRow(ctx, query, keys).Scan(&plan.epochs); err != nil {
		return nil, err
	}
	population, err := readPolicyPopulationToken(ctx, tx, plan.nativeBudget)
	if err != nil {
		return nil, err
	}
	plan.population = &population
	return plan, ctx.Err()
}
