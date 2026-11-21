// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/jackc/pgx/v5"
)

type PrivateRegistrationProbeTrace struct {
	Stage                   string
	BackendPID              uint32
	RRClosed                bool
	TypedRCEntered          bool
	Finalized               bool
	RefusalIdentityVerified bool
	Authorized              bool
	BodyExecuted            bool
	Committed               bool
	DirectCaptureKinds      []int
	RootParentEdgeRows      int
}

// Только test build и только private compiler component. Этот вход не вызывает
// public constructor, не меняет readiness и не предоставляет runtime EXECUTE
// на private SQL. Repo обязан принадлежать настоящему migration owner; DB ACL
// проверяет это при вызове direct_prepare. Gate/authority/manifest настоящие.
func ProbePrivateRegistration(ctx context.Context, repo *Repository, bundle *granteffect.Bundle, gate *authzguard.RelationWriteGate, in kaname.ResourceDecisionIntent) (result kaname.ResourceDecisionResult, trace PrivateRegistrationProbeTrace, err error) {
	trace.Stage = "validate"
	trace.RootParentEdgeRows = -1
	if repo == nil || repo.master == nil || gate == nil || (in.Action != kaname.ResourceDecisionRegister && in.Action != kaname.ResourceDecisionUnregister && in.Action != kaname.ResourceDecisionRecordRefusal) {
		return result, trace, kaname.ErrSourceUnconfirmed
	}
	if err = bundle.Validate(); err != nil {
		return result, trace, err
	}
	if err = validateResourceRegistrationModel(bundle); err != nil {
		return result, trace, err
	}
	var halves catalog.Halves
	if err = json.Unmarshal(bundle.CanonicalCatalog(), &halves); err != nil {
		return result, trace, err
	}
	facts, err := catalog.NewFacts(halves)
	if err != nil {
		return result, trace, err
	}
	r := &ResourceDecisionRunner{repo: repo, bundle: bundle, gate: gate, facts: facts}
	lease, err := repo.master.Acquire(ctx)
	if err != nil {
		return result, trace, err
	}
	defer lease.Release()
	trace.BackendPID = lease.Conn().PgConn().PID()
	lifetime, err := newResourceAttemptLifetime(lease.Conn(), bundle)
	if err != nil {
		return result, trace, err
	}
	var active pgx.Tx
	commitStarted := false
	defer func() {
		lifetime.close()
		if active != nil {
			cleanup := rollbackResourceAttempt(ctx, active)
			if err == nil {
				err = cleanup
			} else {
				err = resourceFailedAttempt(err, cleanup, commitStarted)
			}
		}
		if err != nil {
			result = kaname.ResourceDecisionResult{}
			err = fmt.Errorf("private registration %s: %w", trace.Stage, err)
		}
	}()
	trace.Stage = "RR capture"
	rr, err := lease.Conn().BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return result, trace, err
	}
	active = rr
	budget := &relverdict.AdministrativeReadBudget{}
	var registration *resourceRegistrationStage
	var refusal *resourceRefusalPreparation
	var parents *resourceParentCapture
	var source *resourceSourceCapture
	var footprint resourceFenceFootprint
	var proposal *resourceDecisionProposal
	if in.Action == kaname.ResourceDecisionRecordRefusal {
		source, err = newResourceSourceCapture(rr, budget, lifetime)
		if err != nil {
			return result, trace, err
		}
		parents, err = newResourceParentCapture(rr, source)
		if err != nil {
			return result, trace, err
		}
		refusal, err = prepareResourceRefusal(ctx, parents, in.Snapshot())
		if err != nil {
			return result, trace, err
		}
		trace.RefusalIdentityVerified = true
		footprint = resourceFenceFootprint{plan: kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal}}
		proposal, err = makeResourceRefusalProposal(in.Snapshot(), parents, footprint, refusal)
	} else {
		module, identityErr := resourceIdentityFromGate(ctx, gate)
		if identityErr != nil {
			return result, trace, identityErr
		}
		registration, err = r.stageRegistration(ctx, rr, lifetime, module, in.Snapshot(), budget)
		if err != nil {
			return result, trace, err
		}
		parents, source, footprint = registration.registration.parents, registration.source, registration.footprint
		// Только наблюдение реально захваченных ключей; probe не создаёт rows.
		captureKinds := []resourceSourceKind{resourceSourceMirror, resourceSourceParentEdges, resourceSourceRegistrationScopes, resourceSourceProjectBinding, resourceSourcePointerFacts, resourceSourceRegistrationPointers, resourceSourceObjectReceipts, resourceSourceObjectRetirement}
		if in.Action == kaname.ResourceDecisionUnregister {
			captureKinds = []resourceSourceKind{resourceSourceMirror, resourceSourceParentEdges, resourceSourcePointerFacts, resourceSourceRegistrationPointers, resourceSourceObjectReceipts, resourceSourceObjectPublication, resourceSourceObjectRetirement, resourceSourceFactLedgerHolders}
		}
		for _, kind := range captureKinds {
			typ := registration.registration.catalog.identity.ObjectType
			if kind == resourceSourceMirror {
				typ = registration.registration.catalog.identity.Dotted
			}
			if captured, ok := source.entries[resourceSourceKey{kind: kind, typ: typ, id: registration.registration.row.ObjectID}]; ok {
				trace.DirectCaptureKinds = append(trace.DirectCaptureKinds, int(kind))
				if kind == resourceSourceParentEdges {
					trace.RootParentEdgeRows = len(captured)
				}
			}
		}
		proposal, err = makeResourceRegistrationProposal(in.Snapshot(), parents, footprint, registration)
	}
	if err != nil {
		return result, trace, err
	}
	if err = source.seal(); err != nil {
		return result, trace, err
	}
	if err = rollbackResourceAttempt(ctx, rr); err != nil {
		return result, trace, err
	}
	active = nil
	trace.RRClosed = true
	trace.Stage = "typed RC entry"
	rc, err := lease.Conn().BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return result, trace, err
	}
	active = rc
	writer, err := r.enterResource(ctx, rc, lifetime, footprint)
	if err != nil {
		return result, trace, err
	}
	trace.TypedRCEntered = true
	trace.Stage = "private direct prepare"
	if proposal.prepared != nil || !proposal.lifetime.beforeDecision(writer) || len(proposal.payload) == 0 {
		return result, trace, kaname.ErrSourceUnconfirmed
	}
	if err = chargeNativePolicyBudget(budget, 0, 1); err != nil {
		return result, trace, err
	}
	var rows, reads int
	prepareSQL := `SELECT logical_rows,logical_reads FROM kaname._authority_resource_registration_direct_prepare_v2($1::jsonb,$2,$3)`
	if in.Action == kaname.ResourceDecisionUnregister {
		trace.Stage = "private Unregister prepare"
		prepareSQL = `SELECT logical_rows,logical_reads FROM kaname._authority_resource_unregistration_prepare_v2($1::jsonb,$2,$3)`
	}
	if in.Action == kaname.ResourceDecisionRecordRefusal {
		trace.Stage = "private refusal prepare"
		prepareSQL = `SELECT logical_rows,logical_reads FROM kaname._authority_resource_refusal_prepare_v2($1::jsonb,$2,$3)`
	}
	if err = rc.QueryRow(ctx, prepareSQL, proposal.payload, budget.RemainingRows(), budget.RemainingReads()).Scan(&rows, &reads); err != nil {
		return result, trace, err
	}
	if err = chargeNativePolicyBudget(budget, rows, reads); err != nil {
		return result, trace, err
	}
	proposal.prepared = writer
	trace.Stage = "current source and catalog"
	if err = source.recheck(ctx, writer); err != nil {
		return result, trace, err
	}
	if err = proposal.recheckCatalogs(ctx, writer, parents); err != nil {
		return result, trace, err
	}
	trace.Stage = "actual finalize"
	if err = proposal.finalize(ctx, writer, lifetime, budget); err != nil {
		return result, trace, registration.finalAuthorityError(err)
	}
	trace.Finalized = true
	trace.Stage = "actual final authority"
	if registration != nil {
		if err = registration.authorize(ctx, gate, writer); err != nil {
			return result, trace, err
		}
		trace.Authorized = true
	}
	trace.Stage = "actual Register body"
	decision := &resourceDecisionTx{Tx: rc, lifetime: lifetime, owner: writer}
	if in.Action == kaname.ResourceDecisionRecordRefusal {
		trace.Stage = "actual refusal audit body"
		result, err = refusal.apply(ctx, decision)
	} else if in.Action == kaname.ResourceDecisionUnregister {
		trace.Stage = "actual Unregister body"
		if registration.unregistration == nil {
			return result, trace, kaname.ErrSourceUnconfirmed
		}
		result, err = registration.unregistration.apply(ctx, decision)
	} else {
		result, err = registration.registration.applyRegister(ctx, decision)
	}
	if err != nil {
		return result, trace, err
	}
	trace.BodyExecuted = true
	if err = ctx.Err(); err != nil {
		return result, trace, err
	}
	trace.Stage = "actual Commit"
	commitStarted = true
	if err = decision.Commit(ctx); err != nil {
		return result, trace, err
	}
	active = nil
	trace.Committed = true
	trace.Stage = "committed"
	return result, trace, nil
}
