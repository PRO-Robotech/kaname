// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Семь команд имеют общий private Resource manifest, но отдельные typed входы.
// Конструктор не активирует identity и не открывает raw fallback.
var errCRUDAttemptCleanup = errors.New("CRUD attempt cleanup failed")

type CRUDWriters struct {
	runner *ResourceDecisionRunner
	facts  *catalog.Facts
}

func NewCRUDWriters(ctx context.Context, repo *Repository, bundle *granteffect.Bundle) (*CRUDWriters, error) {
	if repo == nil || !repo.fullContractMatches(bundle) {
		return nil, kaname.ErrSemanticIdentityUnavailable
	}
	if err := repo.ValidateFullAuthorityBundle(ctx, bundle); err != nil {
		return nil, err
	}
	var ready bool
	if err := repo.master.QueryRow(ctx, `SELECT kaname.authority_crud_storage_v3()`).Scan(&ready); err != nil {
		return nil, err
	}
	if !ready {
		return nil, kaname.ErrSemanticIdentityUnavailable
	}
	var halves catalog.Halves
	if err := json.Unmarshal(bundle.CanonicalCatalog(), &halves); err != nil {
		return nil, err
	}
	facts, err := catalog.NewFacts(halves)
	if err != nil {
		return nil, err
	}
	return &CRUDWriters{runner: &ResourceDecisionRunner{repo: repo, bundle: bundle, facts: facts}, facts: facts}, nil
}
func (p *CRUDWriters) AccountCreateWriter(ctx context.Context, r kaname.AccountCreateAuthority, a domain.Subject) (kaname.SemanticAuthorityWriter, error) {
	return p.openCRUD(ctx, "account.create", r, a)
}
func (p *CRUDWriters) AccountDeleteWriter(ctx context.Context, id domain.AccountID, a domain.Subject) (kaname.SemanticAuthorityWriter, error) {
	return p.openCRUD(ctx, "account.delete", id, a)
}
func (p *CRUDWriters) ProjectCreateWriter(ctx context.Context, r domain.Project, a domain.Subject) (kaname.SemanticAuthorityWriter, error) {
	return p.openCRUD(ctx, "project.create", r, a)
}
func (p *CRUDWriters) ProjectDeleteWriter(ctx context.Context, id domain.ProjectID, a domain.Subject) (kaname.SemanticAuthorityWriter, error) {
	return p.openCRUD(ctx, "project.delete", id, a)
}
func (p *CRUDWriters) ServiceAccountCreateWriter(ctx context.Context, r domain.ServiceAccount, a domain.Subject) (kaname.SemanticAuthorityWriter, error) {
	return p.openCRUD(ctx, "service_account.create", r, a)
}
func (p *CRUDWriters) ServiceAccountDeleteWriter(ctx context.Context, id domain.ServiceAccountID, a domain.Subject) (kaname.SemanticAuthorityWriter, error) {
	return p.openCRUD(ctx, "service_account.delete", id, a)
}
func (p *CRUDWriters) RoleDeleteWriter(ctx context.Context, id domain.RoleID, a domain.Subject) (kaname.SemanticAuthorityWriter, error) {
	return p.openCRUD(ctx, "role.delete", id, a)
}

var _ kaname.CRUDWriterFactory = (*CRUDWriters)(nil)

type crudIntent struct {
	Kind    string          `json:"kind"`
	Command string          `json:"command"`
	Actor   string          `json:"actor"`
	Input   json.RawMessage `json:"input"`
}
type crudCapture struct {
	Plan         kaname.AuthorityFencePlan  `json:"plan"`
	Owners       []kaname.AuthorityOwnerRef `json:"owners"`
	Sources      json.RawMessage            `json:"sources"`
	NativeType   string                     `json:"native_type"`
	NativeID     string                     `json:"native_id"`
	LogicalRows  int                        `json:"logical_rows"`
	LogicalReads int                        `json:"logical_reads"`
}
type crudStage struct {
	capture       crudCapture
	intent        crudIntent
	encodedIntent json.RawMessage
	native        *nativeReadBoundary
	epochs        json.RawMessage
	questions     *nativePolicyQuestions
}

func (p *CRUDWriters) stageCRUD(ctx context.Context, tx pgx.Tx, in crudIntent, budget *relverdict.AdministrativeReadBudget) (*crudStage, error) {
	encoded, err := json.Marshal(in)
	if err != nil {
		return nil, err
	}
	stage := &crudStage{intent: in, encodedIntent: encoded, epochs: json.RawMessage("{}"), questions: newNativePolicyQuestions()}
	var captured []byte
	if err = tx.QueryRow(ctx, `SELECT kaname.authority_resource_crud_capture_v3($1::jsonb,$2,$3)`, encoded, budget.RemainingRows(), budget.RemainingReads()).Scan(&captured); err != nil {
		return nil, err
	}
	if err = json.Unmarshal(captured, &stage.capture); err != nil {
		return nil, err
	}
	if err = chargeNativePolicyBudget(budget, stage.capture.LogicalRows, stage.capture.LogicalReads); err != nil {
		return nil, err
	}
	authority := kaname.AuthorityWriteIntent{Kind: kaname.AuthorityResource, Plan: stage.capture.Plan, Owners: stage.capture.Owners, Bundle: p.runner.bundle}
	if err = validateAuthorityIntent(authority); err != nil {
		return nil, err
	}
	var actor domain.Subject
	// Actor уже прошёл Validate до SQL; разбираем точную типизированную форму.
	switch in.Command {
	case "account.create":
		var request kaname.AccountCreateAuthority
		if err = json.Unmarshal(in.Input, &request); err != nil {
			return nil, err
		}
		actor = domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(request.Account.OwnerUserID)}
		if subjectPolicyKey(actor) != in.Actor {
			return nil, kaname.ErrSourceUnconfirmed
		}
		if request.IDSource == "supplied" {
			err = stage.questions.add(actor, "system_admin", "cluster", domain.ClusterSingletonID)
		}
	case "project.create":
		actor, err = crudActor(in.Actor)
		if err == nil {
			// Канонический RPC требует editor@account; project не имеет container create.
			err = stage.questions.add(actor, "editor", stage.capture.NativeType, stage.capture.NativeID)
		}
	case "service_account.create":
		actor, err = crudActor(in.Actor)
		if err != nil {
			return nil, err
		}
		grant, ok := p.facts.ContainerVerb("iam.serviceAccount", "create")
		if !ok || grant.ParentType != "account" || grant.Relation == "" {
			return nil, kaname.ErrSourceUnconfirmed
		}
		err = stage.questions.add(actor, grant.Relation, stage.capture.NativeType, stage.capture.NativeID)
	case "account.delete", "project.delete", "service_account.delete", "role.delete":
		actor, err = crudActor(in.Actor)
		if err != nil {
			return nil, err
		}
		err = stage.questions.add(actor, "v_delete", stage.capture.NativeType, stage.capture.NativeID)
	default:
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	if err != nil {
		return nil, err
	}
	keys := []string{"*", in.Actor}
	if len(stage.questions.roots) > 0 {
		stage.native, err = captureNativeReadBoundary(ctx, p.runner.bundle, stage.questions, nativePolicyReadSnapshot{tx}, &nativeReadBudget{shared: budget})
		if err != nil {
			return nil, err
		}
		if stage.native == nil || (stage.native.global() && stage.capture.Plan.Mode != kaname.AuthorityFenceGlobal) {
			return nil, kaname.ErrSourceUnconfirmed
		}
		keys = append(keys, stage.native.guardKeys()...)
	}
	// Actor admission/marks и membership population имеют собственный epoch,
	// даже self-service Account.Create без native permission question.
	slices.Sort(keys)
	keys = slices.Compact(keys)
	if err = chargeNativePolicyBudget(budget, len(keys), 1); err != nil {
		return nil, err
	}
	if err = tx.QueryRow(ctx, `SELECT kaname.authority_policy_epoch_read($1::text[])`, keys).Scan(&stage.epochs); err != nil {
		return nil, err
	}
	return stage, ctx.Err()
}

func (p *CRUDWriters) openCRUD(ctx context.Context, command string, input any, actor domain.Subject) (kaname.SemanticAuthorityWriter, error) {
	if p == nil || p.runner == nil || p.runner.repo == nil || p.facts == nil || actor.Validate() != nil || actor.ID == "*" || (actor.Type != domain.SubjectTypeUser && actor.Type != domain.SubjectTypeServiceAccount) {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	encoded, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	intent := crudIntent{Kind: "crud", Command: command, Actor: subjectPolicyKey(actor), Input: encoded}
	budget := &relverdict.AdministrativeReadBudget{}
	var last error
	for attempt := 0; attempt < authorityEntryAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		writer, attemptErr := p.openCRUDAttempt(ctx, intent, actor, budget)
		if attemptErr == nil {
			return writer, nil
		}
		last = attemptErr
		// Только подтверждённое изменение preclock source требует нового RR.
		// Native deny, body/commit и SQL deadlock здесь не маскируются retry.
		var pgerr *pgconn.PgError
		if errors.Is(attemptErr, errCRUDAttemptCleanup) || !errors.As(attemptErr, &pgerr) || pgerr.Code != "P1034" {
			return nil, attemptErr
		}
	}
	return nil, errors.Join(kaname.ErrSourceUnconfirmed, last)
}

func (p *CRUDWriters) openCRUDAttempt(ctx context.Context, intent crudIntent, actor domain.Subject, budget *relverdict.AdministrativeReadBudget) (kaname.SemanticAuthorityWriter, error) {
	lease, err := p.runner.repo.master.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	transferred := false
	defer func() {
		if !transferred {
			lease.Release()
		}
	}()
	snapshot, err := lease.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	stage, err := p.stageCRUD(ctx, snapshot, intent, budget)
	if cleanup := policyRollback(ctx, snapshot); cleanup != nil {
		return nil, errors.Join(errCRUDAttemptCleanup, err, cleanup)
	}
	if err != nil {
		return nil, err
	}
	lifetime, err := newResourceAttemptLifetime(lease.Conn(), p.runner.bundle)
	if err != nil {
		return nil, err
	}
	tx, err := lease.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, err
	}
	footprint := resourceFenceFootprint{sourceWrite: true, plan: stage.capture.Plan, owners: stage.capture.Owners}
	writer, err := p.runner.enterResource(ctx, tx, lifetime, footprint)
	var result kaname.SemanticAuthorityWriter
	if err == nil {
		payload, encodeErr := json.Marshal(struct {
			ABI          int             `json:"abi"`
			Intent       json.RawMessage `json:"intent"`
			Capture      crudCapture     `json:"crud_capture"`
			NativeEpochs json.RawMessage `json:"native_epochs"`
		}{2, stage.encodedIntent, stage.capture, stage.epochs})
		err = encodeErr
		proposal := &resourceDecisionProposal{intent: stage.encodedIntent, payload: payload, lifetime: lifetime}
		if err == nil {
			err = proposal.prewait(ctx, writer, budget)
		}
		if err == nil {
			err = proposal.finalize(ctx, writer, lifetime, budget)
		}
		if err == nil {
			writer.producerBudget = budget
			if stage.native != nil {
				writer.nativeRead = &protectedNativeRead{boundary: stage.native, global: stage.capture.Plan.Mode == kaname.AuthorityFenceGlobal, budget: budget}
			}
			semantic := newSemanticAuthorityWriter(writer, p.runner.bundle)
			// Самообслуживание Account.Create не выдумывает native permission, но
			// всё равно повторяет канонический допуск typed actor после final wait.
			var actorCost kaname.SourceReadCost
			actorCost, err = semantic.AdmitSourceActor(ctx, actor)
			if budgetErr := chargeNativePolicyBudget(budget, actorCost.Rows, actorCost.Reads); budgetErr != nil {
				err = errors.Join(err, budgetErr)
			}
			// Право спрашивается по OLD после последнего physical wait и единственного final clock.
			for q := range stage.questions.roots {
				if err != nil {
					break
				}
				var allowed bool
				allowed, err = semantic.SemanticRelationChecker().Check(ctx, q.subject, q.relation, q.objectType+":"+q.objectID)
				if err == nil && !allowed {
					err = iamerr.Wrapf(iamerr.ErrPermissionDenied, "CRUD authority denied")
				}
				if err != nil {
					break
				}
			}
			if err == nil {
				result, err = newPreparedCRUDWriter(ctx, semantic, lifetime, stage.encodedIntent)
			}
		}
	}
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		lifetime.close()
		if cleanup := policyRollback(ctx, tx); cleanup != nil {
			return nil, errors.Join(errCRUDAttemptCleanup, err, cleanup)
		}
		return nil, err
	}
	writer.tx = &policyLeaseTx{Tx: tx, conn: lease}
	transferred = true
	return result, nil
}

func crudActor(key string) (domain.Subject, error) {
	typ, id, ok := strings.Cut(key, ":")
	actor := domain.Subject{Type: domain.SubjectType(typ), ID: domain.SubjectID(id)}
	if !ok || actor.Validate() != nil || (actor.Type != domain.SubjectTypeUser && actor.Type != domain.SubjectTypeServiceAccount) || subjectPolicyKey(actor) != key {
		return domain.Subject{}, kaname.ErrSourceUnconfirmed
	}
	return actor, nil
}
