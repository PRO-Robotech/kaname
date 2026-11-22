// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/authzcascade"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/personmarks"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/jackc/pgx/v5"
)

type resourceChildAuthorization struct {
	target    domain.UserChildRegistrationTarget
	principal operations.Principal
	subject   string
	native    resourceNativeCapture
}

// Предварительный допуск читает текущее основание права на снимке RR.
// Снимок состояния регистрации и квот получают после успешного допуска.
func (r *ResourceDecisionRunner) captureUserChildAuthorization(ctx context.Context, tx pgx.Tx, lifetime *resourceAttemptLifetime,
	input kaname.UserChildRegistrationInput, principal operations.Principal, budget *relverdict.AdministrativeReadBudget,
) (*resourceChildAuthorization, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if r == nil || r.bundle == nil || tx == nil || lifetime == nil || lifetime.ended || lifetime.prepared != nil ||
		tx.Conn() != lifetime.conn || lifetime.bundle != r.bundle || budget == nil {
		return nil, kaname.ErrSourceUnconfirmed
	}
	verified, ok := operations.PrincipalFromContextOK(ctx)
	subject, named := authzguard.SubjectFromPrincipal(verified)
	if !ok || !named || verified.Type != "user" || verified.IsAnonymous() || verified != principal {
		return nil, domain.ErrUserChildRegistrationRefused
	}
	policy, ok := r.bundle.ChildRegistration(input.ResourceType)
	if !ok {
		return nil, domain.ErrUserChildRegistrationRefused
	}
	target, err := policy.Path.Resolve(input.ResourceID)
	if err != nil {
		return nil, err
	}
	parentType, parentID, _ := strings.Cut(target.ParentObject, ":")
	questions := newNativePolicyQuestions()
	actor := domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(verified.ID)}
	if err := questions.add(actor, target.ParentAction, parentType, parentID); err != nil {
		return nil, domain.ErrUserChildRegistrationRefused
	}

	if err := chargeNativePolicyBudget(budget, 0, 1); err != nil {
		return nil, err
	}
	var at time.Time
	if err := tx.QueryRow(ctx, `SELECT transaction_timestamp() WHERE current_setting('transaction_isolation')='repeatable read'
 AND current_setting('transaction_read_only')='on'`).Scan(&at); err != nil {
		return nil, errors.Join(kaname.ErrSourceUnconfirmed, err)
	}
	var halves catalog.Halves
	if err := json.Unmarshal(r.bundle.CanonicalCatalog(), &halves); err != nil {
		return nil, errors.Join(kaname.ErrSourceUnconfirmed, err)
	}
	sources := &nativeAdministrativeSources{snapshot: tx, snapshotAt: at, bundle: r.bundle,
		catalogRelations: mutationCatalogRelations(halves)}
	form := relverdict.NewAdministrativeAsker(tx, r.bundle, func() time.Time { return at }, sources.verify)
	form.BindReadBudget(budget)
	allowed, err := authzcascade.WrapAdmitted(form, personmarks.NewTransaction(tx)).Check(ctx, subject, target.ParentAction, target.ParentObject)
	if errors.Is(err, relverdict.ErrAdministrativeSourceUnconfirmed) {
		return nil, kaname.ErrSourceUnconfirmed
	}
	if errors.Is(err, relverdict.ErrAdministrativeSourceLimit) {
		return nil, kaname.ErrSourceReadLimit
	}
	if err != nil {
		return nil, err
	}
	if !allowed {
		return nil, domain.ErrUserChildRegistrationRefused
	}

	boundary, err := discoverNativeReadBoundary(ctx, tx, r.bundle, questions, &nativeReadBudget{shared: budget})
	if err != nil {
		return nil, err
	}
	return &resourceChildAuthorization{target: target, principal: verified, subject: subject, native: resourceNativeCapture{
		lifetime: lifetime, boundary: boundary, budget: budget, guards: boundary.guardKeys(), epochs: boundary.epochs,
	}}, nil
}

// Повторный допуск использует часы этой транзакции и точный вопрос из RR.
// Смена цели или принципала не запускает новое чтение.
func (a *resourceChildAuthorization) checkFinal(ctx context.Context, writer *authorityWriteTx, subject, relation, object string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if a == nil || a.native.lifetime == nil || a.native.boundary == nil || a.native.budget == nil ||
		!a.native.lifetime.valid(writer, a.native.lifetime.bundle) {
		return false, kaname.ErrSourceUnconfirmed
	}
	principal, ok := operations.PrincipalFromContextOK(ctx)
	if !ok || principal != a.principal || subject != a.subject || relation != a.target.ParentAction || object != a.target.ParentObject {
		return false, domain.ErrUserChildRegistrationRefused
	}
	budget := a.native.budget
	writer.producerBudget = budget
	writer.nativeRead = &protectedNativeRead{boundary: a.native.boundary, global: writer.fence.mode == kaname.AuthorityFenceGlobal, budget: budget}
	semantic := newSemanticAuthorityWriter(writer, a.native.lifetime.bundle)
	allowed, err := semantic.SemanticRelationChecker().Check(ctx, subject, relation, object)
	if err != nil || !allowed {
		return false, err
	}
	actor := domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(principal.ID)}
	cost, err := semantic.AdmitSourceActor(ctx, actor)
	if budgetErr := chargeNativePolicyBudget(budget, cost.Rows, cost.Reads); budgetErr != nil {
		err = errors.Join(err, budgetErr)
	}
	if err != nil {
		return false, err
	}
	return true, nil
}
