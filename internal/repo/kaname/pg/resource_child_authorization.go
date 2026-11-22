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
	target  domain.UserChildRegistrationTarget
	subject string
	native  resourceNativeCapture
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
	return &resourceChildAuthorization{target: target, subject: subject, native: resourceNativeCapture{
		lifetime: lifetime, boundary: boundary, budget: budget, guards: boundary.guardKeys(), epochs: boundary.epochs,
	}}, nil
}
