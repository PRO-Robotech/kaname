// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/PRO-Robotech/kaname/internal/testsupport/registrationscene"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

type UserChildStageProbe struct {
	Target           domain.UserChildRegistrationTarget
	ParentRegistered bool
	ChildRegistered  bool
	Hierarchies      []domain.ParentHierarchy
	OldScopes        []domain.ContainerScope
	NewScopes        []domain.ContainerScope
	Plan             kaname.AuthorityFencePlan
	Envelope         json.RawMessage
	SameLifetime     bool
	SourceSealed     bool
	Queries          []string
}

// Только наблюдение результата настоящего RR stage. Проба не добавляет
// источники и не выполняет private compiler, финализацию или запись.
func ProbeUserChildStage(ctx context.Context, tx pgx.Tx, bundle *granteffect.Bundle,
	input kaname.UserChildRegistrationInput, principal operations.Principal,
) (out UserChildStageProbe, err error) {
	lifetime, err := newResourceAttemptLifetime(tx.Conn(), bundle)
	if err != nil {
		return out, err
	}
	defer lifetime.close()
	observed := childAuthorizationObservedTx{Tx: tx, queries: &out.Queries}
	budget := &relverdict.AdministrativeReadBudget{}
	runner := &ResourceDecisionRunner{bundle: bundle}
	stage, err := runner.stageUserChildRegistration(ctx, observed, lifetime, input, principal, budget)
	if err != nil {
		return out, err
	}
	out.Target = stage.authorization.target
	out.ParentRegistered, out.ChildRegistered = stage.parentRegistered, stage.childRegistered
	out.Hierarchies, out.OldScopes, out.NewScopes = stage.hierarchies, stage.oldScopes, stage.newScopes
	out.SameLifetime = stage.source.lifetime == lifetime && stage.authorization.native.lifetime == lifetime &&
		stage.source.stageTX == observed && stage.source.budget == budget && stage.authorization.native.budget == budget
	out.SourceSealed = stage.source.sealed
	if stage.footprint == nil {
		return out, nil
	}
	out.Plan = stage.footprint.plan
	proposal, err := stage.proposal()
	if err != nil {
		return out, err
	}
	out.Envelope = proposal.payload
	return out, nil
}

// 1045-04: SQL полной подготовки должен совпадать с SQL предварительного
// отказа, как для существующего, так и для отсутствующего родителя. Эта проба
// проверяет порядок в RR. Вход читателя по токену проверяет отдельный тест стенда.
func TestUserChildStageRRDeniesExistingAndAbsentParentBeforeRegistrationCapture(t *testing.T) {
	pool := cvPool(t)
	ctx := t.Context()
	parent := registrationscene.Seed(t, ctx, pool)
	caller := registrationscene.Seed(t, ctx, pool)
	var user string
	require.NoError(t, pool.QueryRow(ctx, `SELECT owner_user_id FROM kaname.accounts WHERE id=$1`, caller.Account).Scan(&user))
	principal := operations.Principal{Type: "user", ID: user}
	ctx = operations.WithPrincipal(ctx, principal)
	require.NotEqual(t, parent.Account, caller.Account)
	// Отношение owner даёт человеку прямое право на аккаунт. Здесь вызывающий
	// владеет своим аккаунтом, а проверка выполняется для другого аккаунта.
	require.NoError(t, NewCatalogWriteRepo(pool).RunInWriteTx(ctx, func(ctx context.Context, w modulecatalog.CatalogWriter) error {
		_, err := w.UpsertResource(ctx, catalog.ResourceRow{Module: "iam", Resource: "stageOrderChild", ObjectType: "stage_order_child",
			ParentNames: []string{"parent"}, ParentTypes: []string{"account"},
			ChildRegistration: &catalog.ChildRegistrationRule{Verb: "registerchild", ParentSegments: 1, MaxChildren: 4, MaxCreates: 2, WindowSeconds: 60}})
		if err != nil {
			return err
		}
		_, err = w.UpsertVerb(ctx, catalog.VerbRow{Module: "iam", Resource: "stageOrderChild", Verb: "registerchild", ContainerParent: "account", ContainerRelation: "owner"})
		return err
	}))
	halves, err := NewCatalogRepo(pool).ReadCatalogHalves(ctx)
	require.NoError(t, err)
	bundle, err := granteffect.NewBundle(ctx, authzmodel.DSL+"\ntype stage_order_child\n  relations\n    define parent: [account]\n", halves, granteffect.ProjectorVersion)
	require.NoError(t, err)
	missing := ids.NewID(domain.PrefixAccount)
	for _, candidate := range []struct {
		name, parent string
		exists       bool
	}{{"existing", parent.Account, true}, {"absent", missing, false}} {
		t.Run(candidate.name, func(t *testing.T) {
			tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
			require.NoError(t, err)
			defer func() { require.NoError(t, tx.Rollback(context.WithoutCancel(ctx))) }()
			var exists bool
			require.NoError(t, tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM kaname.accounts WHERE id=$1)`, candidate.parent).Scan(&exists))
			require.Equal(t, candidate.exists, exists, "состояния родителей реально различаются в том же RR")
			input := kaname.UserChildRegistrationInput{ResourceType: "iam.stageOrderChild", ResourceID: candidate.parent + "/candidate"}
			_, _, authQueries, authErr := ProbeUserChildAuthorization(ctx, tx, bundle, input, principal)
			require.ErrorIs(t, authErr, childPermissionDenied)
			require.ErrorIs(t, authErr, domain.ErrUserChildRegistrationRefused)
			require.Greater(t, len(authQueries), 1, "native авторизация действительно исполнила запросы")
			require.Contains(t, strings.Join(authQueries, "\n"), "email_verified_at", "проверен настоящий допуск человека, а не только форма principal")

			stage, stageErr := ProbeUserChildStage(ctx, tx, bundle, input, principal)
			require.ErrorIs(t, stageErr, childPermissionDenied)
			require.ErrorIs(t, stageErr, domain.ErrUserChildRegistrationRefused)
			require.Equal(t, authErr.Error(), stageErr.Error())
			require.Equal(t, authQueries, stage.Queries,
				"полный stage не читает регистрацию ни до авторизации, ни после её отказа")
			require.Empty(t, stage.Envelope)
			require.Empty(t, stage.Hierarchies)
			require.Empty(t, stage.OldScopes)
			require.Empty(t, stage.NewScopes)
			for _, sql := range stage.Queries {
				for _, forbidden := range []string{"_authority_child_registration_capture", "authority_child_creation", "authority_child_parent_state"} {
					require.NotContains(t, sql, forbidden)
				}
			}
			var registered bool
			require.NoError(t, tx.QueryRow(ctx, `SELECT EXISTS (
 SELECT 1 FROM kaname.resource_mirror WHERE object_type=$1 AND object_id=$2)`, input.ResourceType, input.ResourceID).Scan(&registered))
			require.False(t, registered, "отказ не создал регистрацию и версию")
			var effects bool
			require.NoError(t, tx.QueryRow(ctx, `SELECT
 EXISTS (SELECT 1 FROM kaname.resource_parent_edge WHERE object_type='stage_order_child' AND object_id=$2) OR
 EXISTS (SELECT 1 FROM kaname.resource_registration_scope WHERE object_type='stage_order_child' AND object_id=$2) OR
 EXISTS (SELECT 1 FROM kaname.relation_fact WHERE object_type='stage_order_child' AND object_id=$2) OR
 EXISTS (SELECT 1 FROM kaname.authority_child_creation WHERE child_type=$1 AND child_id=$2)`, input.ResourceType, input.ResourceID).Scan(&effects))
			require.False(t, effects, "отказ не создал цепь, область, факты или расход")
		})
	}
}
