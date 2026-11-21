// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// Проверяется только передача захваченных значений в общий envelope; fake TX
// не подтверждает authority и не выполняет SQL prewait.
func TestResourceObjectProposalKeepsExactClosedIntentAndSources(t *testing.T) {
	for _, route := range []resourceObjectRoute{resourceObjectFull, resourceObjectForward, resourceObjectForwardNoStale} {
		raw := &resourceLifecycleTx{conn: new(pgx.Conn)}
		lifetime, err := newResourceAttemptLifetime(raw.conn, nativeBoundaryBundle(t))
		require.NoError(t, err)
		source, err := newResourceSourceCapture(raw, &relverdict.AdministrativeReadBudget{}, lifetime)
		require.NoError(t, err)
		parents, err := newResourceParentCapture(raw, source)
		require.NoError(t, err)
		source.entries[resourceSourceKey{kind: resourceSourceAccount, typ: "account", id: "acc_object"}] = []resourceSourceRow{{state: "state_b"}, {state: "state_a"}}
		parents.catalogs["iam.account"] = &resourceCatalogCapture{input: "iam.account", rows: []resourceCatalogRow{{state: "catalog_state"}}}
		prepared := &resourceObjectPreparation{effects: &resourceObjectEffectProposal{Bindings: []resourceObjectBindingProposal{}, Parents: []resourceEffectSourceRef{}}, lifetime: lifetime, source: source, route: route, root: &resourceOutputCapture{object: domain.ResourceRef{Type: "iam.account", ID: "acc_object"}}}
		footprint := resourceFenceFootprint{plan: kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceAccounts, Accounts: []domain.AccountID{"acc_object"}}, owners: []kaname.AuthorityOwnerRef{{Kind: "account", ID: "acc_object"}}, objects: []domain.ResourceRef{{Type: "iam.account", ID: "acc_object"}}}
		proposal, err := makeResourceObjectProposal(prepared, parents, footprint)
		require.NoError(t, err)
		var intent struct {
			Kind  string              `json:"kind"`
			Type  string              `json:"object_type"`
			ID    string              `json:"object_id"`
			Route resourceObjectRoute `json:"route"`
		}
		require.NoError(t, json.Unmarshal(proposal.intent, &intent))
		require.Equal(t, "object", intent.Kind)
		require.Equal(t, "iam.account", intent.Type)
		require.Equal(t, "acc_object", intent.ID)
		require.Equal(t, route, intent.Route)
		var envelope resourceProposalEnvelope
		require.NoError(t, json.Unmarshal(proposal.payload, &envelope))
		require.Equal(t, 2, envelope.ABI)
		require.JSONEq(t, string(proposal.intent), string(envelope.Intent))
		require.Equal(t, footprint.owners, envelope.Owners)
		require.Equal(t, footprint.objects, envelope.Objects)
		require.Len(t, envelope.Sources, 1)
		require.Equal(t, []string{"state_a", "state_b"}, envelope.Sources[0].States)
		require.Equal(t, "acc_object", envelope.Sources[0].ID)
		require.Equal(t, []resourceProposalCatalog{{Input: "iam.account", States: []string{"catalog_state"}}}, envelope.Catalogs)
		require.Empty(t, envelope.Registration)
		require.Empty(t, envelope.Installation)
		require.Empty(t, envelope.Actor)
		require.Empty(t, envelope.Service)
		require.Empty(t, envelope.NativeGuards)
		require.JSONEq(t, "{}", string(envelope.NativeEpochs))
		require.Same(t, lifetime, proposal.lifetime)
		require.Nil(t, proposal.prepared, "сериализация не выдаёт held proof")
		require.False(t, source.sealed)
		// Общий сериализатор переносит те же exact источники независимо от
		// intent. Это проверка envelope, не admission регистрации или отказа.
		refusal := kaname.ResourceDecisionIntent{Action: kaname.ResourceDecisionRecordRefusal}
		refusalIntent, err := json.Marshal(refusal)
		require.NoError(t, err)
		sharedEnvelope, _, err := makeResourceProposalEnvelope(refusalIntent, parents, footprint)
		require.NoError(t, err)
		require.JSONEq(t, string(refusalIntent), string(sharedEnvelope.Intent))
		require.Equal(t, envelope.Sources, sharedEnvelope.Sources)
		require.Equal(t, envelope.Catalogs, sharedEnvelope.Catalogs)
		// Refusal требует отдельного verified preparation и конструктора;
		// generic registration не принимает его даже с захваченными источниками.
		registration, err := makeResourceRegistrationProposal(refusal, parents, footprint, nil)
		require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
		require.Nil(t, registration)
		_, err = makeResourceRegistrationProposal(kaname.ResourceDecisionIntent{Action: kaname.ResourceDecisionRegister}, parents, footprint, nil)
		require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
		require.NoError(t, source.seal())
		_, err = makeResourceObjectProposal(prepared, parents, footprint)
		require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed, "нельзя расширить sealed RR capture")
	}
}

func TestResourceObjectDecisionSizesUseHeldEligibilityAndDesiredCoordinates(t *testing.T) {
	lifetime, owner, raw := resourceLifetimeFixture(t)
	at, later := lifetime.at, lifetime.at.Add(time.Second)
	prepared := &resourceObjectPreparation{lifetime: lifetime, root: &resourceOutputCapture{bindings: map[string]domain.AccessBinding{
		"ab_live": {ID: "ab_live", ExpiresAt: &later}, "ab_empty": {ID: "ab_empty"},
		"ab_expired": {ID: "ab_expired", ExpiresAt: &at}, "ab_inactive": {ID: "ab_inactive"},
	}}, inputs: []reconcile.CapturedObjectDiff{
		{Binding: reconcile.BindingScope{BindingID: "ab_live", Active: true}, Desired: []reconcile.DesiredMember{
			{ObjectType: "vpc.network", ObjectID: "same", Tuples: []domain.MembershipTuple{{Relation: "viewer"}}},
			{ObjectType: "vpc.network", ObjectID: "same", Tuples: []domain.MembershipTuple{{Relation: "v_get"}, {Relation: "v_list"}}},
			{ObjectType: "vpc.subnet", ObjectID: "same"},
		}},
		{Binding: reconcile.BindingScope{BindingID: "ab_empty", Active: true}},
		{Binding: reconcile.BindingScope{BindingID: "ab_expired", Active: true}},
		{Binding: reconcile.BindingScope{BindingID: "ab_inactive", Active: false}},
	}}
	tx := &resourceDecisionTx{Tx: raw, owner: owner, lifetime: lifetime}
	sizes, err := resourceObjectDecisionSizes(prepared, tx)
	require.NoError(t, err)
	require.Equal(t, []reconcile.ObjectDecisionSize{{Objects: 2, Tuples: 3}, {}}, sizes)
	require.True(t, prepared.inputs[2].Binding.Active, "held TTL не переписывает RR snapshot")
	owner.fence.decisionAt = later
	_, err = resourceObjectDecisionSizes(prepared, tx)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed, "новый clock не оживляет прошлую попытку")
}

// Настоящий pgx pool формирует ConnectError без сети. Это entry-control,
// не успешная authority/TX проба: SQL preparation/body сюда не допускаются.
func TestResourceObjectRunnerEntryPreservesOutageAndClosedRoutes(t *testing.T) {
	for _, route := range []reconcile.ObjectDecisionRoute{reconcile.ObjectDecisionFull, reconcile.ObjectDecisionForward, reconcile.ObjectDecisionForwardNoStale} {
		cfg, err := pgxpool.ParseConfig("host=127.0.0.1 port=5432 user=private_object database=private_object sslmode=disable")
		require.NoError(t, err)
		cfg.MaxConns, cfg.MinConns = 1, 0
		cause := &pgconn.PgError{Code: "28000", Message: "private object login refused"}
		var dials atomic.Int32
		cfg.ConnConfig.DialFunc = func(context.Context, string, string) (net.Conn, error) { dials.Add(1); return nil, cause }
		pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
		require.NoError(t, err)
		func() {
			defer pool.Close()
			bundle := nativeBoundaryBundle(t)
			var halves catalog.Halves
			require.NoError(t, json.Unmarshal(bundle.CanonicalCatalog(), &halves))
			facts, err := catalog.NewFacts(halves)
			require.NoError(t, err)
			runner := &ResourceDecisionRunner{repo: New(pool, nil), bundle: bundle, facts: facts}
			engine, err := runner.NewObjectReconciler(nil)
			require.NoError(t, err, "object OUTPUT не добавляет module installation gate")
			require.NotNil(t, engine)
			out, err := runner.RunObjectDecision(context.Background(), "iam.account", "acc_object", 0)
			require.ErrorIs(t, err, kaname.ErrInvalidAuthorityFencePlan)
			require.Nil(t, out)
			require.Zero(t, dials.Load())
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			out, err = runner.RunObjectDecision(ctx, "iam.account", "acc_object", route)
			require.ErrorIs(t, err, context.Canceled)
			require.Nil(t, out)
			require.Zero(t, dials.Load())
			out, err = runner.RunObjectDecision(context.Background(), "iam.account", "acc_object", route)
			require.ErrorIs(t, err, iamerr.ErrUnavailable)
			require.ErrorIs(t, err, cause)
			var envelope *pgconn.ConnectError
			require.ErrorAs(t, err, &envelope)
			require.Nil(t, out)
			require.EqualValues(t, 1, dials.Load(), "отказ LOGIN не повторяет whole attempt")
			require.Zero(t, pool.Stat().AcquiredConns())
		}()
	}
}

func TestResourceObjectRunnerMissingOwnerCannotCreateEngine(t *testing.T) {
	var runner *ResourceDecisionRunner
	engine, err := runner.NewObjectReconciler(nil)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
	require.Nil(t, engine)
	out, err := runner.RunObjectDecision(context.Background(), "iam.account", "acc_object", reconcile.ObjectDecisionFull)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
	require.Nil(t, out)
}
