// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

func TestChildRegistrationCatalogRoundTripAndPlanIdentity(t *testing.T) {
	ctx, db, _ := authorityTestDB(t)
	writer := kanamepg.NewCatalogWriteRepo(db)
	reader := kanamepg.NewCatalogRepo(db)
	const module = "childregistrationprobe"
	child := catalog.ResourceRow{
		Module: module, Resource: "child", ObjectType: module + "_child",
		ParentNames: []string{"parent"}, ParentTypes: []string{module + "_parent"},
	}
	require.NoError(t, writer.RunInWriteTx(ctx, func(ctx context.Context, w modulecatalog.CatalogWriter) error {
		if _, err := w.UpsertModule(ctx, module); err != nil {
			return err
		}
		if _, err := w.UpsertResource(ctx, catalog.ResourceRow{Module: module, Resource: "parent", ObjectType: module + "_parent"}); err != nil {
			return err
		}
		if _, err := w.UpsertResource(ctx, child); err != nil {
			return err
		}
		_, err := w.UpsertVerb(ctx, catalog.VerbRow{
			Module: module, Resource: child.Resource, Verb: "registerchild",
			ContainerParent: module + "_parent", ContainerRelation: "child_registrar",
		})
		return err
	}))
	snapshot := func() []byte {
		t.Helper()
		rows, err := reader.ReadCatalogHalves(ctx)
		require.NoError(t, err)
		data, err := catalog.CanonicalJSON(rows)
		require.NoError(t, err)
		return data
	}
	legacy := snapshot()
	require.NotContains(t, string(legacy), "\"ChildRegistration\"")

	state := moduleStateOf(t, ctx, db, module)
	apply := func(rule *catalog.ChildRegistrationRule, expectedChange bool) error {
		t.Helper()
		child.ChildRegistration = rule
		return writer.RunInWriteTx(ctx, func(ctx context.Context, w modulecatalog.CatalogWriter) error {
			changed, err := w.UpsertResource(ctx, child)
			if err != nil {
				return err
			}
			require.Equal(t, expectedChange, changed)
			rows, err := w.ReadModule(ctx, module)
			require.NoError(t, err)
			require.Len(t, rows.Resources, 2)
			require.Equal(t, child.Resource, rows.Resources[0].Resource)
			require.Equal(t, rule, rows.Resources[0].ChildRegistration)
			return nil
		})
	}
	rule := catalog.ChildRegistrationRule{
		Verb: "registerchild", ParentSegments: 1, MaxChildren: 24, MaxCreates: 4, WindowSeconds: 60,
	}
	require.NoError(t, apply(&rule, true))
	active := snapshot()
	require.NotEqual(t, legacy, active)
	require.Contains(t, string(active), "\"ChildRegistration\":{\"Verb\":\"registerchild\",\"ParentSegments\":1,\"MaxChildren\":24,\"MaxCreates\":4,\"WindowSeconds\":60}")
	activeState := moduleStateOf(t, ctx, db, module)
	require.NotEqual(t, state, activeState)
	require.NoError(t, apply(&rule, false))
	require.Equal(t, activeState, moduleStateOf(t, ctx, db, module))

	invalid := rule
	invalid.MaxChildren = 0
	var pgErr *pgconn.PgError
	require.ErrorAs(t, apply(&invalid, false), &pgErr)
	require.Equal(t, "23514", pgErr.Code)
	require.Equal(t, "catalog_resource_child_registration_form", pgErr.ConstraintName)
	require.Equal(t, active, snapshot())

	require.NoError(t, apply(nil, true))
	require.Equal(t, legacy, snapshot())
	require.Equal(t, state, moduleStateOf(t, ctx, db, module))
}
