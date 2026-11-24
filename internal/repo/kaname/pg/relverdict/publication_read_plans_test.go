// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/authzplan"
	"github.com/PRO-Robotech/kaname/internal/authzsnapshot"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

// Первое чтение БД подтверждает, что штатный вход принял тип из закреплённой
// редакции, хотя в модели, с которой стартовал процесс, этого типа нет.
type publicationPlanReadTx struct {
	pgx.Tx
	err error
}

func (tx publicationPlanReadTx) QueryRow(context.Context, string, ...any) pgx.Row {
	return publicationPlanReadRow{err: tx.err}
}

type publicationPlanReadRow struct{ err error }

func (row publicationPlanReadRow) Scan(...any) error { return row.err }

func TestInverseReadersUsePublishedRequestPlans(t *testing.T) {
	plans, err := authzmodel.New("model\n  schema 1.1\ntype user\ntype publication_read_probe\n  relations\n    define v_get: [user]\n")
	require.NoError(t, err)
	oldPlans, err := authzmodel.New("model\n  schema 1.1\ntype user\n")
	require.NoError(t, err)
	ctx, err := authzsnapshot.WithContext(context.Background(), &authzsnapshot.Snapshot{
		Revision: 2, Digest: "published", CatalogID: "catalog", ConfirmedAt: time.Now(),
		Plans: plans, Facts: &catalog.Facts{},
	})
	require.NoError(t, err)
	readReached := errors.New("catalog read reached after resolving the published plan")
	tx := publicationPlanReadTx{err: readReached}
	for _, tc := range []struct {
		name string
		read func(context.Context, PlanSource) error
	}{
		{"objects", func(ctx context.Context, explicit PlanSource) error {
			_, _, err := List(ctx, tx, ListQuery{PreparedPlans: explicit, Subject: "user:reader", ObjectType: "publication_read_probe", Relation: "v_get"})
			return err
		}},
		{"subjects", func(ctx context.Context, explicit PlanSource) error {
			_, _, err := Subjects(ctx, tx, SubjectsQuery{PreparedPlans: explicit, ObjectType: "publication_read_probe", ObjectID: "document", Relation: "v_get"})
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.ErrorIs(t, tc.read(ctx, nil), readReached)
			// Подготовленная модель транзакции имеет приоритет над редакцией запроса.
			require.ErrorIs(t, tc.read(ctx, oldPlans), authzplan.ErrTypeNotDeclared)
		})
	}
}
