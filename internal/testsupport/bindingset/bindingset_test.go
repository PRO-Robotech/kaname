// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package bindingset

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

type recordingExecer struct{ seen []string }

func (r *recordingExecer) Exec(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
	r.seen = append(r.seen, sql)
	return pgconn.CommandTag{}, nil
}

func TestWithWrapsTheInsertIntoOneStatement(t *testing.T) {
	got := With("\n\tINSERT INTO kaname.access_bindings (id) VALUES ($1)\n")
	require.Equal(t,
		"WITH bound AS (INSERT INTO kaname.access_bindings (id) VALUES ($1) "+
			"RETURNING id, subject_type, subject_id, resource_type, resource_id) "+
			"INSERT INTO kaname.access_binding_subjects "+
			"(binding_id, subject_type, subject_id, ordinal, resource_type, resource_id) "+
			"SELECT id, subject_type, subject_id, 0, resource_type, resource_id FROM bound",
		got)
}

func TestSeedIssuesItsOwnStatement(t *testing.T) {
	rec := &recordingExecer{}
	Seed(t, context.Background(), rec)
	require.Equal(t, []string{SeedSQL}, rec.seen)
}

type fakeWriter struct {
	insertErr error
	sets      map[domain.AccessBindingID][]domain.Subject
}

func (f *fakeWriter) Insert(_ context.Context, b domain.AccessBinding) (domain.AccessBinding, error) {
	if f.insertErr != nil {
		return domain.AccessBinding{}, f.insertErr
	}
	return domain.AccessBinding{ID: b.ID, SubjectType: b.SubjectType, SubjectID: b.SubjectID}, nil
}

func (f *fakeWriter) InsertSubjects(_ context.Context, id domain.AccessBindingID, s []domain.Subject) error {
	if f.sets == nil {
		f.sets = map[domain.AccessBindingID][]domain.Subject{}
	}
	f.sets[id] = append(f.sets[id], s...)
	return nil
}

func TestInsertWritesTheSetFromThePairOrFromSubjects(t *testing.T) {
	ctx := context.Background()
	w := &fakeWriter{}
	_, err := Insert(ctx, w, domain.AccessBinding{ID: "acb1", SubjectType: domain.SubjectTypeUser, SubjectID: "usr1"})
	require.NoError(t, err)
	require.Equal(t, []domain.Subject{{Type: domain.SubjectTypeUser, ID: "usr1"}}, w.sets["acb1"], "без Subjects — строка из пары")

	set := []domain.Subject{{Type: domain.SubjectTypeUser, ID: "usr1"}, {Type: domain.SubjectTypeGroup, ID: "grp1"}}
	_, err = Insert(ctx, w, domain.AccessBinding{ID: "acb2", SubjectType: domain.SubjectTypeUser, SubjectID: "usr1", Subjects: set})
	require.NoError(t, err)
	require.Equal(t, set, w.sets["acb2"], "Subjects пишутся как есть")

	refused := &fakeWriter{insertErr: errors.New("отказ вставки")}
	_, err = Insert(ctx, refused, domain.AccessBinding{ID: "acb3", SubjectType: domain.SubjectTypeUser, SubjectID: "usr1"})
	require.EqualError(t, err, "отказ вставки")
	require.Empty(t, refused.sets, "после отказанной вставки набор не пишется")
}
