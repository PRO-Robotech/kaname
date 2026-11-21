// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/grantsource"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// Настоящая baseline-фикстура создаёт выдачу usr-0 на prj-home, без обхода
// ограничений БД. Второго субъекта добавляем настоящей строкой child-таблицы.
func TestActorBindingSourcesNativeSecondSubject(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	f := newScopeCarrierFixture(t, ctx)
	_, err := f.pool.Exec(ctx, `INSERT INTO kaname.access_binding_subjects
  (binding_id, subject_type, subject_id, ordinal)
  VALUES ('acb-1', 'user', 'usr-1', 1)`)
	require.NoError(t, err)
	// База требует наличия legacy-пары, но не первого ordinal. Порядок
	// child-строк не должен превращаться в дополнительную policy чтения.
	_, err = f.pool.Exec(ctx, `UPDATE kaname.access_binding_subjects SET ordinal=2 WHERE binding_id='acb-1' AND subject_id='usr-0'`)
	require.NoError(t, err)
	_, err = f.pool.Exec(ctx, `UPDATE kaname.access_binding_subjects SET ordinal=0 WHERE binding_id='acb-1' AND subject_id='usr-1'`)
	require.NoError(t, err)
	repo := kanamepg.New(f.pool, nil)
	w, err := repo.AuthorityWriter(ctx, kaname.AuthorityFencePlan{
		Mode: kaname.AuthorityFenceAccounts, Accounts: []domain.AccountID{"acc-1"},
	})
	require.NoError(t, err)
	defer func() { require.NoError(t, w.Rollback(context.Background())) }()
	actor := domain.Subject{Type: domain.SubjectTypeUser, ID: "usr-1"}
	sources, err := grantsource.CollectBindings(ctx, w, actor)
	require.NoError(t, err)
	found := false
	for _, s := range sources {
		if s.Binding.ID != "acb-1" {
			continue
		}
		require.False(t, found, "один прямой носитель не должен удваиваться")
		found = true
		require.Equal(t, actor, s.Recipient)
		require.Equal(t, []domain.Subject{
			actor, {Type: domain.SubjectTypeUser, ID: "usr-0"},
		}, s.Binding.Subjects)
		require.NotNil(t, s.Role)
		require.Equal(t, domain.RoleID("rol-1"), s.Role.ID)
		require.Equal(t, 0, s.CapabilityVersion, "базовая выдача хранит настоящую версию 0")
	}
	require.True(t, found, "непервый субъект child-таблицы должен находить выдачу")
	// Отсутствующий ключ версии не превращается адаптером в нулевую версию.
	versions, err := w.BindingCapabilityVersions(ctx, []domain.AccessBindingID{"acb-1", "missing-binding"})
	require.NoError(t, err)
	require.Contains(t, versions, domain.AccessBindingID("acb-1"))
	require.NotContains(t, versions, domain.AccessBindingID("missing-binding"))
}
