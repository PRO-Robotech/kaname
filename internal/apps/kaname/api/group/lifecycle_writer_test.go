// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package group

import (
	"context"
	"errors"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/stretchr/testify/require"
)

type lifecycleFactoryProbe struct {
	writer Writer
	err    error
	kinds  []kaname.GroupMutation
	groups []domain.Group
}

func (p *lifecycleFactoryProbe) GroupLifecycleWriter(_ context.Context, k kaname.GroupMutation, g domain.Group) (kaname.Writer, error) {
	p.kinds = append(p.kinds, k)
	p.groups = append(p.groups, g)
	return p.writer, p.err
}

type lifecycleWriterProbe struct {
	fakeGrpWriter
	commits     int
	rollbackErr error
	bodyErr     error
}

func (w *lifecycleWriterProbe) Commit(context.Context) error { w.commits++; return nil }
func (w *lifecycleWriterProbe) Rollback(ctx context.Context) error {
	w.rollbackErr = ctx.Err()
	return nil
}
func TestGroupLifecycleWorkersUseSelectedWriter(t *testing.T) {
	for _, kind := range []kaname.GroupMutation{kaname.GroupCreate, kaname.GroupUpdate, kaname.GroupDelete} {
		t.Run(string(kind), func(t *testing.T) {
			legacy, old := newFakeMemberRepo()
			selected := &lifecycleWriterProbe{}
			f := &lifecycleFactoryProbe{writer: selected}
			g := domain.Group{ID: testGroupID, AccountID: metaAcc, Name: "participant-group"}
			var err error
			switch kind {
			case kaname.GroupCreate:
				_, err = NewCreateGroupUseCase(legacy, nil).WithLifecycleWriter(f).doCreate(context.Background(), g, "actor")
			case kaname.GroupUpdate:
				_, err = NewUpdateGroupUseCase(legacy, nil).WithLifecycleWriter(f).doUpdate(context.Background(), g, []string{"name"}, "actor", []string{"name"})
			case kaname.GroupDelete:
				_, err = NewDeleteGroupUseCase(legacy, nil).WithLifecycleWriter(f).doDelete(context.Background(), g.ID, "actor", string(g.AccountID))
			}
			require.NoError(t, err)
			require.Equal(t, 1, selected.commits)
			require.Empty(t, old.seq)
			require.False(t, old.committed)
			require.Equal(t, []kaname.GroupMutation{kind}, f.kinds)
			require.Equal(t, g.ID, f.groups[0].ID)
			require.Equal(t, g.AccountID, f.groups[0].AccountID)
		})
	}
}
func TestGroupLifecycleEntryFailureAndCancelledRollback(t *testing.T) {
	var typedNil *lifecycleFactoryProbe
	for name, f := range map[string]kaname.GroupLifecycleWriterFactory{"nil": nil, "typed_nil": typedNil, "closed": &lifecycleFactoryProbe{err: errors.New("closed")}, "no_writer": &lifecycleFactoryProbe{}, "ownership_changed": &lifecycleFactoryProbe{err: kaname.ErrAuthorityClassificationChanged}} {
		t.Run(name, func(t *testing.T) {
			legacy, old := newFakeMemberRepo()
			for _, kind := range []kaname.GroupMutation{kaname.GroupCreate, kaname.GroupUpdate, kaname.GroupDelete} {
				err := (lifecycleWriterSelection{true, f}).run(context.Background(), legacy, kind, domain.Group{ID: testGroupID}, func(context.Context, Writer) error { t.Fatal("body reached after failed entry"); return nil })
				require.Error(t, err)
			}
			require.Empty(t, old.seq)
			require.False(t, old.committed)
		})
	}
	repo, _ := newFakeMemberRepo()
	selected := &lifecycleWriterProbe{}
	f := &lifecycleFactoryProbe{writer: selected}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out, err := withGroupLifecycleTx(ctx, lifecycleWriterSelection{true, f}, repo, kaname.GroupCreate, domain.Group{ID: testGroupID}, func(context.Context, Writer) (string, error) { cancel(); return "partial", nil })
	require.Error(t, err)
	require.Empty(t, out)
	require.Zero(t, selected.commits)
	require.NoError(t, selected.rollbackErr)
}
