// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

// Double выдаёт только реальные по форме carrier headers; permission answers
// здесь нет. Последняя страница и ошибка Query проверяются независимо от SQL.
type roleQuestionTx struct {
	pgx.Tx
	bindings     []domain.AccessBinding
	calls        int
	failCall     int
	rowsFailCall int
	failure      error
	cancel       context.CancelFunc
}

func (t *roleQuestionTx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	t.calls++
	if t.calls == t.failCall {
		return nil, t.failure
	}
	if t.cancel != nil && t.calls == 2 {
		t.cancel()
		return nil, ctx.Err()
	}
	after, limit := args[1].(string), args[2].(int)
	var page []domain.AccessBinding
	for _, b := range t.bindings {
		if string(b.ID) > after {
			page = append(page, b)
			if len(page) == limit {
				break
			}
		}
	}
	var rowError error
	if t.calls == t.rowsFailCall {
		rowError = t.failure
	}
	return &roleQuestionRows{page: page, failure: rowError}, nil
}

type roleQuestionRows struct {
	pgx.Rows
	page    []domain.AccessBinding
	index   int
	failure error
}

func (r *roleQuestionRows) Next() bool { return r.index < len(r.page) }
func (r *roleQuestionRows) Scan(dst ...any) error {
	b := r.page[r.index]
	r.index++
	*dst[0].(*domain.AccessBindingID) = b.ID
	*dst[1].(*domain.ResourceType) = b.ResourceType
	*dst[2].(*string) = b.ResourceID
	return nil
}
func (r *roleQuestionRows) Err() error { return r.failure }
func (*roleQuestionRows) Close()       {}
func roleQuestionFixture(n int) *roleQuestionTx {
	tx := &roleQuestionTx{}
	for i := 0; i < n; i++ {
		tx.bindings = append(tx.bindings, domain.AccessBinding{ID: domain.AccessBindingID(fmt.Sprintf("acb_%04d", i)), ResourceType: "account", ResourceID: fmt.Sprintf("acc_%04d", i)})
	}
	return tx
}
func roleQuestionRequest() roleNativeRequest {
	return roleNativeRequest{role: domain.Role{ID: "rol_target", AccountID: "acc_home", Rules: domain.Rules{{Module: "iam", Resources: []string{"role"}, Verbs: []string{"bind"}, ResourceNames: []string{"rol_reference"}}}}, content: true}
}
func TestRoleNativeQuestionsFullCarrierTailAndMethodReferences(t *testing.T) {
	for _, size := range []int{255, 256, 257} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			tx := roleQuestionFixture(size)
			q, rows, err := discoverRoleNativeQuestions(context.Background(), tx, nativeBoundaryActor(), roleQuestionRequest(), &relverdict.AdministrativeReadBudget{})
			require.NoError(t, err)
			require.Equal(t, size, rows)
			require.Equal(t, 1+size/256, tx.calls)
			for _, root := range []nativePolicyQuestion{
				{"user:usr_native", "system_admin", "cluster", domain.ClusterSingletonID},
				{"user:usr_native", "admin", "account", "acc_home"},
				{"user:usr_native", "v_update", "iam_role", "rol_target"},
				{"user:usr_native", "viewer", "iam_role", "rol_reference"},
				{"user:usr_native", "v_list", "iam_role", "rol_reference"},
				{"user:usr_native", "admin", "account", fmt.Sprintf("acc_%04d", size-1)},
			} {
				require.Contains(t, q.roots, root)
			}
			require.Len(t, q.roots, size+5)
		})
	}
}
func TestRoleNativeQuestionsLastPageErrorCancellationAndBudget(t *testing.T) {
	boom := errors.New("late carrier page unavailable")
	for _, mode := range []string{"error", "rows_error", "cancel", "budget"} {
		t.Run(mode, func(t *testing.T) {
			tx := roleQuestionFixture(257)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			budget := &relverdict.AdministrativeReadBudget{}
			want := boom
			switch mode {
			case "error":
				tx.failCall = 2
				tx.failure = boom
			case "rows_error":
				tx.rowsFailCall = 2
				tx.failure = boom
			case "cancel":
				tx.cancel = cancel
				want = context.Canceled
			case "budget":
				require.NoError(t, budget.Charge(100000-256, 0))
				want = kaname.ErrSourceReadLimit
			}
			q, _, err := discoverRoleNativeQuestions(ctx, tx, nativeBoundaryActor(), roleQuestionRequest(), budget)
			require.ErrorIs(t, err, want)
			require.Nil(t, q)
			require.Equal(t, 2, tx.calls)
		})
	}
}
func TestRoleNativeQuestionsExplicitMetadataProjectSystemAndNoScope(t *testing.T) {
	for _, tc := range []struct {
		name     string
		role     domain.Role
		create   bool
		object   string
		relation string
		typ      string
		failure  bool
	}{
		{name: "account_create", role: domain.Role{AccountID: "acc_home"}, create: true, object: "acc_home", relation: "editor", typ: "account"},
		{name: "project_create", role: domain.Role{ProjectID: "prj_home"}, create: true, object: "prj_home", relation: "editor", typ: "project"},
		{name: "system_update", role: domain.Role{ID: "rol_system", IsSystem: true, ClusterID: domain.ClusterID(domain.ClusterSingletonID)}, object: "rol_system", relation: "v_update", typ: "iam_role"},
		{name: "no_scope", role: domain.Role{ID: "rol_bad"}, failure: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx := roleQuestionFixture(257)
			q, rows, err := discoverRoleNativeQuestions(context.Background(), tx, nativeBoundaryActor(), roleNativeRequest{role: tc.role, create: tc.create}, &relverdict.AdministrativeReadBudget{})
			if tc.failure {
				require.Error(t, err)
				require.Nil(t, q)
			} else {
				require.NoError(t, err)
				require.Contains(t, q.roots, nativePolicyQuestion{"user:usr_native", tc.relation, tc.typ, tc.object})
			}
			require.Zero(t, rows)
			require.Zero(t, tx.calls)
		})
	}
	request := roleQuestionRequest()
	request.content = false
	q, _, err := discoverRoleNativeQuestions(context.Background(), roleQuestionFixture(257), nativeBoundaryActor(), request, &relverdict.AdministrativeReadBudget{})
	require.NoError(t, err)
	require.Len(t, q.roots, 3, "explicit metadata не объявляет proposed reference content")
}
func TestRoleStagePriorBudgetIsNotReset(t *testing.T) {
	s := &roleMutationStage{rows: policyDiscoveryRows - 1, reads: 4095}
	require.NoError(t, s.read(1))
	require.Equal(t, policyDiscoveryRows, s.rows)
	require.Equal(t, 4096, s.reads)
	require.ErrorIs(t, s.read(0), kaname.ErrSourceReadLimit)
	s = &roleMutationStage{rows: policyDiscoveryRows}
	require.ErrorIs(t, s.read(1), kaname.ErrSourceReadLimit)
}
