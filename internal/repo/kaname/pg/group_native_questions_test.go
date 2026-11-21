// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

type groupQuestionTx struct {
	pgx.Tx
	primary, additional []domain.AccessBinding
	calls               int
	failCall            int
	failure             error
	rowFailure          bool
	cancel              context.CancelFunc
	account             domain.AccountID
}
type groupQuestionRow struct{ account domain.AccountID }

func (r groupQuestionRow) Scan(dst ...any) error { *dst[0].(*domain.AccountID) = r.account; return nil }
func (t *groupQuestionTx) QueryRow(context.Context, string, ...any) pgx.Row {
	return groupQuestionRow{t.account}
}
func (t *groupQuestionTx) Query(ctx context.Context, query string, args ...any) (pgx.Rows, error) {
	t.calls++
	if t.calls == t.failCall && !t.rowFailure {
		return nil, t.failure
	}
	if t.cancel != nil && t.calls == 2 {
		t.cancel()
		return nil, ctx.Err()
	}
	list := t.primary
	if strings.Contains(query, "JOIN kaname.access_bindings") {
		list = t.additional
	}
	after, limit := args[1].(string), args[2].(int)
	var page []domain.AccessBinding
	for _, b := range list {
		if string(b.ID) > after {
			page = append(page, b)
			if len(page) == limit {
				break
			}
		}
	}
	var err error
	if t.calls == t.failCall {
		err = t.failure
	}
	return &groupQuestionRows{page: page, failure: err}, nil
}

type groupQuestionRows struct {
	pgx.Rows
	page    []domain.AccessBinding
	index   int
	failure error
}

func (r *groupQuestionRows) Next() bool { return r.index < len(r.page) }
func (r *groupQuestionRows) Scan(dst ...any) error {
	b := r.page[r.index]
	r.index++
	*dst[0].(*domain.AccessBindingID) = b.ID
	*dst[1].(*domain.ResourceType) = b.ResourceType
	*dst[2].(*string) = b.ResourceID
	*dst[3].(*domain.RoleID) = b.RoleID
	return nil
}
func (r *groupQuestionRows) Err() error { return r.failure }
func (*groupQuestionRows) Close()       {}
func groupQuestionFixture(n int, secondary bool) *groupQuestionTx {
	tx := &groupQuestionTx{account: "acc_home"}
	for i := 0; i < n; i++ {
		b := domain.AccessBinding{ID: domain.AccessBindingID(fmt.Sprintf("acb_%04d", i)), ResourceType: "account", ResourceID: fmt.Sprintf("acc_%04d", i), RoleID: domain.RoleID(fmt.Sprintf("rol_%04d", i))}
		if secondary {
			tx.additional = append(tx.additional, b)
		} else {
			tx.primary = append(tx.primary, b)
		}
	}
	return tx
}
func groupQuestionRequest() groupAdditionNativeRequest {
	return groupAdditionNativeRequest{member: domain.GroupMember{GroupID: "grp_native", MemberType: domain.SubjectTypeServiceAccount, MemberID: "sa_recipient"}}
}
func TestGroupNativeQuestionsEveryPrimaryAndAdditionalTail(t *testing.T) {
	for _, size := range []int{255, 256, 257} {
		for _, secondary := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/secondary=%v", size, secondary), func(t *testing.T) {
				tx := groupQuestionFixture(size, secondary)
				q, rows, err := discoverGroupNativeQuestions(context.Background(), tx, nativeBoundaryActor(), groupQuestionRequest(), &relverdict.AdministrativeReadBudget{})
				require.NoError(t, err)
				physical := size
				if secondary {
					physical *= 2
				}
				require.Equal(t, 1+physical, rows)
				expected := newNativePolicyQuestions()
				require.NoError(t, expected.groupBase(nativeBoundaryActor(), domain.Group{ID: "grp_native", AccountID: "acc_home"}))
				list := tx.primary
				if secondary {
					list = tx.additional
				}
				for _, b := range list {
					require.NoError(t, expected.groupCarrier(nativeBoundaryActor(), b))
				}
				require.Equal(t, expected.roots, q.roots)
				require.Len(t, q.roots, 3+3*size, "каждый scope admin и два exact meta корня; system_admin общий")
				require.Equal(t, 2+size/256, tx.calls)
			})
		}
	}
}
func TestGroupNativeQuestionsNoPartialLateErrorCancelMalformedOrSharedBudget(t *testing.T) {
	boom := errors.New("late GROUP page")
	for _, mode := range []string{"error", "rows_error", "cancel", "budget", "unknown_scope", "missing_role"} {
		t.Run(mode, func(t *testing.T) {
			tx := groupQuestionFixture(257, false)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			budget := &relverdict.AdministrativeReadBudget{}
			want := boom
			switch mode {
			case "error":
				tx.failCall = 2
				tx.failure = boom
			case "rows_error":
				tx.failCall = 2
				tx.failure = boom
				tx.rowFailure = true
			case "cancel":
				tx.cancel = cancel
				want = context.Canceled
			case "budget":
				require.NoError(t, budget.Charge(100000-257, 0))
				want = kaname.ErrSourceReadLimit
			case "unknown_scope":
				tx.primary[256].ResourceType = "unknown"
				want = nil
			case "missing_role":
				tx.primary[256].RoleID = ""
				want = nil
			}
			q, _, err := discoverGroupNativeQuestions(ctx, tx, nativeBoundaryActor(), groupQuestionRequest(), budget)
			require.Error(t, err)
			if want != nil {
				require.ErrorIs(t, err, want)
			}
			require.Nil(t, q)
			require.Equal(t, 2, tx.calls)
		})
	}
}
func TestGroupNativeQuestionsReadBudgetAndPurposeFailBeforeSQL(t *testing.T) {
	tx := groupQuestionFixture(1, false)
	budget := &relverdict.AdministrativeReadBudget{}
	require.NoError(t, budget.Charge(0, 4096))
	q, _, err := discoverGroupNativeQuestions(context.Background(), tx, nativeBoundaryActor(), groupQuestionRequest(), budget)
	require.ErrorIs(t, err, kaname.ErrSourceReadLimit)
	require.Nil(t, q)
	require.Zero(t, tx.calls)
	request := groupQuestionRequest()
	request.member.MemberType = domain.SubjectTypeGroup
	q, _, err = discoverGroupNativeQuestions(context.Background(), tx, nativeBoundaryActor(), request, &relverdict.AdministrativeReadBudget{})
	require.ErrorIs(t, err, kaname.ErrInvalidAuthorityFencePlan)
	require.Nil(t, q)
	require.Zero(t, tx.calls)
}
