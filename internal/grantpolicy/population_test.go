// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package grantpolicy

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	ab "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
)

type populationFence struct{ at time.Time }

func (f populationFence) Mode() kaname.AuthorityFenceMode { return kaname.AuthorityFenceGlobal }
func (f populationFence) Accounts() []domain.AccountID    { return nil }
func (f populationFence) DecisionAt() time.Time           { return f.at }

type populationReader struct {
	ab.ReaderIface
	read func(context.Context, []domain.AccessBindingID) (map[domain.AccessBindingID][]domain.Subject, error)
}

func (r populationReader) ListSubjectsForBindings(ctx context.Context, ids []domain.AccessBindingID) (map[domain.AccessBindingID][]domain.Subject, error) {
	if r.read != nil {
		return r.read(ctx, ids)
	}
	out := map[domain.AccessBindingID][]domain.Subject{}
	for _, id := range ids {
		out[id] = []domain.Subject{{Type: domain.SubjectTypeGroup, ID: "grp_population"}}
	}
	return out, nil
}

type populationWriter struct {
	kaname.SemanticAuthorityWriter
	at     time.Time
	reader ab.ReaderIface
}

func (w populationWriter) AccessBindings() ab.ReaderIface {
	if w.reader != nil {
		return w.reader
	}
	return populationReader{}
}
func (w populationWriter) AuthorityFence() kaname.AuthorityFence { return populationFence{w.at} }
func TestPopulationLastPendingPageAndLateFailureAreNotTruncatedSuccess(t *testing.T) {
	w := populationWriter{at: time.Now()}
	for _, late := range []bool{false, true} {
		reads, visits := 0, 0
		terminal := errors.New("late page unavailable")
		err := population(context.Background(), w, func(token string) ([]domain.AccessBinding, string, error) {
			reads++
			if token == "" {
				return []domain.AccessBinding{{ID: "acb_first", Status: domain.AccessBindingStatusActive}}, "last", nil
			}
			if late {
				return nil, "", terminal
			}
			return []domain.AccessBinding{{ID: "acb_pending", Status: domain.AccessBindingStatusPending}}, "", nil
		}, func(b domain.AccessBinding) error {
			visits++
			if b.Status == domain.AccessBindingStatusPending {
				return denied()
			}
			return nil
		})
		require.Error(t, err)
		require.Equal(t, 2, reads)
		if late {
			require.ErrorIs(t, err, terminal)
			require.Equal(t, 1, visits)
		} else {
			require.Equal(t, 2, visits)
		}
	}
}
func TestPopulationExpiryUsesPostFenceDecisionAt(t *testing.T) {
	at := time.Now()
	expired := at.Add(-time.Nanosecond)
	future := at.Add(time.Nanosecond)
	seen := []domain.AccessBindingID{}
	err := population(context.Background(), populationWriter{at: at}, func(string) ([]domain.AccessBinding, string, error) {
		return []domain.AccessBinding{
			{ID: "acb_old", Status: domain.AccessBindingStatusActive, ExpiresAt: &expired},
			{ID: "acb_at", Status: domain.AccessBindingStatusPending, ExpiresAt: &at},
			{ID: "acb_next", Status: domain.AccessBindingStatusPending, ExpiresAt: &future},
		}, "", nil
	}, func(b domain.AccessBinding) error { seen = append(seen, b.ID); return nil })
	require.NoError(t, err)
	require.Equal(t, []domain.AccessBindingID{"acb_next"}, seen)
}

// Это исходный достижимый контрпример: 4000 истёкших ACTIVE/PENDING
// носителей с 32 subjects каждый. Нулевой эффект не означает бесплатное чтение.
func TestPopulationExpiredPhysicalSubjectsExhaustBudget(t *testing.T) {
	at := time.Now()
	expired := at.Add(-time.Second)
	pageReads, subjectReads, physical, visits := 0, 0, 0, 0
	cursor := 0
	reader := populationReader{read: func(_ context.Context, ids []domain.AccessBindingID) (map[domain.AccessBindingID][]domain.Subject, error) {
		subjectReads++
		out := map[domain.AccessBindingID][]domain.Subject{}
		for _, id := range ids {
			out[id] = populationSubjects(32)
			physical += 32
		}
		return out, nil
	}}
	w := populationWriter{at: at, reader: reader}
	err := population(context.Background(), w, func(string) ([]domain.AccessBinding, string, error) {
		pageReads++
		end := min(cursor+256, 4000)
		rows := make([]domain.AccessBinding, 0, end-cursor)
		for cursor < end {
			status := domain.AccessBindingStatusActive
			if cursor%2 == 1 {
				status = domain.AccessBindingStatusPending
			}
			rows = append(rows, domain.AccessBinding{ID: domain.AccessBindingID(fmt.Sprintf("acb_expired_%d", cursor)), Status: status, ExpiresAt: &expired})
			cursor++
		}
		physical += len(rows)
		next := ""
		if cursor < 4000 {
			next = fmt.Sprintf("page_%d", cursor)
		}
		return rows, next, nil
	}, func(domain.AccessBinding) error { visits++; return nil })
	require.ErrorIs(t, err, kaname.ErrSourceReadLimit)
	require.Greater(t, physical, 100000)
	require.Equal(t, pageReads, subjectReads)
	require.Less(t, cursor, 4000, "остаток не читается после исчерпания бюджета")
	require.Zero(t, visits, "expired sources не должны давать эффект")
}

func populationSubjects(count int) []domain.Subject {
	out := make([]domain.Subject, count)
	for i := range out {
		out[i] = domain.Subject{Type: domain.SubjectTypeGroup, ID: domain.SubjectID(fmt.Sprintf("grp_population_%d", i))}
	}
	return out
}

func TestPopulationMixedPhysicalBudgetExactBoundaryAndLastPage(t *testing.T) {
	// 3030 * (1 carrier + 32 subjects) = 99990. Последняя страница
	// содержит один live carrier и 9 либо 10 subjects: 100000 либо 100001.
	for _, lastSubjects := range []int{9, 10} {
		t.Run(fmt.Sprintf("physical_%d", 99991+lastSubjects), func(t *testing.T) {
			at := time.Now()
			expired := at.Add(-time.Second)
			cursor, physical, visits := 0, 0, 0
			lastVisited := false
			reader := populationReader{read: func(_ context.Context, ids []domain.AccessBindingID) (map[domain.AccessBindingID][]domain.Subject, error) {
				out := map[domain.AccessBindingID][]domain.Subject{}
				for _, id := range ids {
					n := 32
					if id == "acb_boundary_last" {
						n = lastSubjects
					}
					out[id] = populationSubjects(n)
					physical += n
				}
				return out, nil
			}}
			err := population(context.Background(), populationWriter{at: at, reader: reader}, func(string) ([]domain.AccessBinding, string, error) {
				if cursor == 3030 {
					physical++
					return []domain.AccessBinding{{ID: "acb_boundary_last", Status: domain.AccessBindingStatusPending}}, "", nil
				}
				end := min(cursor+256, 3030)
				rows := make([]domain.AccessBinding, 0, end-cursor)
				for cursor < end {
					b := domain.AccessBinding{ID: domain.AccessBindingID(fmt.Sprintf("acb_mixed_%d", cursor)), Status: domain.AccessBindingStatusActive}
					if cursor%2 == 0 {
						b.ExpiresAt = &expired
					}
					rows = append(rows, b)
					cursor++
				}
				physical += len(rows)
				return rows, fmt.Sprintf("page_%d", cursor), nil
			}, func(b domain.AccessBinding) error {
				visits++
				if b.ID == "acb_boundary_last" {
					lastVisited = true
				}
				return nil
			})
			require.Equal(t, 99991+lastSubjects, physical)
			if lastSubjects == 9 {
				require.NoError(t, err)
				require.True(t, lastVisited)
				require.Equal(t, 1516, visits)
			} else {
				require.ErrorIs(t, err, kaname.ErrSourceReadLimit)
				require.False(t, lastVisited, "последний carrier не обрабатывается после превышения physical budget")
				require.Equal(t, 1515, visits)
			}
		})
	}
}

func TestPopulationLateSubjectErrorAndCancellationFailBeforeLastVisitor(t *testing.T) {
	for _, failure := range []string{"reader_error", "cancel_page", "cancel_subjects"} {
		t.Run(failure, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			terminal := errors.New("late subject read unavailable")
			reads, subjectReads, visits := 0, 0, 0
			reader := populationReader{read: func(_ context.Context, ids []domain.AccessBindingID) (map[domain.AccessBindingID][]domain.Subject, error) {
				subjectReads++
				if subjectReads == 2 {
					if failure == "reader_error" {
						return nil, terminal
					}
					if failure == "cancel_subjects" {
						cancel()
					}
				}
				out := map[domain.AccessBindingID][]domain.Subject{}
				for _, id := range ids {
					out[id] = populationSubjects(1)
				}
				return out, nil
			}}
			err := population(ctx, populationWriter{at: time.Now(), reader: reader}, func(string) ([]domain.AccessBinding, string, error) {
				reads++
				if reads == 1 {
					return []domain.AccessBinding{{ID: "acb_before", Status: domain.AccessBindingStatusActive}}, "last", nil
				}
				if failure == "cancel_page" {
					cancel()
				}
				return []domain.AccessBinding{{ID: "acb_after", Status: domain.AccessBindingStatusPending}}, "", nil
			}, func(domain.AccessBinding) error { visits++; return nil })
			require.Equal(t, 2, reads)
			require.Equal(t, 1, visits)
			if failure == "reader_error" {
				require.ErrorIs(t, err, terminal)
			} else {
				require.ErrorIs(t, err, context.Canceled)
			}
			if failure == "cancel_page" {
				require.Equal(t, 1, subjectReads)
			} else {
				require.Equal(t, 2, subjectReads)
			}
		})
	}
}
