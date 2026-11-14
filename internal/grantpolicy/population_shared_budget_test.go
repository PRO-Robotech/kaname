// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package grantpolicy

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/stretchr/testify/require"
)

type sharedPopulationWriter struct {
	populationWriter
	rows, reads         int
	rowLimit, readLimit int
}

func (w *sharedPopulationWriter) ChargeSourceRead(c kaname.SourceReadCost) error {
	if c.Rows < 0 || c.Reads < 0 || c.Rows > w.rowLimit-w.rows || c.Reads > w.readLimit-w.reads {
		return kaname.ErrSourceReadLimit
	}
	w.rows += c.Rows
	w.reads += c.Reads
	return nil
}
func TestPopulationSharedBudgetBeforeNextReadAndNoReset(t *testing.T) {
	for _, limit := range []int{0, 1} {
		t.Run(string(rune('0'+limit)), func(t *testing.T) {
			pageReads, subjectReads := 0, 0
			w := &sharedPopulationWriter{populationWriter: populationWriter{at: time.Now(), reader: populationReader{read: func(context.Context, []domain.AccessBindingID) (map[domain.AccessBindingID][]domain.Subject, error) {
				subjectReads++
				return nil, nil
			}}}, rowLimit: 100000, readLimit: limit}
			err := population(context.Background(), w, func(string) ([]domain.AccessBinding, string, error) {
				pageReads++
				return []domain.AccessBinding{{ID: "acb_one", Status: domain.AccessBindingStatusActive}}, "", nil
			}, func(domain.AccessBinding) error { t.Fatal("budget не допускает visit"); return nil })
			require.ErrorIs(t, err, kaname.ErrSourceReadLimit)
			require.Equal(t, limit, pageReads)
			require.Zero(t, subjectReads)
			err = population(context.Background(), w, func(string) ([]domain.AccessBinding, string, error) {
				t.Fatal("повторный вызов не сбрасывает budget")
				return nil, "", nil
			}, func(domain.AccessBinding) error { return nil })
			require.ErrorIs(t, err, kaname.ErrSourceReadLimit)
		})
	}
}
func TestPopulationSharedExactPhysicalCostIncludesSentinelAndExpiredSubjects(t *testing.T) {
	at := time.Now()
	old := at.Add(-time.Second)
	w := &sharedPopulationWriter{populationWriter: populationWriter{at: at}, rowLimit: 5, readLimit: 4}
	visits := 0
	err := population(context.Background(), w, func(token string) ([]domain.AccessBinding, string, error) {
		if token == "" {
			return []domain.AccessBinding{{ID: "acb_old", Status: domain.AccessBindingStatusActive, ExpiresAt: &old}}, "tail", nil
		}
		return []domain.AccessBinding{{ID: "acb_tail", Status: domain.AccessBindingStatusPending}}, "", nil
	}, func(b domain.AccessBinding) error {
		visits++
		require.Equal(t, domain.AccessBindingID("acb_tail"), b.ID)
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, 1, visits)
	require.Equal(t, 5, w.rows)
	require.Equal(t, 4, w.reads)
	// Ни header, ни subjects не начислены дважды; exhausted shared pointer живёт
	// после успешного population и запрещает следующее чтение.
	require.ErrorIs(t, chargePopulationRead(w, 0, 1), kaname.ErrSourceReadLimit)
}
func TestPopulationSharedLateErrorCancelAndSentinelLimit(t *testing.T) {
	for _, mode := range []string{"error", "cancel", "sentinel"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			boom := errors.New("late population page")
			w := &sharedPopulationWriter{populationWriter: populationWriter{at: time.Now()}, rowLimit: 100000, readLimit: 4096}
			if mode == "sentinel" {
				w.rowLimit = 1
			}
			visits, reads := 0, 0
			err := population(ctx, w, func(token string) ([]domain.AccessBinding, string, error) {
				reads++
				if token == "" {
					return []domain.AccessBinding{{ID: "acb_first", Status: domain.AccessBindingStatusActive}}, "tail", nil
				}
				if mode == "cancel" {
					cancel()
					return nil, "", nil
				}
				return nil, "", boom
			}, func(domain.AccessBinding) error { visits++; return nil })
			switch mode {
			case "sentinel":
				require.ErrorIs(t, err, kaname.ErrSourceReadLimit)
				require.Equal(t, 1, reads)
				require.Zero(t, visits)
			case "cancel":
				require.ErrorIs(t, err, context.Canceled)
				require.Equal(t, 2, reads)
				require.Equal(t, 1, visits)
			default:
				require.ErrorIs(t, err, boom)
				require.Equal(t, 2, reads)
				require.Equal(t, 1, visits)
			}
		})
	}
}
