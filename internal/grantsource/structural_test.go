// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package grantsource

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/grantcoverage"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/stretchr/testify/require"
)

type structuralWriter struct {
	kaname.AuthorityWriter
	at       time.Time
	direct   func(kaname.CanonicalSourceFilter) ([]kaname.CanonicalDirectSource, string, error)
	creators func(kaname.CanonicalSourceFilter) ([]kaname.CanonicalCreatorSource, string, error)
}

func (w structuralWriter) AuthorityFence() kaname.AuthorityFence { return bindingFence{at: w.at} }
func (w structuralWriter) CanonicalDirectSources(_ context.Context, f kaname.CanonicalSourceFilter) ([]kaname.CanonicalDirectSource, string, error) {
	return w.direct(f)
}
func (w structuralWriter) CanonicalCreatorSources(_ context.Context, f kaname.CanonicalSourceFilter) ([]kaname.CanonicalCreatorSource, string, error) {
	if w.creators == nil {
		return nil, "", nil
	}
	return w.creators(f)
}
func structuralFixture() structuralWriter {
	return structuralWriter{at: time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC), direct: func(kaname.CanonicalSourceFilter) ([]kaname.CanonicalDirectSource, string, error) {
		return []kaname.CanonicalDirectSource{{SourceKind: kaname.CanonicalAccountOwner, SourceID: "a", AccountID: "a", ObjectType: "account", ObjectID: "a", Relation: "owner", Recipient: sourceActor}}, "", nil
	}}
}
func TestStructuralSourcesRejectMalformedAndTypedImpostor(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*kaname.CanonicalDirectSource)
	}{
		{"unknown", func(s *kaname.CanonicalDirectSource) { s.SourceKind = "legacy_fact" }},
		{"missing", func(s *kaname.CanonicalDirectSource) { s.SourceID = "" }},
		{"same-id-sa", func(s *kaname.CanonicalDirectSource) { s.Recipient.Type = domain.SubjectTypeServiceAccount }},
		{"foreign-owner", func(s *kaname.CanonicalDirectSource) { s.Recipient.ID = "other" }},
		{"invented-condition", func(s *kaname.CanonicalDirectSource) { s.Condition.Name = "mfa" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := structuralFixture()
			original := w.direct
			w.direct = func(f kaname.CanonicalSourceFilter) ([]kaname.CanonicalDirectSource, string, error) {
				ss, n, e := original(f)
				tc.change(&ss[0])
				return ss, n, e
			}
			got, err := CollectStructuralSources(context.Background(), w, sourceActor)
			require.ErrorIs(t, err, kaname.ErrCanonicalSourceInvalid)
			require.Empty(t, got.Direct)
		})
	}
	w := structuralFixture()
	got, err := CollectStructuralSources(context.Background(), w, sourceActor)
	require.NoError(t, err)
	require.Len(t, got.Direct, 1)
}
func TestStructuralSourcesLastPageExpiryAndNoPartialSuccess(t *testing.T) {
	w := structuralFixture()
	calls := 0
	w.direct = func(f kaname.CanonicalSourceFilter) ([]kaname.CanonicalDirectSource, string, error) {
		calls++
		if f.After == "" {
			return nil, "last", nil
		}
		until := w.at.Add(time.Nanosecond)
		return []kaname.CanonicalDirectSource{{SourceKind: kaname.CanonicalClusterAdmin, SourceID: "grant", ObjectType: "cluster", ObjectID: domain.ClusterSingletonID, Relation: "system_admin", Recipient: sourceActor, ExpiresAt: &until}}, "", nil
	}
	got, err := CollectStructuralSources(context.Background(), w, sourceActor)
	require.NoError(t, err)
	require.Len(t, got.Direct, 1)
	require.Equal(t, 2, calls)
	original := w.direct
	w.direct = func(f kaname.CanonicalSourceFilter) ([]kaname.CanonicalDirectSource, string, error) {
		ss, n, e := original(f)
		if len(ss) > 0 {
			ss[0].ExpiresAt = &w.at
		}
		return ss, n, e
	}
	got, err = CollectStructuralSources(context.Background(), w, sourceActor)
	require.ErrorIs(t, err, kaname.ErrCanonicalSourceInvalid)
	require.Empty(t, got.Direct)
}
func TestStructuralSourcesBoundedPagesAndRepeatedCursor(t *testing.T) {
	for _, repeat := range []bool{false, true} {
		w := structuralFixture()
		n := 0
		w.direct = func(kaname.CanonicalSourceFilter) ([]kaname.CanonicalDirectSource, string, error) {
			n++
			next := fmt.Sprint(n)
			if repeat {
				next = "same"
			}
			return nil, next, nil
		}
		got, err := CollectStructuralSources(context.Background(), w, sourceActor)
		require.Error(t, err)
		require.Empty(t, got.Direct)
		require.LessOrEqual(t, n, maxStructuralSourcePages)
	}
}
func TestStructuralCreatorKeepsTypedIdentityAndIsNotDirect(t *testing.T) {
	w := structuralFixture()
	actor := domain.Subject{Type: domain.SubjectTypeServiceAccount, ID: "creator-a"}
	w.direct = func(kaname.CanonicalSourceFilter) ([]kaname.CanonicalDirectSource, string, error) {
		return nil, "", nil
	}
	w.creators = func(f kaname.CanonicalSourceFilter) ([]kaname.CanonicalCreatorSource, string, error) {
		require.Equal(t, actor, f.Actor)
		return []kaname.CanonicalCreatorSource{{SourceID: "sa", ObjectID: "sa", ObjectType: "iam_service_account", AccountID: "a", Creator: actor}}, "", nil
	}
	got, err := CollectStructuralSources(context.Background(), w, actor)
	require.NoError(t, err)
	require.Empty(t, got.Direct)
	require.Len(t, got.Creators, 1)
	original := w.creators
	w.creators = func(f kaname.CanonicalSourceFilter) ([]kaname.CanonicalCreatorSource, string, error) {
		ss, n, e := original(f)
		ss[0].Creator.ID = "creator-b"
		return ss, n, e
	}
	got, err = CollectStructuralSources(context.Background(), w, actor)
	require.Error(t, err)
	require.Empty(t, got.Creators)
}

func structuralCompiler(t *testing.T) *granteffect.Compiler {
	t.Helper()
	c, err := granteffect.New(`model
  schema 1.1
type user
type account
  relations
    define owner: [user]
    define v_get: owner
`, catalog.Halves{Live: catalog.Rows{Modules: []string{"iam"}, Resources: []catalog.ResourceRow{{Module: "iam", Resource: "account", ObjectType: "account"}}, Verbs: []catalog.VerbRow{{Module: "iam", Resource: "account", Verb: "get", PerObject: true}}}})
	require.NoError(t, err)
	return c
}

func TestStructuralCompileUsesRealCompilerAndPreservesObligations(t *testing.T) {
	c := structuralCompiler(t)
	got, err := CollectAndCompileStructuralSources(context.Background(), structuralFixture(), c, sourceActor)
	require.NoError(t, err)
	require.NotEmpty(t, got.Component.Effects())
	require.NotEmpty(t, got.Obligations)
	require.False(t, got.Component.Complete())
	proof := granteffect.Prove(got.Component, got.Component)
	require.Equal(t, grantcoverage.NotProved, proof.Status)
	require.Equal(t, grantcoverage.ReasonIncomplete, proof.Reason)
	neighbour := c.CompileDirect(granteffect.Direct{SourceID: "neighbour", ObjectType: "account", ObjectID: "a", Relation: "owner", Recipient: sourceActor})
	require.True(t, neighbour.Complete())
	require.False(t, granteffect.Union(neighbour, got.Component).Complete())
	for _, effect := range got.Component.Effects() {
		require.Equal(t, "account_owner:a", effect.Provenance.SourceID)
	}
}

func TestStructuralSourcesBoundedRowsWithoutPartialSuccess(t *testing.T) {
	w := structuralFixture()
	base, _, _ := w.direct(kaname.CanonicalSourceFilter{})
	pages := 0
	w.direct = func(kaname.CanonicalSourceFilter) ([]kaname.CanonicalDirectSource, string, error) {
		pages++
		rows := make([]kaname.CanonicalDirectSource, kaname.MaxCanonicalSourcePage)
		for i := range rows {
			rows[i] = base[0]
		}
		return rows, fmt.Sprint(pages), nil
	}
	got, err := CollectStructuralSources(context.Background(), w, sourceActor)
	require.ErrorIs(t, err, ErrStructuralSourceLimit)
	require.Empty(t, got.Direct)
	require.Equal(t, maxStructuralSourceRows/kaname.MaxCanonicalSourcePage+1, pages)
}

func TestStructuralCompileCancellationAfterCollectionReturnsZero(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := structuralFixture()
	w.creators = func(kaname.CanonicalSourceFilter) ([]kaname.CanonicalCreatorSource, string, error) {
		cancel()
		return nil, "", nil
	}
	got, err := CollectAndCompileStructuralSources(ctx, w, structuralCompiler(t), sourceActor)
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, StructuralEffects{}, got)
}

// Коллектор допускает больше строк, чем суммарный бюджет эффектов. Отказ
// компиляции обязан вернуть нулевой результат, включая уже собранные строки.
func TestStructuralCompileGlobalBudgetReturnsZero(t *testing.T) {
	w := structuralFixture()
	row, _, _ := w.direct(kaname.CanonicalSourceFilter{})
	remaining := granteffect.MaxEffects + 1
	w.direct = func(kaname.CanonicalSourceFilter) ([]kaname.CanonicalDirectSource, string, error) {
		n := kaname.MaxCanonicalSourcePage
		if remaining < n {
			n = remaining
		}
		rows := make([]kaname.CanonicalDirectSource, n)
		for i := range rows {
			rows[i] = row[0]
		}
		remaining -= n
		next := ""
		if remaining > 0 {
			next = fmt.Sprint(remaining)
		}
		return rows, next, nil
	}
	got, err := CollectAndCompileStructuralSources(context.Background(), w, structuralCompiler(t), sourceActor)
	require.True(t, errors.Is(err, ErrStructuralSourceLimit))
	require.ErrorIs(t, err, granteffect.ErrUnionLimit)
	require.Equal(t, 0, remaining)
	require.Equal(t, StructuralEffects{}, got)
}
