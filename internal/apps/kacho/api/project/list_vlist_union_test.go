// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// list_vlist_union_test.go — rbac-2026 P7 (D-6 / acceptance rbac-B-02).
//
// P7 makes ProjectService.List visibility the UNION of the principal's FGA
// `viewer`-set AND `v_list`-set on `project` (on top of the retained
// owner-via-parent-Account branch):
//
//	visible(project) = owned-via-account
//	                 ∪ ListObjects(subject, "viewer", "project")
//	                 ∪ ListObjects(subject, "v_list", "project")
//
// A grant of `iam.project.{get,list}` on the flat explicit model materializes
// ONLY `project:<id> # v_list/v_get @ subj` (object-only, no cascade into the
// project's resources, D-2). Before P7 the List filtered by `viewer` alone, so
// the project stayed invisible. P7 adds the v_list branch → the project shows
// up in the selector while a Check on a resource INSIDE it still DENIES.
//
// RED until ListProjectsUseCase unions viewer ∪ v_list.
package project

import (
	"context"
	stderrors "errors"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	repoproject "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/project"
)

// ───────────── relation-aware FGA stub ──────────────────────────────────────

type projUnionFGAStub struct {
	clients.RelationQueries
	idsBy map[string]map[string][]string // [relation][subject] = ids
	err   error
	calls map[string]int
}

func newProjUnionFGAStub() *projUnionFGAStub {
	return &projUnionFGAStub{
		idsBy: map[string]map[string][]string{},
		calls: map[string]int{},
	}
}

func (s *projUnionFGAStub) set(relation, subject string, ids []string) {
	if s.idsBy[relation] == nil {
		s.idsBy[relation] = map[string][]string{}
	}
	s.idsBy[relation][subject] = ids
}

func (s *projUnionFGAStub) ListObjects(ctx context.Context, subject, relation, objectType string,
	condCtx map[string]any, maxResults int) ([]string, error) {
	s.calls[relation]++
	if s.err != nil {
		return nil, s.err
	}
	if m := s.idsBy[relation]; m != nil {
		return m[subject], nil
	}
	return nil, nil
}

// P7-A — v_list-only grant (object-only, no viewer, non-owner) → project VISIBLE.
func TestListProjects_P7_VListOnlyGrant_ProjectVisible(t *testing.T) {
	repo := newListFakeRepo()
	seedAccount(repo, "acc-other", "usr-other") // usr-u1 does NOT own it
	seedProject(repo, "prj-a", "acc-other")
	seedProject(repo, "prj-b", "acc-other")

	fga := newProjUnionFGAStub()
	fga.set("v_list", "user:usr-u1", []string{"prj-a"}) // object-only grant
	fga.set("viewer", "user:usr-u1", nil)

	uc := NewListProjectsUseCase(repo).WithRelationStore(fga)

	out, _, err := uc.Execute(ctxAs("usr-u1"), repoproject.ListFilter{PageSize: 100})
	require.NoError(t, err)
	ids := projIDs(out)
	require.ElementsMatch(t, []string{"prj-a"}, ids,
		"v_list-only grant makes prj-a visible (see-without-contents, D-6/B-02); prj-b hidden")
	require.GreaterOrEqual(t, fga.calls["v_list"], 1,
		"P7 must query the v_list relation on project in addition to viewer")
}

// P7-B — viewer grant still surfaces the project (regression).
func TestListProjects_P7_ViewerGrant_StillVisible(t *testing.T) {
	repo := newListFakeRepo()
	seedAccount(repo, "acc-other", "usr-other")
	seedProject(repo, "prj-a", "acc-other")
	seedProject(repo, "prj-b", "acc-other")

	fga := newProjUnionFGAStub()
	fga.set("viewer", "user:usr-u1", []string{"prj-a"})
	fga.set("v_list", "user:usr-u1", nil)

	uc := NewListProjectsUseCase(repo).WithRelationStore(fga)

	out, _, err := uc.Execute(ctxAs("usr-u1"), repoproject.ListFilter{PageSize: 100})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"prj-a"}, projIDs(out),
		"viewer grant keeps the project visible (regression — viewer branch retained)")
}

// P7-C — UNION of owner ∪ viewer ∪ v_list, deduplicated.
func TestListProjects_P7_UnionDedup(t *testing.T) {
	repo := newListFakeRepo()
	seedAccount(repo, "acc-alice", "usr-alice") // alice OWNS this
	seedAccount(repo, "acc-bob", "usr-bob")
	seedProject(repo, "prj-alice-1", "acc-alice") // owned
	seedProject(repo, "prj-bob-1", "acc-bob")     // viewer grant
	seedProject(repo, "prj-bob-2", "acc-bob")     // v_list grant
	seedProject(repo, "prj-bob-3", "acc-bob")     // hidden

	fga := newProjUnionFGAStub()
	fga.set("viewer", "user:usr-alice", []string{"prj-bob-1", "prj-alice-1"}) // prj-alice-1 also owned → dedup
	fga.set("v_list", "user:usr-alice", []string{"prj-bob-2"})

	uc := NewListProjectsUseCase(repo).WithRelationStore(fga)

	out, _, err := uc.Execute(ctxAs("usr-alice"), repoproject.ListFilter{PageSize: 100})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"prj-alice-1", "prj-bob-1", "prj-bob-2"}, projIDs(out),
		"union owner ∪ viewer ∪ v_list, deduplicated; prj-bob-3 hidden")
}

// P7-D — no-leak: a project in none of the three sets stays hidden.
func TestListProjects_P7_Foreign_NoLeak(t *testing.T) {
	repo := newListFakeRepo()
	seedAccount(repo, "acc-other", "usr-other")
	seedProject(repo, "prj-a", "acc-other")
	seedProject(repo, "prj-foreign", "acc-other")

	fga := newProjUnionFGAStub()
	fga.set("v_list", "user:usr-u1", []string{"prj-a"})
	fga.set("viewer", "user:usr-u1", []string{"prj-a"})

	uc := NewListProjectsUseCase(repo).WithRelationStore(fga)

	out, _, err := uc.Execute(ctxAs("usr-u1"), repoproject.ListFilter{PageSize: 100})
	require.NoError(t, err)
	require.NotContains(t, projIDs(out), "prj-foreign",
		"project in neither owner/viewer/v_list set must stay hidden (no-leak)")
}

// P7-E — operator-SA system_viewer floor: resolves viewer on every project →
// sees ALL even with empty v_list.
func TestListProjects_P7_OperatorFloor_Unbroken(t *testing.T) {
	repo := newListFakeRepo()
	seedAccount(repo, "acc-1", "usr-u1")
	seedProject(repo, "prj-1", "acc-1")
	seedProject(repo, "prj-2", "acc-1")

	op := "sva-operator"
	fga := newProjUnionFGAStub()
	fga.set("viewer", "service_account:"+op, []string{"prj-1", "prj-2"})
	fga.set("v_list", "service_account:"+op, nil)

	uc := NewListProjectsUseCase(repo).WithRelationStore(fga)

	out, _, err := uc.Execute(ctxSAProj(op), repoproject.ListFilter{PageSize: 100})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"prj-1", "prj-2"}, projIDs(out),
		"operator system_viewer floor still sees ALL projects under the union")
}

// P7-F — fail-closed: FGA error on either relation → Unavailable.
func TestListProjects_P7_FGAUnavailable_FailClosed(t *testing.T) {
	repo := newListFakeRepo()
	seedAccount(repo, "acc-other", "usr-other")
	seedProject(repo, "prj-a", "acc-other")

	fga := newProjUnionFGAStub()
	fga.err = stderrors.New("openfga listObjects: status 503")

	uc := NewListProjectsUseCase(repo).WithRelationStore(fga)

	out, _, err := uc.Execute(ctxAs("usr-u1"), repoproject.ListFilter{PageSize: 100})
	require.Error(t, err)
	require.Empty(t, out)
	st, ok := status.FromError(err)
	require.True(t, ok, "want grpc status; got %v", err)
	require.Equal(t, codes.Unavailable, st.Code(),
		"FGA outage on either relation → UNAVAILABLE fail-closed (INV-7 under union)")
}

// projIDs / ctxSAProj — local helpers (the SEC-L test file owns the user ctx
// helper; add SA + id-extractor here to avoid touching existing files).
func projIDs(out []domain.Project) []string {
	ids := make([]string, 0, len(out))
	for _, p := range out {
		ids = append(ids, string(p.ID))
	}
	return ids
}

func ctxSAProj(said string) context.Context {
	return operations.WithPrincipal(context.Background(), operations.Principal{Type: "service_account", ID: said})
}
