// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

// Snapshot fixture не отвечает на permission-вопросы: только topology/ownership.
// Compilation настоящий, из допущенного canonical bundle, не allow callback.
type nativeSnapshotFixture struct {
	edges     map[nativeReadNode][]nativeReadNode
	owners    map[nativeReadNode]string
	failAfter string
	err       error
	calls     int
	cancel    context.CancelFunc
}

func (s *nativeSnapshotFixture) account(ctx context.Context, n nativeReadNode) (string, error) {
	return s.owners[n], ctx.Err()
}
func (s *nativeSnapshotFixture) parents(ctx context.Context, n, after nativeReadNode, limit int) ([]nativeReadNode, error) {
	s.calls++
	if s.cancel != nil {
		s.cancel()
		return nil, ctx.Err()
	}
	if s.err != nil && after.id == s.failAfter {
		return nil, s.err
	}
	rows := append([]nativeReadNode(nil), s.edges[n]...)
	sort.Slice(rows, func(i, j int) bool { return nativeNodeLess(rows[i], rows[j]) })
	var out []nativeReadNode
	for _, r := range rows {
		if nativeNodeLess(after, r) {
			out = append(out, r)
			if len(out) == limit {
				break
			}
		}
	}
	return out, ctx.Err()
}
func nativeBoundaryBundle(t *testing.T) *granteffect.Bundle {
	t.Helper()
	b, err := granteffect.NewBundle(context.Background(), authzmodel.DSL, catalog.Halves{Live: catalog.Rows{
		Modules: []string{"iam"}, Resources: []catalog.ResourceRow{{Module: "iam", Resource: "account", ObjectType: "account"}},
		Verbs: []catalog.VerbRow{{Module: "iam", Resource: "account", Verb: "get", PerObject: true}},
	}}, granteffect.ProjectorVersion)
	require.NoError(t, err)
	return b
}
func nativeBoundaryActor() domain.Subject {
	return domain.Subject{Type: domain.SubjectTypeUser, ID: "usr_native"}
}
func nativeBoundaryGraph() *nativeSnapshotFixture {
	role := nativeReadNode{"iam_role", "rol_native"}
	account := nativeReadNode{"account", "acc_native"}
	return &nativeSnapshotFixture{owners: map[nativeReadNode]string{role: "acc_native", account: "acc_native"}, edges: map[nativeReadNode][]nativeReadNode{role: {account}, account: {{"cluster", domain.ClusterSingletonID}}}}
}
func TestNativeReadBoundaryAbsenceHasScopeGuardAndNoForeignScope(t *testing.T) {
	b := nativeBoundaryBundle(t)
	q := newNativePolicyQuestions()
	actor := nativeBoundaryActor()
	require.NoError(t, q.add(actor, "viewer", "iam_role", "rol_native"))
	s := nativeBoundaryGraph()
	s.owners[nativeReadNode{"iam_role", "rol_foreign"}] = "acc_foreign"
	p, err := captureNativeReadBoundary(context.Background(), b, q, s, &nativeReadBudget{})
	require.NoError(t, err)
	require.False(t, p.global())
	require.Equal(t, []string{"*", "scope:acc_native"}, p.guardKeys())
	// В fixture вообще нет relation_fact: guard защищает отсутствие, не только
	// перечисленные существующие факты. Чужой объект не расширяет root closure.
	require.NoError(t, p.requireQuestion(b, "user:usr_native", "viewer", "iam_role:rol_native"))
	require.ErrorIs(t, p.requireQuestion(b, "service_account:usr_native", "viewer", "iam_role:rol_native"), kaname.ErrSourceUnconfirmed)
	require.ErrorIs(t, p.requireQuestion(b, "user:usr_native", "viewer", "iam_role:rol_foreign"), kaname.ErrSourceUnconfirmed)
	roots, err := q.ordered(context.Background())
	require.NoError(t, err)
	require.ErrorIs(t, p.requireScope(roots[0], nativeReadNode{"iam_role", "rol_foreign"}), kaname.ErrSourceUnconfirmed)
	require.ErrorIs(t, p.requireFactSlot(roots[0], nativeReadNode{"iam_role", "rol_native"}, "invented"), kaname.ErrSourceUnconfirmed)
	require.ErrorIs(t, p.requireQuestion(nativeBoundaryBundle(t), "user:usr_native", "viewer", "iam_role:rol_native"), kaname.ErrSourceUnconfirmed)
}
func TestNativeReadBoundaryLastPageAndLateErrorNeverPartial(t *testing.T) {
	b := nativeBoundaryBundle(t)
	q := newNativePolicyQuestions()
	require.NoError(t, q.add(nativeBoundaryActor(), "viewer", "iam_role", "rol_native"))
	s := nativeBoundaryGraph()
	root := nativeReadNode{"iam_role", "rol_native"}
	s.edges[root] = nil
	for i := 0; i < 257; i++ {
		n := nativeReadNode{"account", fmt.Sprintf("acc_%04d", i)}
		s.edges[root] = append(s.edges[root], n)
		s.owners[n] = n.id
	}
	p, err := captureNativeReadBoundary(context.Background(), b, q, s, &nativeReadBudget{})
	require.NoError(t, err)
	require.True(t, p.accounts["acc_0256"])
	require.True(t, p.global())
	require.Equal(t, []string{"*"}, p.guardKeys()) // fanout/account budget preselect GLOBAL.
	boom := errors.New("late page unavailable")
	s.err = boom
	s.failAfter = "acc_0255"
	p, err = captureNativeReadBoundary(context.Background(), b, q, s, &nativeReadBudget{})
	require.ErrorIs(t, err, boom)
	require.Nil(t, p)
}
func TestNativeReadBoundaryCancellationAndBudgetAreErrors(t *testing.T) {
	b := nativeBoundaryBundle(t)
	q := newNativePolicyQuestions()
	require.NoError(t, q.add(nativeBoundaryActor(), "viewer", "iam_role", "rol_native"))
	ctx, cancel := context.WithCancel(context.Background())
	s := nativeBoundaryGraph()
	s.cancel = cancel
	p, err := captureNativeReadBoundary(ctx, b, q, s, &nativeReadBudget{})
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, p)
	p, err = captureNativeReadBoundary(context.Background(), b, q, nativeBoundaryGraph(), &nativeReadBudget{rows: 100000})
	require.ErrorIs(t, err, kaname.ErrSourceReadLimit)
	require.Nil(t, p)
	budget := &nativeReadBudget{rows: 99999, reads: 4095}
	require.NoError(t, budget.charge(1, 1))
	require.ErrorIs(t, budget.charge(0, 1), kaname.ErrSourceReadLimit)
	require.ErrorIs(t, budget.charge(-1, 0), kaname.ErrSourceReadLimit)
}
func TestNativeReadQuestionsKeepScopeMetaAndIssuerDistinct(t *testing.T) {
	q := newNativePolicyQuestions()
	actor := nativeBoundaryActor()
	scope := domain.ScopeAnchor{Type: "account", ID: "acc_native"}
	require.NoError(t, q.binding(actor, scope, "rol_native"))
	issuer := domain.Subject{Type: domain.SubjectTypeServiceAccount, ID: "sva_issuer"}
	require.NoError(t, q.delegationIssuer(issuer, "acc_native"))
	roots, err := q.ordered(context.Background())
	require.NoError(t, err)
	require.Len(t, roots, 6)
	var scopeMeta, roleMeta, issuerAdmin bool
	for _, r := range roots {
		scopeMeta = scopeMeta || r.objectType == "iam_grant_scope"
		roleMeta = roleMeta || r.objectType == "iam_grant_role"
		issuerAdmin = issuerAdmin || (r.subject == "service_account:sva_issuer" && r.relation == "admin")
	}
	require.True(t, scopeMeta)
	require.True(t, roleMeta)
	require.True(t, issuerAdmin)
	require.NoError(t, q.binding(actor, scope, "rol_native"))
	again, err := q.ordered(context.Background())
	require.NoError(t, err)
	require.Equal(t, roots, again)
}
func TestNativeReadQuestionsRemovalAndRoleMethodDoNotBecomeD1(t *testing.T) {
	q := newNativePolicyQuestions()
	actor := nativeBoundaryActor()
	require.NoError(t, q.removal(actor, domain.AccessBinding{ID: "abn_native", ResourceType: "account", ResourceID: "acc_native"}))
	require.NoError(t, q.roleBase(actor, domain.Role{ID: "rol_native", AccountID: "acc_native"}, false))
	roots, err := q.ordered(context.Background())
	require.NoError(t, err)
	var remove, update bool
	for _, r := range roots {
		require.NotEqual(t, "iam_grant_scope", r.objectType)
		require.NotEqual(t, "iam_grant_role", r.objectType)
		remove = remove || r.relation == "v_delete"
		update = update || r.relation == "v_update"
	}
	require.True(t, remove)
	require.True(t, update)
}
func TestNativeKnownClassReadRejectsConditionsWritesAndUnknownTypes(t *testing.T) {
	n := nativeReadNode{"iam_access_binding", "abn_native"}
	require.False(t, nativeKnownClassRead(n, "v_get", "system_class:anonymous", "", nil))
	require.False(t, nativeKnownClassRead(n, "v_get", "system_class:anonymous", "", json.RawMessage(`null`)))
	for _, subject := range []string{"system_class:anonymous", "system_class:authenticated"} {
		for _, rel := range []string{"viewer", "v_get", "v_list"} {
			require.True(t, nativeKnownClassRead(n, rel, subject, "", json.RawMessage(`{}`)))
		}
	}
	require.False(t, nativeKnownClassRead(n, "v_update", "system_class:anonymous", "", json.RawMessage(`{}`)))
	require.False(t, nativeKnownClassRead(n, "v_get", "user:*", "", json.RawMessage(`{}`)))
	require.False(t, nativeKnownClassRead(n, "v_get", "system_class:unknown", "", json.RawMessage(`{}`)))
	require.False(t, nativeKnownClassRead(n, "v_get", "system_class:anonymous", "mfa_fresh", json.RawMessage(`{}`)))
	require.False(t, nativeKnownClassRead(n, "v_get", "system_class:anonymous", "", json.RawMessage(`{"unexpected":true}`)))
	require.False(t, nativeKnownClassRead(nativeReadNode{"module_unknown", "abn_native"}, "v_get", "system_class:anonymous", "", json.RawMessage(`{}`)))
}
func TestNativeReadBoundaryUnknownOwnershipRequiresGlobal(t *testing.T) {
	b := nativeBoundaryBundle(t)
	q := newNativePolicyQuestions()
	require.NoError(t, q.add(nativeBoundaryActor(), "viewer", "iam_role", "rol_native"))
	s := nativeBoundaryGraph()
	delete(s.owners, nativeReadNode{"iam_role", "rol_native"})
	p, err := captureNativeReadBoundary(context.Background(), b, q, s, &nativeReadBudget{})
	require.NoError(t, err)
	require.True(t, p.global())
	roots, err := q.ordered(context.Background())
	require.NoError(t, err)
	require.ErrorIs(t, p.requireScope(roots[0], nativeReadNode{"iam_role", "rol_native"}), kaname.ErrSourceUnconfirmed)
}

func TestNativeRoleReferencesUseBothCanonicalVisibilityQuestions(t *testing.T) {
	q := newNativePolicyQuestions()
	actor := nativeBoundaryActor()
	role := domain.Role{ID: "rol_native", AccountID: "acc_native", Rules: domain.Rules{{Module: "iam", Resources: []string{"role"}, Verbs: []string{"bind"}, ResourceNames: []string{"rol_reference"}}}}
	require.NoError(t, q.roleBase(actor, role, true))
	roots, err := q.ordered(context.Background())
	require.NoError(t, err)
	var editor, viewer, list bool
	for _, r := range roots {
		if r.objectType == "iam_role" && r.objectID == "rol_reference" {
			viewer = viewer || r.relation == "viewer"
			list = list || r.relation == "v_list"
			require.NotEqual(t, "v_get", r.relation)
		}
		editor = editor || (r.objectType == "account" && r.relation == "editor")
	}
	require.True(t, editor)
	require.True(t, viewer)
	require.True(t, list)
}
func TestNativePopulationQuestionsRetainLastCarrierAndInvalidInput(t *testing.T) {
	q := newNativePolicyQuestions()
	actor := nativeBoundaryActor()
	require.NoError(t, q.groupBase(actor, domain.Group{ID: "grp_native", AccountID: "acc_native"}))
	for i := 0; i < 257; i++ {
		require.NoError(t, q.groupCarrier(actor, domain.AccessBinding{ID: domain.AccessBindingID(fmt.Sprintf("abn_%04d", i)), RoleID: "rol_native", ResourceType: "account", ResourceID: fmt.Sprintf("acc_%04d", i)}))
	}
	roots, err := q.ordered(context.Background())
	require.NoError(t, err)
	var last bool
	for _, r := range roots {
		last = last || (r.objectType == "account" && r.objectID == "acc_0256" && r.relation == "admin")
	}
	require.True(t, last)
	require.Error(t, q.add(actor, "v_get", "iam_role", "rol_native:extra"))
	require.Error(t, q.add(domain.Subject{Type: domain.SubjectTypeUser, ID: "*"}, "v_get", "iam_role", "rol_native"))
	require.Error(t, q.add(actor, "v_get", "iam_role", string([]byte{0xff})))
	require.Error(t, q.add(actor, "v_get", "iam_role", "bad\x01"))
}

// Эта проба отменяет контекст после успешного Scan последнего epoch-запроса,
// когда topology discovery уже завершился. Она не подменяет проверку полномочий.
type nativeFinalEpochTx struct {
	pgx.Tx
	cancel       context.CancelFunc
	epochScanned bool
}

type nativeFinalEpochRow func(...any) error

func (r nativeFinalEpochRow) Scan(dst ...any) error { return r(dst...) }

type nativeEmptyParentRows struct{ pgx.Rows }

func (nativeEmptyParentRows) Next() bool { return false }
func (nativeEmptyParentRows) Close()     {}
func (nativeEmptyParentRows) Err() error { return nil }

func (tx *nativeFinalEpochTx) Query(_ context.Context, query string, _ ...any) (pgx.Rows, error) {
	if !strings.Contains(query, "FROM kaname.resource_scope_edge") {
		return nil, fmt.Errorf("unexpected topology query: %s", query)
	}
	return nativeEmptyParentRows{}, nil
}

func (tx *nativeFinalEpochTx) QueryRow(_ context.Context, query string, _ ...any) pgx.Row {
	return nativeFinalEpochRow(func(dst ...any) error {
		switch {
		case strings.Contains(query, "transaction_isolation"):
			*dst[0].(*string) = "repeatable read"
		case strings.Contains(query, "authority_policy_object_account"):
			*dst[0].(*string) = "acc_native"
		case strings.Contains(query, "authority_policy_epoch_read"):
			*dst[0].(*json.RawMessage) = json.RawMessage(`{"*":[1,1],"scope:acc_native":[1,1]}`)
			tx.epochScanned = true
			if tx.cancel != nil {
				tx.cancel()
			}
		default:
			return fmt.Errorf("unexpected snapshot query: %s", query)
		}
		return nil
	})
}

func TestDiscoverNativeReadBoundaryCancellationAfterFinalEpochScan(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		t.Run(fmt.Sprintf("cancel=%t", canceled), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			tx := &nativeFinalEpochTx{}
			if canceled {
				tx.cancel = cancel
			}
			q := newNativePolicyQuestions()
			require.NoError(t, q.add(nativeBoundaryActor(), "viewer", "iam_role", "rol_native"))
			boundary, err := discoverNativeReadBoundary(ctx, tx, nativeBoundaryBundle(t), q, &nativeReadBudget{})
			require.True(t, tx.epochScanned)
			if canceled {
				require.ErrorIs(t, err, context.Canceled)
				require.Nil(t, boundary)
			} else {
				require.NoError(t, err)
				require.NotNil(t, boundary)
				require.JSONEq(t, `{"*":[1,1],"scope:acc_native":[1,1]}`, string(boundary.epochs))
			}
		})
	}
}
