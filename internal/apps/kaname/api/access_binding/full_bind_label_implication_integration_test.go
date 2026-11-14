// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	accessbindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// Наблюдатель не меняет ответы и не заменяет проход: сигнал появляется
// только после возврата последнего настоящего прохода detached callback.
// Тип и ID берутся из публичного результата Create, а не из таймера тишины.
type fb11SetupCallbacks struct {
	mu   sync.Mutex
	done map[string]chan error
}

func (c *fb11SetupCallbacks) completion(objectType, objectID string) chan error {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := objectType + ":" + objectID
	if c.done == nil {
		c.done = make(map[string]chan error)
	}
	if c.done[key] == nil {
		c.done[key] = make(chan error, 1)
	}
	return c.done[key]
}

func (c *fb11SetupCallbacks) awaitSetup(ctx context.Context, objectType, objectID string) error {
	wait, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	select {
	case err := <-c.completion(objectType, objectID):
		return err
	case <-wait.Done():
		return wait.Err()
	}
}

type fb11SetupReconciler struct {
	accessbindingapp.SelectorReconciler
	callbacks *fb11SetupCallbacks
}

func (r *fb11SetupReconciler) ReconcileObjectForwardNoStale(ctx context.Context, objectType, objectID string) error {
	err := r.SelectorReconciler.ReconcileObjectForwardNoStale(ctx, objectType, objectID)
	r.callbacks.completion(objectType, objectID) <- err
	return err
}

func (r *fb11SetupReconciler) awaitSetup(ctx context.Context, objectType, objectID string) error {
	return r.callbacks.awaitSetup(ctx, objectType, objectID)
}

// FB11: настоящие IAM-direct объекты ролей получают метки через Role.Create.
// Обе половины используют аккаунт A/allInScope; меняется только селектор
// источника prod -> dev. Импликация проверяется отдельно от CreateBinding(A).
func TestFullBind_FB11_LabelImplicationCoversTheProposedRule(t *testing.T) {
	for _, allow := range []bool{true, false} {
		t.Run(map[bool]string{true: "broader_prod_source", false: "disjoint_dev_source"}[allow], func(t *testing.T) {
			callbacks := &fb11SetupCallbacks{}
			w := newFullBindWorld(t, func(actual *reconcile.Reconciler) accessbindingapp.SelectorReconciler {
				return &fb11SetupReconciler{SelectorReconciler: actual, callbacks: callbacks}
			})
			// Исходные помощники request/source/ordinary мира FB8 используют
			// проект P. Здесь область аккаунта задаётся явно, без их изменения.
			request := func(subject domain.UserID, role domain.RoleID) *iamv1.CreateAccessBindingRequest {
				return &iamv1.CreateAccessBindingRequest{
					Subjects: []*iamv1.Subject{userSubject(subject)}, RoleId: string(role),
					ScopeType: "iam.account", ScopeId: string(w.accA), Target: allInScopeTarget(),
				}
			}
			source := func(role domain.RoleID) {
				id := w.createDone(asUser(w.ctx, w.usrA), request(w.usrD, role), "FB11: account source")
				// Operation.done подтверждает запись, но не конец detached прохода.
				require.NoError(t, callbacks.awaitSetup(w.ctx, "iam.accessBinding", id))
				require.NoError(t, w.rec.ReconcileBinding(w.ctx, domain.AccessBindingID(id)))
			}
			// У iam.role живой глагол чтения — list; get снят из каталога.
			// Проверяем метки на настоящем v_list без оживления снятого права.
			probeRole := func(name, env string) domain.RoleID {
				labels := map[string]string{"env": env, "team": "a"}
				op, err := w.roles.Create(asUser(w.ctx, w.usrA), &iamv1.CreateRoleRequest{
					Name: name, Labels: labels,
					Rules:          []*iamv1.Rule{{Module: "iam", Resources: []string{"role"}, Verbs: []string{"list"}}},
					DefinitionTier: &iamv1.DefinitionTier{TierType: "iam.account", TierId: string(w.accA)},
				})
				require.NoError(t, err)
				require.NotNil(t, op)
				done := awaitOp(t, w.ctx, w.ops, op.GetId())
				require.Nil(t, done.Error, "FB11: actual labelled Role.Create")
				var md iamv1.CreateRoleMetadata
				require.NoError(t, op.GetMetadata().UnmarshalTo(&md))
				require.NotEmpty(t, md.GetRoleId())
				require.NoError(t, w.rec.ReconcileBinding(w.ctx, w.ownerBinding))
				rd, err := w.repo.Reader(w.ctx)
				require.NoError(t, err)
				defer func() { _ = rd.Rollback(w.ctx) }()
				role, err := rd.Roles().Get(w.ctx, domain.RoleID(md.GetRoleId()))
				require.NoError(t, err)
				require.Equal(t, w.accA, role.AccountID)
				require.Equal(t, domain.Labels{"env": domain.LabelVal(env), "team": "a"}, role.Labels)
				return role.ID
			}
			prod := probeRole("fb_label_probe_prod", "prod")
			dev := probeRole("fb_label_probe_dev", "dev")
			require.NotEqual(t, prod, dev)
			for _, user := range []domain.UserID{w.usrD, w.usrE} {
				w.native("user:"+string(user), "v_list", "iam_role", string(prod), relverdict.Deny)
				w.native("user:"+string(user), "v_list", "iam_role", string(dev), relverdict.Deny)
			}
			env := "dev"
			if allow {
				env = "prod"
			}
			sourceRule := &iamv1.Rule{Module: "iam", Resources: []string{"role"}, Verbs: []string{"list"}, MatchLabels: map[string]string{"env": env}}
			proposedRule := &iamv1.Rule{Module: "iam", Resources: []string{"role"}, Verbs: []string{"list"}, MatchLabels: map[string]string{"env": "prod", "team": "a"}}
			source(w.role("fb_label_source", sourceRule))
			osetr := w.role("fb_label_proposed", proposedRule)
			source(w.createCapabilityRole())
			// Все callback настройки уже вернулись после настоящих проходов.
			// Дополнительный проход владельца сохраняется до точного снимка;
			// идемпотентность графа сама по себе не доказывает тишину outbox.
			require.NoError(t, w.rec.ReconcileBinding(w.ctx, w.ownerBinding))
			w.native("user:"+string(w.usrD), "admin", "account", string(w.accA), relverdict.Deny)
			w.native("user:"+string(w.usrD), "admin", "project", string(w.prjA), relverdict.Deny)
			actorProd, actorDev := relverdict.Deny, relverdict.Allow
			if allow {
				actorProd, actorDev = relverdict.Allow, relverdict.Deny
			}
			w.native("user:"+string(w.usrD), "v_list", "iam_role", string(prod), actorProd)
			w.native("user:"+string(w.usrD), "v_list", "iam_role", string(dev), actorDev)

			// До исследуемого вызова операции настройки уже зафиксированы,
			// а объекты выдач доведены до материализации владельца.
			// Синхронный отказ не добавляет Operation или строки выдачи.
			artifacts := func() [6]int64 {
				var n [6]int64
				require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT
				 (SELECT count(*) FROM kaname.operations),
				 (SELECT count(*) FROM kaname.access_bindings),
				 (SELECT count(*) FROM kaname.access_binding_subjects),
				 (SELECT count(*) FROM kaname.access_binding_target_members),
				 (SELECT count(*) FROM kaname.access_binding_emitted_tuples),
				 (SELECT count(*) FROM kaname.fga_outbox)`).Scan(&n[0], &n[1], &n[2], &n[3], &n[4], &n[5]))
				return n
			}
			before := artifacts()
			require.Empty(t, w.listOf(w.usrE))
			op, err := w.ab.Create(asUser(w.ctx, w.usrD), request(w.usrE, osetr))
			if !allow {
				require.Nil(t, op, "FB11: denial precedes Operation")
				require.Error(t, err)
				require.Equal(t, codes.PermissionDenied, status.Code(err))
				require.Equal(t, "permission denied", status.Convert(err).Message())
				require.Equal(t, before, artifacts(), "FB11: denial adds no operation/grant artifacts")
				require.Empty(t, w.listOf(w.usrE))
			} else {
				require.NoError(t, err)
				require.NotNil(t, op)
				done := awaitOp(t, w.ctx, w.ops, op.GetId())
				require.Nil(t, done.Error, "FB11: accepted grant is durable")
				var md iamv1.CreateAccessBindingMetadata
				require.NoError(t, op.GetMetadata().UnmarshalTo(&md))
				require.NotEmpty(t, md.GetAccessBindingId())
				require.NoError(t, callbacks.awaitSetup(w.ctx, "iam.accessBinding", md.GetAccessBindingId()))
				rows := w.listOf(w.usrE)
				require.Len(t, rows, 1)
				require.Equal(t, md.GetAccessBindingId(), string(rows[0].ID))
				require.Equal(t, osetr, rows[0].RoleID)
				require.Equal(t, domain.SubjectTypeUser, rows[0].SubjectType)
				require.Equal(t, string(w.usrE), string(rows[0].SubjectID))
				require.Equal(t, "account", string(rows[0].ResourceType))
				require.Equal(t, string(w.accA), rows[0].ResourceID)
				require.Equal(t, domain.ScopeAccount, rows[0].Scope)
				require.Equal(t, domain.AccessBindingStatusActive, rows[0].Status)
				require.True(t, rows[0].Target.AllInScope)
				require.Empty(t, rows[0].Target.Resources)
				require.NoError(t, w.rec.ReconcileBinding(w.ctx, rows[0].ID))
			}
			want := relverdict.Deny
			if allow {
				want = relverdict.Allow
			}
			w.native("user:"+string(w.usrE), "v_list", "iam_role", string(prod), want)
			w.native("user:"+string(w.usrE), "v_list", "iam_role", string(dev), relverdict.Deny)
		})
	}
}
