// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// grant_delegation_cd_bounds_integration_test.go — группы C и D приёмки
// делегированных выдач (PRO-Robotech/kaname#986): не шире прав делегирующего
// (GD-20…GD-22) и без прав на проект, группу, роль, учётку (GD-25, GD-26).
//
// Глаголы проекта, группы, роли и учётки решает ДВЕРЬ слушателя (аннотации
// `editor` и `v_update`, §0.8 приёмки), а не use-case. Поэтому GD-25 идёт через
// дверь, собранную тем же конструктором, что в корне службы
// (`authzguard.NewOwnDoor`), над настоящей дверью решения мира: проба, зовущая
// use-case мимо двери, судила бы путь, которого у вызывающего нет.

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	operationpb "github.com/PRO-Robotech/corelib/api/corelib/operation"

	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// ownDoor — дверь слушателя над дверью решения мира, с журналом вопросов.
func (w *gdWorld) ownDoor() (grpc.UnaryServerInterceptor, *gdQuestionLog) {
	w.t.Helper()
	q := &gdQuestionLog{inner: w.door}
	door, err := authzguard.NewOwnDoor(authzguard.OwnDoorOptions{SelfCheck: q})
	require.NoError(w.t, err, "дверь слушателя не собралась")
	return door.Unary(), q
}

// viaDoor — вызов мутации через дверь слушателя; отдаёт операцию либо отказ
// (двери или обработчика) и признак, достигнут ли обработчик.
func (w *gdWorld) viaDoor(ctx context.Context, fullMethod string, req any,
	call func(ctx context.Context) (*operationpb.Operation, error)) (*operationpb.Operation, bool, error) {
	w.t.Helper()
	door, _ := w.ownDoor()
	reached := false
	out, err := door(ctx, req, &grpc.UnaryServerInfo{FullMethod: fullMethod},
		func(ctx context.Context, _ any) (any, error) {
			reached = true
			return call(ctx)
		})
	if err != nil {
		return nil, reached, err
	}
	op, ok := out.(*operationpb.Operation)
	require.Truef(w.t, ok, "%s: ответ не Operation (%T)", fullMethod, out)
	return op, reached, nil
}

// requireOpDone — операция `done` без ошибки.
func (w *gdWorld) requireOpDone(op *operationpb.Operation, err error, why string) {
	w.t.Helper()
	require.NoErrorf(w.t, err, "%s: отказ", why)
	done := awaitOp(w.t, w.ctx, w.ops, op.GetId())
	require.Nilf(w.t, done.Error, "%s: операция завершилась ошибкой %+v", why, done.Error)
}

// GD-20 — делегирующий потерял право — делегат больше не выдаёт.
func TestGrantDelegation_GD20_DelegatorLostAuthorityDelegateNoLongerGrants(t *testing.T) {
	w := newGDWorld(t)
	w.requireSubject("GD-20")
	dE := w.createDelegation(asUser(w.ctx, w.usrE), w.delegationBody(w.accA, w.svaIss2,
		[]domain.RoleID{w.rolPuller, w.rolPusher, w.rolRegAdmin},
		[]string{"registry.registries", "registry.repositories"},
		[]string{"SUBJECT_TYPE_SERVICE_ACCOUNT", "SUBJECT_TYPE_SYSTEM_CLASS"}), "GD-20 Дано: D-E от usr-E")
	w.d1()
	bE := requireGranted(t, w.tryGrant(asSA(w.ctx, w.svaIss2), w.v()), "GD-20 Дано: B-E (V от sva-iss2)")

	op, err := w.revokeBinding(asUser(w.ctx, w.usrA), w.grantE)
	w.requireOpDone(op, err, "GD-20: usr-A отзывает admin человеку usr-E")
	w.pollRelation("user:"+string(w.usrE), "admin", "account:"+string(w.accA), false,
		"GD-20: usr-E больше не держит admin на acc-A")

	puller := w.vWith(func(r *iamv1.CreateAccessBindingRequest) {
		r.RoleId, r.Subjects = string(w.rolPuller), []*iamv1.Subject{svaSubject(w.svaA2)}
	})
	requireDenied(t, w.tryGrant(asSA(w.ctx, w.svaIss2), puller), "GD-20 a: делегат usr-E")
	requireGranted(t, w.tryGrant(asSA(w.ctx, w.svaIss), puller), "GD-20 b (близнец): делегат владельца")

	assert.Equal(t, iamv1.AccessBinding_ACTIVE, w.getBinding(bE).GetStatus(), "GD-20: B-E осталась (Д3)")
	got, gerr := w.getDelegation(asUser(w.ctx, w.usrA), dE)
	require.NoError(t, gerr)
	assert.Equal(t, "ACTIVE", got["status"], "GD-20: D-E действует")
}

// revokeBinding — `AccessBindingService.Revoke` как есть.
func (w *gdWorld) revokeBinding(ctx context.Context, id string) (*operationpb.Operation, error) {
	return w.abx.Revoke(ctx, &iamv1.RevokeAccessBindingRequest{AccessBindingId: id})
}

// GD-21 — делегат не делегирует дальше.
func TestGrantDelegation_GD21_DelegateDoesNotDelegateFurther(t *testing.T) {
	w := newGDWorld(t)
	w.requireSubject("GD-21")
	w.d1()
	body := w.delegationBody(w.accA, w.svaOther, []domain.RoleID{w.rolPuller},
		[]string{"registry.registries"}, []string{"SUBJECT_TYPE_SERVICE_ACCOUNT"})

	o := w.gdMutate(asSA(w.ctx, w.svaIss), "Create", body)
	require.Empty(t, o.opID, "GD-21 a: синхронного отказа нет, заведена операция")
	requireRefusal(t, o.syncErr, codes.PermissionDenied, "permission denied", "GD-21 a")
	assert.Zero(t, w.activeDelegationsOfPair(w.accA, w.svaOther), "GD-21 a: делегирований sva-other")

	w.createDelegation(asUser(w.ctx, w.usrA), body, "GD-21 b (близнец): тот же запрос от usr-A")
}

// GD-22 — делегат не правит выдачу.
func TestGrantDelegation_GD22_DelegateDoesNotUpdateAGrant(t *testing.T) {
	w := newGDWorld(t)
	w.requireSubject("GD-22")
	w.d1()
	b10 := requireGranted(t, w.tryGrant(asSA(w.ctx, w.svaIss), w.v()), "GD-22 Дано: B10")
	update := func(ctx context.Context) (*operationpb.Operation, error) {
		return w.abx.Update(ctx, &iamv1.UpdateAccessBindingRequest{
			AccessBindingId: b10,
			UpdateMask:      &fieldmaskpb.FieldMask{Paths: []string{"labels"}},
			Labels:          map[string]string{"k": "v"},
		})
	}
	op, err := update(asSA(w.ctx, w.svaIss))
	require.Nilf(t, op, "GD-22 a: синхронного отказа нет, заведена операция")
	requireRefusal(t, err, codes.PermissionDenied, "permission denied", "GD-22 a")
	assert.Empty(t, w.getBinding(b10).GetLabels(), "GD-22 a: метки B10 прежние")

	op, err = update(asUser(w.ctx, w.usrA))
	w.requireOpDone(op, err, "GD-22 b (близнец): usr-A")
	assert.Equal(t, map[string]string{"k": "v"}, w.getBinding(b10).GetLabels(), "GD-22 b: метки")
}

// gd25Row — строка GD-25: глагол через дверь.
type gd25Row struct {
	name string
	run  func(w *gdWorld, ctx context.Context) (*operationpb.Operation, bool, error)
}

// gd25Rows — семь строк GD-25 (a…g).
func gd25Rows() []gd25Row {
	const svc = "/kaname.cloud.iam.v1."
	return []gd25Row{
		{"a ProjectService.Create", func(w *gdWorld, ctx context.Context) (*operationpb.Operation, bool, error) {
			req := &iamv1.CreateProjectRequest{AccountId: string(w.accA), Name: "gd25-prj", Description: "GD-25"}
			return w.viaDoor(ctx, svc+"ProjectService/Create", req, func(ctx context.Context) (*operationpb.Operation, error) {
				return w.projects.Create(ctx, req)
			})
		}},
		{"b ProjectService.Update", func(w *gdWorld, ctx context.Context) (*operationpb.Operation, bool, error) {
			req := &iamv1.UpdateProjectRequest{ProjectId: string(w.prjA2),
				UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"labels"}}, Labels: map[string]string{"k": "v"}}
			return w.viaDoor(ctx, svc+"ProjectService/Update", req, func(ctx context.Context) (*operationpb.Operation, error) {
				return w.projects.Update(ctx, req)
			})
		}},
		{"c ProjectService.Delete", func(w *gdWorld, ctx context.Context) (*operationpb.Operation, bool, error) {
			req := &iamv1.DeleteProjectRequest{ProjectId: string(w.prjA2)}
			return w.viaDoor(ctx, svc+"ProjectService/Delete", req, func(ctx context.Context) (*operationpb.Operation, error) {
				return w.projects.Delete(ctx, req)
			})
		}},
		{"d GroupService.Create", func(w *gdWorld, ctx context.Context) (*operationpb.Operation, bool, error) {
			req := &iamv1.CreateGroupRequest{AccountId: string(w.accA), Name: "gd25-grp", Description: "GD-25"}
			return w.viaDoor(ctx, svc+"GroupService/Create", req, func(ctx context.Context) (*operationpb.Operation, error) {
				return w.groups.Create(ctx, req)
			})
		}},
		{"e GroupService.AddMember", func(w *gdWorld, ctx context.Context) (*operationpb.Operation, bool, error) {
			req := &iamv1.AddGroupMemberRequest{GroupId: w.grpA, MemberType: "user", MemberId: string(w.usrB)}
			return w.viaDoor(ctx, svc+"GroupService/AddMember", req, func(ctx context.Context) (*operationpb.Operation, error) {
				return w.groups.AddMember(ctx, req)
			})
		}},
		{"f RoleService.Create", func(w *gdWorld, ctx context.Context) (*operationpb.Operation, bool, error) {
			req := &iamv1.CreateRoleRequest{AccountId: string(w.accA), Name: "gd25_role", Description: "GD-25",
				Rules: []*iamv1.Rule{{Module: "iam", Resources: []string{"project"}, Verbs: []string{"get"}}}}
			return w.viaDoor(ctx, svc+"RoleService/Create", req, func(ctx context.Context) (*operationpb.Operation, error) {
				return w.roles.Create(ctx, req)
			})
		}},
		{"g ServiceAccountService.Create", func(w *gdWorld, ctx context.Context) (*operationpb.Operation, bool, error) {
			req := &iamv1.CreateServiceAccountRequest{AccountId: string(w.accA), Name: "gd25-sva", Description: "GD-25"}
			return w.viaDoor(ctx, svc+"ServiceAccountService/Create", req, func(ctx context.Context) (*operationpb.Operation, error) {
				return w.sas.Create(ctx, req)
			})
		}},
	}
}

// accountCensus — перепись проектов, групп, ролей и учёток acc-A (с метками
// проектов: правка без нового объекта тоже изменение).
func (w *gdWorld) accountCensus() string {
	w.t.Helper()
	var out string
	for _, q := range []string{
		`SELECT count(*)::text || '|' || coalesce(string_agg(id || ':' || labels::text, ',' ORDER BY id), '') FROM kaname.projects WHERE account_id = $1`,
		`SELECT count(*)::text FROM kaname.groups WHERE account_id = $1`,
		`SELECT count(*)::text FROM kaname.roles WHERE account_id = $1`,
		`SELECT count(*)::text FROM kaname.service_accounts WHERE account_id = $1`,
		`SELECT count(*)::text FROM kaname.group_members WHERE group_id IN (SELECT id FROM kaname.groups WHERE account_id = $1)`,
	} {
		var s string
		require.NoErrorf(w.t, w.pool.QueryRow(w.ctx, q, string(w.accA)).Scan(&s), "перепись acc-A: %s", q)
		out += s + ";"
	}
	return out
}

// GD-25 — делегат не трогает проекты, группы, роли и учётки; правый столбец —
// близнец (отличается вызывающим); строки b и c от usr-A — каждая на свежем мире.
func TestGrantDelegation_GD25_DelegateDoesNotTouchProjectsGroupsRolesAccounts(t *testing.T) {
	rows := gd25Rows()
	// Близнецы — до испытуемого: их предмет — дверь и глаголы сегодняшнего
	// ствола, и сломанная дверь мира краснеет здесь, а не за отсутствием
	// делегирования.
	for _, r := range rows {
		if r.name[0] != 'b' && r.name[0] != 'c' {
			continue
		}
		t.Run("близнец "+r.name, func(t *testing.T) {
			w := newGDWorld(t)
			op, reached, err := r.run(w, asUser(w.ctx, w.usrA))
			require.Truef(t, reached, "GD-25 близнец %s: дверь не пропустила владельца (%v)", r.name, err)
			w.requireOpDone(op, err, "GD-25 близнец "+r.name)
		})
	}

	w := newGDWorld(t)
	for _, r := range rows {
		if r.name[0] == 'b' || r.name[0] == 'c' {
			continue
		}
		op, reached, err := r.run(w, asUser(w.ctx, w.usrA))
		require.Truef(t, reached, "GD-25 близнец %s: дверь не пропустила владельца (%v)", r.name, err)
		w.requireOpDone(op, err, "GD-25 близнец "+r.name)
	}

	w.requireSubject("GD-25")
	w.d1()
	for _, r := range rows {
		before := w.accountCensus()
		op, _, err := r.run(w, asSA(w.ctx, w.svaIss))
		require.Nilf(t, op, "GD-25 %s: делегат получил операцию", r.name)
		requireDoorOrHandlerDenial(t, err, "GD-25 "+r.name)
		assert.Equalf(t, before, w.accountCensus(), "GD-25 %s: объекты acc-A изменились", r.name)
	}
}

// requireDoorOrHandlerDenial — отказ в праве (`PERMISSION_DENIED`) от двери
// либо обработчика. Скрытие существования у двери — тот же код.
func requireDoorOrHandlerDenial(t *testing.T, err error, why string) {
	t.Helper()
	require.Errorf(t, err, "%s: отказа нет", why)
	st := status.Convert(err)
	require.Equalf(t, codes.PermissionDenied, st.Code(), "%s: код (текст %q)", why, st.Message())
}

// GD-26 — делегирование не даёт отношений модели прав.
func TestGrantDelegation_GD26_DelegationGivesNoModelRelations(t *testing.T) {
	w := newGDWorld(t)
	// Близнец — до испытуемого: usr-E держит admin на acc-A.
	w.requireRelation("user:"+string(w.usrE), "admin", "account:"+string(w.accA), true, "GD-26 близнец: usr-E")

	w.requireSubject("GD-26")
	w.d1()
	for _, rel := range []string{"admin", "editor", "viewer", "v_get"} {
		for _, obj := range []string{"account:" + string(w.accA), "project:" + string(w.prjA)} {
			w.requireRelation("service_account:"+w.svaIss, rel, obj, false, fmt.Sprintf("GD-26: %s на %s", rel, obj))
		}
	}
}
