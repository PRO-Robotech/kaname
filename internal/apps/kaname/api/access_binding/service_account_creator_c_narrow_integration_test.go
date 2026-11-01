// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// service_account_creator_c_narrow_integration_test.go — группа C приёмки
// `service-account-creation-is-its-own-right.md` (PRO-Robotech/kaname#1003):
// у создателя нет прав сверх учёток (SAC-20…SAC-22). Глаголы проекта, группы и
// роли судит ДВЕРЬ слушателя, поэтому вызов идёт только через дверь мира.

import (
	"context"
	"log/slog"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	operationpb "github.com/PRO-Robotech/corelib/api/corelib/operation"
	"github.com/PRO-Robotech/corelib/authz/catalogderive"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// sac20Row — строка SAC-20: вызов и его тело; правый столбец — тот же вызов от usr-A.
type sac20Row struct {
	name  string
	fresh bool // правый столбец — на свежем мире (вызов уничтожает объект)
	call  func(w *sacWorld, ctx context.Context) sacOp
}

func sac20Rows() []sac20Row {
	return []sac20Row{
		{"a — ProjectService.Create", false, func(w *sacWorld, ctx context.Context) sacOp {
			req := &iamv1.CreateProjectRequest{AccountId: string(w.accA), Name: "p-20a"}
			return w.mutate(ctx, sacMethodPrjCreate, req, func(ctx context.Context) (*operationpb.Operation, error) {
				return w.prjx.Create(ctx, req)
			})
		}},
		{"b — ProjectService.Update", false, func(w *sacWorld, ctx context.Context) sacOp {
			req := &iamv1.UpdateProjectRequest{ProjectId: string(w.prjA2),
				UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"labels"}}, Labels: map[string]string{"k": "v"}}
			return w.mutate(ctx, sacMethodPrjUpdate, req, func(ctx context.Context) (*operationpb.Operation, error) {
				return w.prjx.Update(ctx, req)
			})
		}},
		{"c — ProjectService.Delete", true, func(w *sacWorld, ctx context.Context) sacOp {
			req := &iamv1.DeleteProjectRequest{ProjectId: string(w.prjA2)}
			return w.mutate(ctx, sacMethodPrjDelete, req, func(ctx context.Context) (*operationpb.Operation, error) {
				return w.prjx.Delete(ctx, req)
			})
		}},
		{"d — GroupService.Create", false, func(w *sacWorld, ctx context.Context) sacOp {
			req := &iamv1.CreateGroupRequest{AccountId: string(w.accA), Name: "g-20d"}
			return w.mutate(ctx, sacMethodGrpCreate, req, func(ctx context.Context) (*operationpb.Operation, error) {
				return w.grpx.Create(ctx, req)
			})
		}},
		{"e — GroupService.Update", false, func(w *sacWorld, ctx context.Context) sacOp {
			req := &iamv1.UpdateGroupRequest{GroupId: w.grpA,
				UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"description"}}, Description: "d"}
			return w.mutate(ctx, sacMethodGrpUpdate, req, func(ctx context.Context) (*operationpb.Operation, error) {
				return w.grpx.Update(ctx, req)
			})
		}},
		{"f — GroupService.AddMember", false, func(w *sacWorld, ctx context.Context) sacOp {
			req := &iamv1.AddGroupMemberRequest{GroupId: w.grpA, MemberType: "service_account", MemberId: w.svaA}
			return w.mutate(ctx, sacMethodGrpAdd, req, func(ctx context.Context) (*operationpb.Operation, error) {
				return w.grpx.AddMember(ctx, req)
			})
		}},
		{"g — GroupService.Delete", true, func(w *sacWorld, ctx context.Context) sacOp {
			req := &iamv1.DeleteGroupRequest{GroupId: w.grpA}
			return w.mutate(ctx, sacMethodGrpDelete, req, func(ctx context.Context) (*operationpb.Operation, error) {
				return w.grpx.Delete(ctx, req)
			})
		}},
		// Имя роли — `r_20h`, а не `r-20h` тела приёмки: дефис в имени роли аккаунта
		// отвергает `roles_custom_name_check`, и близнец справа не дошёл бы до `done`.
		{"h — RoleService.Create", false, func(w *sacWorld, ctx context.Context) sacOp {
			req := &iamv1.CreateRoleRequest{AccountId: string(w.accA), Name: "r_20h",
				Rules: []*iamv1.Rule{{Module: "iam", Resources: []string{"project"}, Verbs: []string{"get"}}}}
			return w.mutate(ctx, sacMethodRolCreate, req, func(ctx context.Context) (*operationpb.Operation, error) {
				return w.rolex.Create(ctx, req)
			})
		}},
		{"i — RoleService.Update", false, func(w *sacWorld, ctx context.Context) sacOp {
			req := &iamv1.UpdateRoleRequest{RoleId: string(w.rolOwn),
				UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"description"}}, Description: "d"}
			return w.mutate(ctx, sacMethodRolUpdate, req, func(ctx context.Context) (*operationpb.Operation, error) {
				return w.rolex.Update(ctx, req)
			})
		}},
		{"j — RoleService.Delete", true, func(w *sacWorld, ctx context.Context) sacOp {
			req := &iamv1.DeleteRoleRequest{RoleId: string(w.rolOwn)}
			return w.mutate(ctx, sacMethodRolDelete, req, func(ctx context.Context) (*operationpb.Operation, error) {
				return w.rolex.Delete(ctx, req)
			})
		}},
	}
}

// sac20Census — перепись проектов, групп и ролей acc-A строками базы.
func (w *sacWorld) sac20Census() string {
	w.t.Helper()
	var out []string
	for _, q := range []string{
		`SELECT id || ':' || name || ':' || labels::text FROM kaname.projects WHERE account_id = $1`,
		`SELECT id || ':' || name || ':' || description FROM kaname.groups WHERE account_id = $1`,
		`SELECT g.id || ':' || count(m.*) FROM kaname.groups g LEFT JOIN kaname.group_members m ON m.group_id = g.id WHERE g.account_id = $1 GROUP BY g.id`,
		`SELECT id || ':' || name || ':' || description FROM kaname.roles WHERE account_id = $1`,
	} {
		rows, err := w.pool.Query(w.ctx, q, string(w.accA))
		require.NoError(w.t, err)
		for rows.Next() {
			var s string
			require.NoError(w.t, rows.Scan(&s))
			out = append(out, s)
		}
		rows.Close()
		require.NoError(w.t, rows.Err())
	}
	sort.Strings(out)
	return strings.Join(out, "\n")
}

// SAC-20 — создатель не трогает проекты, группы и роли.
func TestServiceAccountCreator_SAC20_CreatorDoesNotTouchProjectsGroupsRoles(t *testing.T) {
	w := newSACWorld(t)
	w.requireCreatorRole("SAC-20")
	w.grantC("SAC-20 Дано: G", w.svaIss)
	w.pollRelation("service_account:"+w.svaIss, sacCreatorRelation, "account:"+string(w.accA), true,
		"SAC-20 контроль: право создавать у sva-iss")

	before := w.sac20Census()
	for _, row := range sac20Rows() {
		o := row.call(w, asSA(w.ctx, w.svaIss))
		requireSACDenied(t, o, "SAC-20 "+row.name+": от sva-iss")
		require.Falsef(t, o.reached, "SAC-20 %s: обработчик достигнут — отказ не двери", row.name)
	}
	require.Equal(t, before, w.sac20Census(), "SAC-20: перепись проектов, групп, ролей acc-A до = после")

	// Правый столбец — близнец (отличается вызывающим). c, g, j — каждая на свежем мире.
	for _, row := range sac20Rows() {
		if row.fresh {
			continue
		}
		requireSACDone(t, row.call(w, asUser(w.ctx, w.usrA)), "SAC-20 "+row.name+" (близнец): от usr-A")
	}
	for _, row := range sac20Rows() {
		if !row.fresh {
			continue
		}
		t.Run(row.name+" (близнец, свежий мир)", func(t *testing.T) {
			fw := newSACWorld(t)
			requireSACDone(t, row.call(fw, asUser(fw.ctx, fw.usrA)), "SAC-20 "+row.name+" (близнец): от usr-A")
		})
	}
}

// SAC-21 — перепись: у создателя на аккаунте ровно одно право.
func TestServiceAccountCreator_SAC21_CensusCreatorHoldsExactlyOneAccountRight(t *testing.T) {
	w := newSACWorld(t)
	w.requireCreatorRole("SAC-21")
	w.grantC("SAC-21 Дано: G", w.svaIss)

	reg, err := seed.LoadPermissionRegistry(w.ctx, slog.New(slog.NewTextHandler(os.Stderr,
		&slog.HandlerOptions{Level: slog.LevelError})))
	require.NoError(t, err, "SAC-21: каталог прав")
	doorMap, err := catalogderive.Derive(authzguard.OwnDoorProtoPackages()...)
	require.NoError(t, err, "SAC-21: карта двери из аннотаций")

	type entry struct{ fqn, relation string }
	var account []entry
	for _, r := range reg.All() {
		if r.ScopeExtractor.ObjectType != "account" {
			continue
		}
		// Каталог — тот, что судит дверь: отношение записи совпадает с картой двери.
		de, ok := doorMap["/"+r.FQN]
		require.Truef(t, ok, "SAC-21: записи %s нет в карте двери", r.FQN)
		require.Equalf(t, r.RequiredRelation, de.Relation, "SAC-21: отношение %s в каталоге и в двери", r.FQN)
		account = append(account, entry{r.FQN, r.RequiredRelation})
	}
	t.Logf("SAC-21: записей с областью account прочитано %d", len(account))
	require.NotEmpty(t, account, "SAC-21: НЕ ВЫПОЛНИЛОСЬ — записей с областью account 0")

	asked := 0
	for _, subject := range []struct {
		ref  string
		twin bool
	}{{"service_account:" + w.svaIss, false}, {"user:" + string(w.usrA), true}} {
		var trueAt []string
		for _, e := range account {
			asked++
			if w.relation(subject.ref, e.relation, "account:"+string(w.accA)) {
				trueAt = append(trueAt, e.fqn)
			}
		}
		if subject.twin {
			require.Lenf(t, trueAt, len(account), "SAC-21 (близнец): usr-A — истина у каждой записи")
		} else {
			require.Equal(t, []string{"kaname.cloud.iam.v1.ServiceAccountService/Create"}, trueAt,
				"SAC-21: истина у sva-iss — ровно у ServiceAccountService/Create")
		}
		objects := []struct{ typ, id string }{
			{"project", string(w.prjA)}, {"iam_group", w.grpA}, {"iam_role", string(w.rolOwn)}, {sacSAModelType, w.svaA},
		}
		for _, o := range objects {
			for _, r := range []string{"viewer", "editor", "admin", "v_get", "v_list", "v_update", "v_delete"} {
				if !w.plans().Declares(o.typ, r) {
					continue
				}
				asked++
				if subject.twin {
					// Близнец: пообъектные права владельца на объекте, заведённом
					// глаголом в этом мире (rol-own), материализуются после коммита —
					// окно, которое закрывает опрос, а не барьер операции (ban #9).
					w.pollRelation(subject.ref, r, o.typ+":"+o.id, true, "SAC-21 (близнец)")
					continue
				}
				w.requireRelation(subject.ref, r, o.typ+":"+o.id, false, "SAC-21")
			}
		}
	}
	t.Logf("SAC-21: вопросов задано %d", asked)
	require.Positive(t, asked, "SAC-21: НЕ ВЫПОЛНИЛОСЬ — вопросов 0")
}

// SAC-22 — право создавать не даёт права выдавать.
func TestServiceAccountCreator_SAC22_CreationRightGivesNoGrantAuthority(t *testing.T) {
	w := newSACWorld(t)
	w.requireCreatorRole("SAC-22")
	_, cr1 := w.sac10("SAC-22")
	req := &iamv1.CreateAccessBindingRequest{
		Subjects:  []*iamv1.Subject{svaSubject(cr1)},
		RoleId:    string(w.rolView),
		ScopeType: "iam.account",
		ScopeId:   string(w.accA),
		Target:    allInScopeTarget(),
	}
	requireDenied(t, w.tryGrant(asSA(w.ctx, w.svaIss), req), "SAC-22 a: sva-iss выдаёт view учётке sva-cr1")
	require.Zero(t, w.bindingsOfSubject(cr1), "SAC-22 a: выдач с субъектом sva-cr1")
	requireGranted(t, w.tryGrant(asUser(w.ctx, w.usrA), req), "SAC-22 b (близнец): тот же запрос от usr-A")
}

// bindingsOfSubject — выдач с данным субъектом (строки набора субъектов).
func (w *sacWorld) bindingsOfSubject(id string) int {
	w.t.Helper()
	var n int
	require.NoError(w.t, w.pool.QueryRow(w.ctx,
		`SELECT count(*) FROM kaname.access_binding_subjects WHERE subject_id = $1`, id).Scan(&n))
	return n
}
