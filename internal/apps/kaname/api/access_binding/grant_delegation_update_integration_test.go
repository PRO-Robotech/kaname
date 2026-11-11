// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package access_binding_test

// Приёмка kaname#1032 SHA256 daad435d16de8f5a23f38f6b8cc3d7a4a9bb12202457b078b89e6d8b3b686b7b.
// Никакая функция не заканчивается пробой дескриптора: за ней настоящий When/Then.
import (
	"context"
	"fmt"
	"testing"

	operationpb "github.com/PRO-Robotech/corelib/api/corelib/operation"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func TestGrantDelegation_GDU01_SingleAxisEffectiveAccess(t *testing.T) {
	for _, axis := range []string{"role", "target", "subject"} {
		t.Run(axis, func(t *testing.T) {
			u := newGDUWorld(t, false)
			u.effect(axis, false)
			req := u.grant(axis, true)
			requireDenied(t, u.tryGrant(asSA(u.ctx, u.svaIss), req), "до PATCH только новая ось запрещена")
			u.invariant(true)
			u.subject()
			key := map[string]string{"role": "roleIds", "target": "targetTypes", "subject": "subjectTypes"}[axis]
			before := u.get()
			u.patch(key, map[string]any{key: u.all()[key]})
			for _, k := range []string{"roleIds", "targetTypes", "subjectTypes"} {
				if k != key {
					require.Equal(t, before[k], u.get()[k])
				}
			}
			u.effect(axis, false)
			require.Equal(t, 1, u.countDelegated(u.d))
			u.expandedGrant(axis)
		})
	}
}
func TestGrantDelegation_GDU02_AllAxesAtomic(t *testing.T) {
	for _, absent := range []string{"none", "roleIds", "targetTypes", "subjectTypes"} {
		t.Run(absent, func(t *testing.T) {
			u := newGDUWorld(t, false)
			u.effect("all", false)
			u.subject()
			axes := u.all()
			if absent != "none" {
				axes[absent] = u.currentAxes()[absent]
			}
			u.patch("roleIds,targetTypes,subjectTypes", axes)
			u.axes(axes)
			u.effect("all", false)
			if absent != "none" {
				requireDenied(t, u.tryGrant(asSA(u.ctx, u.svaIss), u.grant("all", true)), "отсутствует ровно "+absent)
				u.patch(absent, map[string]any{absent: u.all()[absent]})
			}
			u.effect("all", false)
			u.expandedGrant("all")
		})
	}
}
func TestGrantDelegation_GDU03_NarrowingRejected(t *testing.T) {
	for _, name := range []string{"role", "target", "subject", "replace_role", "atomic_two_axes", "all_first_role", "two_first_target"} {
		t.Run(name, func(t *testing.T) {
			u := newGDUWorld(t, false)
			u.subject()
			u.patch("", u.all())
			bad := map[string]any{}
			good := map[string]any{}
			mask, field := "roleIds", "role_ids"
			switch name {
			case "role":
				bad[mask] = []string{string(u.rolPusher)}
				good[mask] = u.all()[mask]
			case "target":
				mask, field = "targetTypes", "target_types"
				bad[mask] = []string{gdRepoTgt}
				good[mask] = u.all()[mask]
			case "subject":
				mask, field = "subjectTypes", "subject_types"
				bad[mask] = []string{gduGroup}
				good[mask] = u.all()[mask]
			case "replace_role":
				bad[mask] = []string{string(u.rolPusher), string(u.rolRegAdmin)}
				good[mask] = []string{string(u.rolPuller), string(u.rolPusher), string(u.rolRegAdmin)}
			case "atomic_two_axes":
				mask, field = "roleIds,subjectTypes", "subject_types"
				bad["roleIds"] = []string{string(u.rolPuller), string(u.rolPusher), string(u.rolRegAdmin)}
				bad["subjectTypes"] = []string{gduGroup}
				good["roleIds"] = bad["roleIds"]
				good["subjectTypes"] = u.all()["subjectTypes"]
			case "all_first_role":
				mask = "roleIds,targetTypes,subjectTypes"
				bad = map[string]any{"roleIds": []string{string(u.rolPusher)}, "targetTypes": []string{gdRepoTgt}, "subjectTypes": []string{gduGroup}}
				good = u.all()
			case "two_first_target":
				mask, field = "targetTypes,subjectTypes", "target_types"
				bad = map[string]any{"targetTypes": []string{gdRepoTgt}, "subjectTypes": []string{gduGroup}}
				good = map[string]any{"targetTypes": u.all()["targetTypes"], "subjectTypes": u.all()["subjectTypes"]}
			}
			u.refuse(asUser(u.ctx, u.usrA), gduMask(mask), bad, codes.FailedPrecondition, gduNarrow(u.d, field), "")
			u.patch(mask, good)
		})
	}
}
func TestGrantDelegation_GDU04_EmptySelectedAxisRejected(t *testing.T) {
	for _, axis := range []string{"roleIds", "targetTypes", "subjectTypes"} {
		for _, mode := range []string{"absent", "null", "empty", "nil_mask", "empty_mask"} {
			t.Run(axis+"/"+mode, func(t *testing.T) {
				u := newGDUWorld(t, false)
				u.subject()
				good := u.currentAxes()
				bad := map[string]any{}
				mask := gduMask(axis)
				switch mode {
				case "null":
					bad[axis] = nil
				case "empty":
					bad[axis] = []string{}
				case "nil_mask", "empty_mask":
					for k, v := range good {
						if k != axis {
							bad[k] = v
						}
					}
					if mode == "nil_mask" {
						mask = nil
					} else {
						mask = gduMask("")
					}
				}
				field := map[string]string{"roleIds": "role_ids", "targetTypes": "target_types", "subjectTypes": "subject_types"}[axis]
				u.refuse(asUser(u.ctx, u.usrA), mask, bad, codes.InvalidArgument, field+": required", field)
				bad[axis] = good[axis]
				u.success(asUser(u.ctx, u.usrA), mask, bad)
			})
		}
	}
	t.Run("no_mask_no_axes", func(t *testing.T) {
		u := newGDUWorld(t, false)
		u.subject()
		u.refuse(asUser(u.ctx, u.usrA), nil, nil, codes.InvalidArgument, "role_ids: required", "role_ids")
		u.success(asUser(u.ctx, u.usrA), nil, u.currentAxes())
		u.success(asUser(u.ctx, u.usrA), nil, u.all())
	})
}
func TestGrantDelegation_GDU05_SetsBoundsAndNoop(t *testing.T) {
	t.Run("permutation_and_duplicates", func(t *testing.T) {
		u := newGDUWorld(t, false)
		u.subject()
		axes := u.all()
		axes["roleIds"] = []string{string(u.rolRegAdmin), string(u.rolPuller), string(u.rolPusher)}
		axes["subjectTypes"] = []string{gduUser, gduSA, gduGroup}
		u.patch("", axes)
		n := len(u.audit())
		axes["roleIds"] = []string{string(u.rolPusher), string(u.rolRegAdmin), string(u.rolPuller)}
		axes["subjectTypes"] = []string{gduGroup, gduUser, gduSA}
		u.patch("", axes)
		u.patch("", axes)
		u.axes(axes)
		require.Len(t, u.audit(), n)
		for _, a := range []struct{ key, field, noun string }{{"roleIds", "role_ids", "role"}, {"targetTypes", "target_types", "type"}, {"subjectTypes", "subject_types", "type"}} {
			vals := gduSorted(axes[a.key])
			dup := append(append([]string{}, vals...), vals[0])
			u.refuse(asUser(u.ctx, u.usrA), gduMask(a.key), map[string]any{a.key: dup}, codes.InvalidArgument, fmt.Sprintf("%s: %s %s is listed twice", a.field, a.noun, vals[0]), a.field)
			u.patch(a.key, map[string]any{a.key: vals})
		}
	})
	for _, axis := range []string{"roleIds", "targetTypes"} {
		t.Run(axis+"_16_17", func(t *testing.T) {
			u := newGDUWorld(t, false)
			roles, targets := u.deliverBounds()
			u.subject()
			values := targets
			if axis == "roleIds" {
				values = roles
			}
			require.Len(t, values, 17)
			field, noun := "target_types", "types"
			if axis == "roleIds" {
				field, noun = "role_ids", "roles"
			}
			u.refuse(asUser(u.ctx, u.usrA), gduMask(axis), map[string]any{axis: values}, codes.InvalidArgument, fmt.Sprintf("%s: at most 16 %s", field, noun), field)
			u.patch(axis, map[string]any{axis: values[:16]})
			u.axes(map[string]any{axis: values[:16]})
		})
	}
	t.Run("four_subjects_and_unknown", func(t *testing.T) {
		u := newGDUWorld(t, false)
		u.subject()
		all := []string{gduSA, gduGroup, gduUser, gduClass}
		for _, bad := range []any{"SUBJECT_TYPE_UNSPECIFIED", float64(99)} {
			values := []any{gduSA, gduGroup, gduUser, bad}
			text := fmt.Sprintf("subject_types: %v is not a subject type", bad)
			u.refuse(asUser(u.ctx, u.usrA), gduMask("subjectTypes"), map[string]any{"subjectTypes": values}, codes.InvalidArgument, text, "subject_types")
			u.patch("subjectTypes", map[string]any{"subjectTypes": all})
		}
	})
}
func TestGrantDelegation_GDU06_WholeFinalComposition(t *testing.T) {
	for _, name := range []string{"missing_role", "nonmodule_role", "foreign_role", "wild_role", "space_role", "case_role", "wild_target", "missing_target", "space_target", "case_target", "foreign_target", "iam_role", "replace_module", "retired_selected", "retired_unselected", "foreign_rule_port"} {
		t.Run(name, func(t *testing.T) {
			u := newGDUWorld(t, false)
			u.subject()
			key, field := "roleIds", ""
			bad := map[string]any{}
			code := codes.FailedPrecondition
			text := ""
			good := map[string]any{"roleIds": u.all()["roleIds"]}
			restore := func() {}
			switch name {
			case "missing_role", "wild_role", "space_role", "case_role":
				r := "rol00000000000000000"
				if name == "wild_role" {
					r = "*"
				}
				if name == "space_role" {
					r = " " + string(u.rolPusher)
				}
				if name == "case_role" {
					r = "ROL" + string(u.rolPusher)[3:]
				}
				bad[key] = []string{string(u.rolPuller), r}
				text = "Role " + r + " not found"
			case "nonmodule_role":
				bad[key] = []string{string(u.rolPuller), gdAdminRID}
				text = "role " + gdAdminRID + " is not declared by a module manifest"
			case "foreign_role":
				bad[key] = []string{string(u.rolPuller), string(u.rolVPCPool)}
				text = "role_ids and target_types must belong to one module; found registry, vpc"
			case "iam_role":
				bad[key] = []string{string(u.rolPuller), gdIAMRole}
				text = "role_ids and target_types must belong to one module; found iam, registry"
			case "replace_module":
				key = "roleIds,targetTypes"
				bad = map[string]any{"roleIds": []string{string(u.rolVPCPool)}, "targetTypes": []string{"vpc.addressPool"}}
				good = map[string]any{"roleIds": u.all()["roleIds"], "targetTypes": u.all()["targetTypes"]}
				text = fmt.Sprintf("grant delegation %s: module is immutable after GrantDelegation.Create", u.d)
			case "foreign_rule_port":
				restore = u.foreignRoleRule()
				bad[key] = u.all()[key]
				text = "role_ids and target_types must belong to one module; found registry, vpc"
			default:
				key = "targetTypes"
				value := "registry.missing"
				switch name {
				case "wild_target":
					value = "registry.*"
				case "space_target":
					value = " " + gdRepoTgt
				case "case_target":
					value = "Registry.repositories"
				case "foreign_target":
					value = "vpc.addressPool"
				case "retired_selected", "retired_unselected":
					value = gduRetiredTarget
					u.deliverRetirementTarget()
					u.patch("targetTypes", map[string]any{"targetTypes": []string{"registry.registries", value}})
					restore = u.retireTarget()
				}
				bad[key] = []string{"registry.registries", value}
				good = map[string]any{key: u.all()[key]}
				if name == "retired_selected" {
					good = bad
				}
				code = codes.InvalidArgument
				field = "target_types"
				text = gduDeadType(value)
				if name == "foreign_target" {
					code = codes.FailedPrecondition
					field = ""
					text = "role_ids and target_types must belong to one module; found registry, vpc"
				}
				if name == "retired_unselected" {
					key = "roleIds"
					bad = map[string]any{key: u.all()[key]}
					good = bad
				}
			}
			u.refuse(asUser(u.ctx, u.usrA), gduMask(key), bad, code, text, field)
			restore()
			if name == "retired_selected" || name == "retired_unselected" {
				require.Equal(t, u.body(gduMask(key), bad), u.body(gduMask(key), good), "близнец меняет только живость каталога, тело PATCH прежнее")
			}
			if name == "retired_selected" {
				before := u.get()
				audits := len(u.audit())
				u.patch(key, good)
				require.Equal(t, before, u.get(), "успешный близнец остаётся no-op")
				require.Len(t, u.audit(), audits, "no-op не создаёт событие расширения")
				return
			}
			u.patch(key, good)
		})
	}
	t.Run("catalog_retired_after_acceptance", func(t *testing.T) {
		u := newGDUWorld(t, false)
		u.subject()
		u.deliverRetirementTarget()
		u.patch("targetTypes", map[string]any{"targetTypes": []string{"registry.registries", gdRepoTgt, gduRetiredTarget}})
		op, release := u.acceptHeld(u.body(gduMask("roleIds"), map[string]any{"roleIds": u.all()["roleIds"]}))
		restore := u.retireTarget()
		release()
		gduOpError(t, u, op, codes.InvalidArgument, gduDeadType(gduRetiredTarget))
		u.invariant(false)
		restore()
		u.patch("roleIds", map[string]any{"roleIds": u.all()["roleIds"]})
	})

}
func TestGrantDelegation_GDU07_MaskIdentityAndAliases(t *testing.T) {
	imm := map[string]string{"id": "id", "account_id": "accountId", "accountId": "accountId", "delegate": "delegate", "module": "module", "status": "status", "delegated_by": "delegatedBy", "delegatedBy": "delegatedBy", "created_at": "createdAt", "createdAt": "createdAt", "revoked_at": "revokedAt", "revokedAt": "revokedAt", "revoked_by": "revokedBy", "revokedBy": "revokedBy"}
	for _, path := range []string{"id", "account_id", "accountId", "delegate", "module", "status", "delegated_by", "delegatedBy", "created_at", "createdAt", "revoked_at", "revokedAt", "revoked_by", "revokedBy", "expiresAt", "bogus", "*", "roleIds.child"} {
		t.Run(path, func(t *testing.T) {
			u := newGDUWorld(t, false)
			u.subject()
			text := fmt.Sprintf("Illegal argument update_mask field %q", path)
			if name, ok := imm[path]; ok {
				text = name + " is immutable after GrantDelegation.Create"
			}
			u.rawMaskRefusal([]string{path}, map[string]any{"roleIds": u.all()["roleIds"]}, text, path)
			u.patch("roleIds", map[string]any{"roleIds": u.all()["roleIds"]})
		})
	}
	t.Run("grpc_aliases_duplicate_and_unselected", func(t *testing.T) {
		u := newGDUWorld(t, false)
		u.subject()
		axes := map[string]any{"roleIds": u.all()["roleIds"], "subjectTypes": []string{"SUBJECT_TYPE_UNSPECIFIED"}, "targetTypes": []string{}}
		u.rawMask([]string{"role_ids"}, axes)
		u.rawMask([]string{"roleIds", "role_ids", "roleIds"}, axes)
		require.Len(t, u.audit(), 1)
		u.axes(map[string]any{"subjectTypes": []string{gduSA}, "targetTypes": []string{"registry.registries"}})
		u.patch("roleIds", axes)
		u.patch("roleIds,targetTypes,subjectTypes", u.all())
		u.axes(u.all())
	})
}
func TestGrantDelegation_GDU08_ActorAuthorityFirst(t *testing.T) {
	for _, actor := range []string{"owner", "account_admin", "cloud_admin", "outsider", "delegate"} {
		t.Run(actor, func(t *testing.T) {
			u := newGDUWorld(t, false)
			u.subject()
			ctx := asUser(u.ctx, u.usrA)
			switch actor {
			case "account_admin":
				ctx = asUser(u.ctx, u.usrE)
			case "cloud_admin":
				gdSeedTuple(t, u.ctx, u.pool, "user:"+string(u.usrD), "system_admin", "cluster:cluster_root")
				u.requireRelation("user:"+string(u.usrD), "system_admin", "cluster:cluster_root", true, "C admin")
				ctx = asUser(u.ctx, u.usrD)
			case "outsider":
				ctx = asUser(u.ctx, u.usrB)
			case "delegate":
				ctx = asSA(u.ctx, u.svaIss)
			}
			if actor == "outsider" || actor == "delegate" {
				u.refuse(ctx, gduMask("roleIds"), map[string]any{"roleIds": u.all()["roleIds"]}, codes.PermissionDenied, "permission denied", "")
				if actor == "outsider" {
					u.admin(userSubject(u.usrB))
				} else {
					u.admin(svaSubject(u.svaIss))
				}
			}
			u.success(ctx, gduMask("roleIds"), map[string]any{"roleIds": u.all()["roleIds"]})
			require.Equal(t, map[string]any{"type": "user", "id": string(u.usrA)}, u.get()["delegatedBy"])
		})
	}
	t.Run("actor_creator_matrix_and_hidden_missing", func(t *testing.T) {
		u := newGDUWorld(t, true)
		u.subject()
		axes := map[string]any{"roleIds": u.all()["roleIds"]}
		o := asUser(u.ctx, u.usrB)
		u.refuse(o, gduMask("roleIds"), axes, codes.PermissionDenied, "permission denied", "")
		u.revokeAdminE()
		u.refuse(o, gduMask("roleIds"), axes, codes.PermissionDenied, "permission denied", "")
		u.admin(userSubject(u.usrB))
		u.refuse(o, gduMask("roleIds"), axes, codes.FailedPrecondition, gduLostCreator(u.d), "")
		u.admin(userSubject(u.usrE))
		u.success(o, gduMask("roleIds"), axes)
		// Побайтовое сравнение gRPC Status с denied на ещё одном непривилегированном субъекте.
		denied := u.call(asUser(u.ctx, u.usrC), gduMask("roleIds"), axes)
		id := u.d
		u.d = "gdl00000000000000000"
		missing := u.call(asUser(u.ctx, u.usrA), gduMask("roleIds"), axes)
		u.d = id
		require.True(t, proto.Equal(status.Convert(denied.syncErr).Proto(), status.Convert(missing.syncErr).Proto()))
		requireSyncRefusal(t, missing.syncErr, codes.PermissionDenied, "permission denied", "missing hidden")
		u.patch("roleIds", axes)
	})
	t.Run("actor_lost_after_acceptance", func(t *testing.T) {
		u := newGDUWorld(t, false)
		u.subject()
		g := u.claimGate()
		op := u.acceptedAs(g, asUser(u.ctx, u.usrE), u.body(gduMask("roleIds"), map[string]any{"roleIds": u.all()["roleIds"]}))
		g.disarm()
		u.revokeAdminE()
		g.release(op.GetId())
		gduOpError(t, u, op, codes.PermissionDenied, "permission denied")
		u.invariant(true)
		u.grantE = u.admin(userSubject(u.usrE))
		u.success(asUser(u.ctx, u.usrE), gduMask("roleIds"), map[string]any{"roleIds": u.all()["roleIds"]})
	})

}
func TestGrantDelegation_GDU09_PublicDoorAndInvalidID(t *testing.T) {
	u := newGDUWorld(t, false)
	u.subject()
	axes := map[string]any{"roleIds": u.all()["roleIds"]}
	// Эта полоса — прямой use-case, НЕ доказательство HTTP authN/ACR. Дверь:
	// IAM-GDU-ANONYMOUS-DENIED / ACR1-DENIED / MACHINE-AUTHORITY-DENIED в newman.
	u.refuse(u.ctx, gduMask("roleIds"), axes, codes.PermissionDenied, "permission denied", "")
	for _, actor := range []context.Context{asUser(u.ctx, u.usrA), asUser(u.ctx, u.usrB)} {
		for _, id := range []string{"", "bad"} {
			m := map[string]any{"grantDelegationId": id, "updateMask": "roleIds", "roleIds": axes["roleIds"]}
			out := u.gdMutate(actor, "Update", mustJSON(t, m))
			require.Empty(t, out.opID)
			message := "grant_delegation_id: required"
			field := "grant_delegation_id"
			if id == "bad" {
				message = "invalid grant delegation id 'bad'"
				field = ""
			}
			gduRefusalDetails(t, out.syncErr, codes.InvalidArgument, message, field)
		}
	}
	u.patch("roleIds", axes)
}
func TestGrantDelegation_GDU10_OriginalCreatorRechecked(t *testing.T) {
	t.Run("lost_restored_and_backend", func(t *testing.T) {
		u := newGDUWorld(t, true)
		u.revokeAdminE()
		u.subject()
		axes := map[string]any{"roleIds": u.all()["roleIds"]}
		u.refuse(asUser(u.ctx, u.usrA), gduMask("roleIds"), axes, codes.FailedPrecondition, gduLostCreator(u.d), "")
		u.refuse(asUser(u.ctx, u.usrA), gduMask("roleIds"), u.currentAxes(), codes.FailedPrecondition, gduLostCreator(u.d), "")
		req := u.grant("target", false)
		req.Subjects = []*iamv1.Subject{svaSubject(u.svaA2)}
		requireDenied(t, u.tryGrant(asSA(u.ctx, u.svaIss), req), "новая выдача проверяет исходного автора")
		u.grantE = u.admin(userSubject(u.usrE))
		restore := u.authzFault("user:" + string(u.usrE))
		u.refuse(asUser(u.ctx, u.usrA), gduMask("roleIds"), axes, codes.Unavailable, "authz backend unavailable", "")
		restore()
		u.patch("roleIds", axes)
		u.expandedGrant("role")
		require.Equal(t, map[string]any{"type": "user", "id": string(u.usrE)}, u.get()["delegatedBy"])
		u.revokeAdminE()
		req.RoleId = string(u.rolPusher)
		requireDenied(t, u.tryGrant(asSA(u.ctx, u.svaIss), req), "Update не переносит автора на U")
	})
	t.Run("creator_lost_after_acceptance", func(t *testing.T) {
		u := newGDUWorld(t, true)
		u.subject()
		op, release := u.acceptHeld(u.body(gduMask("roleIds"), map[string]any{"roleIds": u.all()["roleIds"]}))
		u.revokeAdminE()
		release()
		gduOpError(t, u, op, codes.FailedPrecondition, gduLostCreator(u.d))
		u.invariant(true)
		u.admin(userSubject(u.usrE))
		u.patch("roleIds", map[string]any{"roleIds": u.all()["roleIds"]})
	})
}
func TestGrantDelegation_GDU11_RevokedAndExpiredBindings(t *testing.T) {
	t.Run("revoked_never_revives", func(t *testing.T) {
		u := newGDUWorld(t, false)
		u.subject()
		u.patch("roleIds", map[string]any{"roleIds": u.all()["roleIds"]})
		u.revokeDelegation(asUser(u.ctx, u.usrA), u.d, "Revoke before Update")
		before := u.get()
		for _, axes := range []map[string]any{u.all(), u.currentAxes()} {
			out := u.call(asUser(u.ctx, u.usrA), gduMask(""), axes)
			require.Empty(t, out.opID)
			requireSyncRefusal(t, out.syncErr, codes.FailedPrecondition, fmt.Sprintf("grant delegation %s is already revoked", u.d), "REVOKED")
			require.Equal(t, before, u.get())
			require.Zero(t, u.countActiveDelegated(u.d))
			u.selfCheck(u.svaA, "v_get", pcrRegType, pcrX, false)
		}
	})
	for _, expired := range []bool{false, true} {
		t.Run(fmt.Sprintf("binding_expired_%t", expired), func(t *testing.T) {
			u := newGDUWorld(t, false)
			req := u.grant("role", false)
			req.Subjects = []*iamv1.Subject{svaSubject(u.svaA2)}
			id := requireGranted(t, u.tryGrant(asSA(u.ctx, u.svaIss), req), "Bexp штатная выдача")
			delta := "1 day"
			if expired {
				delta = "-1 day"
			}
			// Изолированный исторический посев сохраняет expires_at > created_at:
			// срок уже прошёл, но наступил после создания. Ограничение не снимается.
			_, err := u.pool.Exec(u.ctx, `UPDATE kaname.access_bindings
				SET created_at=now()-interval '2 days', expires_at=now()+$2::interval
				WHERE id=$1`, id, delta)
			require.NoError(t, err)
			if expired {
				require.NoError(t, u.rec.ExpireBinding(u.ctx, domain.AccessBindingID(id)))
			} else {
				require.NoError(t, u.rec.ReconcileBinding(u.ctx, domain.AccessBindingID(id)))
			}
			old := proto.Clone(u.getBinding(id))
			u.selfCheck(u.svaA2, "v_get", pcrRegType, pcrX, !expired)
			u.subject()
			u.patch("roleIds", map[string]any{"roleIds": u.all()["roleIds"]})
			require.True(t, proto.Equal(old, u.getBinding(id)))
			u.selfCheck(u.svaA2, "v_get", pcrRegType, pcrX, !expired)
		})
	}
}
func TestGrantDelegation_GDU12_FailureAtomicity(t *testing.T) {
	for _, fault := range []string{"authority", "commit_before_fixation", "lost_response_after_fixation"} {
		t.Run(fault, func(t *testing.T) {
			u := newGDUWorld(t, false)
			u.subject()
			axes := u.all()
			before := u.get()
			n := len(u.audit())
			if fault == "authority" {
				restore := u.authzFault("")
				u.refuse(asUser(u.ctx, u.usrA), gduMask(""), axes, codes.Unavailable, "authz backend unavailable", "")
				restore()
				u.patch("", axes)
				return
			}
			if fault == "commit_before_fixation" {
				restore := u.failCommit()
				out := u.call(asUser(u.ctx, u.usrA), gduMask(""), axes)
				require.NoError(t, out.syncErr)
				require.NotEmpty(t, out.opID)
				require.NotNil(t, out.opErr)
				require.Equal(t, codes.Unavailable, out.opErr.Code())
				require.Equal(t, "service unavailable", out.opErr.Message())
				restore()
				require.Equal(t, before, u.get())
				require.Len(t, u.audit(), n)
				u.invariant(true)
				u.patch("", axes)
				return
			}
			// Полученный Operation намеренно не используется как источник результата;
			// завершение подтверждает хранилище операции, клиент восстанавливается Get/retry.
			_, msg, err := u.gdCall(asUser(u.ctx, u.usrA), "Update", u.body(gduMask(""), axes))
			require.NoError(t, err)
			op := msg.(*operationpb.Operation)
			done := awaitOp(t, u.ctx, u.ops, op.GetId())
			require.Nil(t, done.Error)
			u.axes(axes)
			u.patch("", axes)
			require.Len(t, u.audit(), n+1)
			u.invariant(false)
		})
	}
}
func TestGrantDelegation_GDU16_AuditExactlyOnceOnExpansion(t *testing.T) {
	u := newGDUWorld(t, false)
	u.subject()
	before := u.currentAxes()
	rows := u.auditRows()
	u.success(asUser(u.ctx, u.usrE), gduMask(""), u.all())
	events := u.audit()
	require.Len(t, events, 1)
	ev := events[0]
	require.Equal(t, string(u.usrE), ev.payload["actor"])
	require.Equal(t, u.d, ev.payload["delegation_id"])
	require.Equal(t, string(u.accA), ev.payload["account_id"])
	require.True(t, ev.tenant.Valid)
	require.Equal(t, string(u.accA), ev.tenant.String)
	for _, side := range []struct {
		name string
		axes map[string]any
	}{{"before", before}, {"after", u.all()}} {
		m, ok := ev.payload[side.name].(map[string]any)
		require.True(t, ok)
		for _, a := range []struct{ json, key string }{{"roleIds", "role_ids"}, {"targetTypes", "target_types"}, {"subjectTypes", "subject_types"}} {
			want := gduSorted(side.axes[a.json])
			if a.key == "subject_types" {
				// Аудит использует доменные имена, как существующий Create;
				// вход публичного RPC несёт protobuf enum. Сравниваем все значения.
				for i, name := range want {
					subject, ok := domain.SubjectTypeOfPrincipal(name)
					require.True(t, ok, "тип субъекта известен домену")
					want[i] = string(subject)
				}
			}
			require.Equal(t, want, gotSlice(m[a.key]), side.name+"/"+a.key)
		}
	}
	for _, event := range []string{"iam.access_binding.granted", "iam.access_binding.revoked", "iam.access_binding.delegation_revoked"} {
		require.Equal(t, len(findAudit(rows, event, "")), len(findAudit(u.auditRows(), event, "")), "Update не меняет выдачи")
	}
	u.patch("", u.all())
	require.Len(t, u.audit(), 1)
	u.refuse(asUser(u.ctx, u.usrA), gduMask("roleIds"), map[string]any{"roleIds": []string{string(u.rolPusher)}}, codes.FailedPrecondition, gduNarrow(u.d, "role_ids"), "")
	require.Len(t, u.audit(), 1)
	u.patch("roleIds", map[string]any{"roleIds": []string{string(u.rolPuller), string(u.rolPusher), string(u.rolRegAdmin)}})
	require.Len(t, u.audit(), 2)
	require.Equal(t, 1, u.countDelegated(u.d))
}
func TestGrantDelegation_GDU17_ReplacementWithExplicitGap(t *testing.T) {
	u := newGDUWorld(t, false)
	u.subject()
	u.patch("", u.all())
	req := u.grant("role", true)
	req.DeletionProtection = true
	b2 := requireGranted(t, u.tryGrant(asSA(u.ctx, u.svaIss), req), "защищённая выдача r2")
	require.NoError(t, u.rec.ReconcileBinding(u.ctx, domain.AccessBindingID(b2)))
	u.effect("role", true)
	body := u.delegationBody(u.accA, u.svaIss, []domain.RoleID{u.rolPuller}, []string{"registry.registries"}, []string{gduSA})
	dup := u.gdMutate(asUser(u.ctx, u.usrA), "Create", body)
	require.NoError(t, dup.syncErr)
	require.NotNil(t, dup.opErr)
	require.Equal(t, codes.AlreadyExists, dup.opErr.Code())
	require.Equal(t, fmt.Sprintf("an active grant delegation to service account %s in account %s already exists", u.svaIss, u.accA), dup.opErr.Message())
	old := u.d
	u.revokeDelegation(asUser(u.ctx, u.usrA), old, "явный разрыв перед заменой")
	u.selfCheck(u.svaA, "v_get", pcrRegType, pcrX, false)
	u.effect("role", false)
	for _, id := range []string{u.b, b2} {
		b := u.getBinding(id)
		require.Equal(t, iamv1.AccessBinding_REVOKED, b.GetStatus())
		require.Equal(t, reasonDelegationRevoked, b.GetRevocationReason())
		require.NotNil(t, b.GetRevokedAt())
		got, _ := delegationIDOf(t, b)
		require.Equal(t, old, got)
	}
	u.d = u.createDelegation(asUser(u.ctx, u.usrA), body, "Create после Revoke")
	require.NotEqual(t, old, u.d)
	u.selfCheck(u.svaA, "v_get", pcrRegType, pcrX, false)
	newB := requireGranted(t, u.tryGrant(asSA(u.ctx, u.svaIss), u.grant("role", false)), "повторная разрешённая выдача")
	require.NotEqual(t, u.b, newB)
	u.requireDelegatedBinding(newB, u.d, "новая ссылка")
	require.NoError(t, u.rec.ReconcileBinding(u.ctx, domain.AccessBindingID(newB)))
	u.selfCheck(u.svaA, "v_get", pcrRegType, pcrX, true)
	requireDenied(t, u.tryGrant(asSA(u.ctx, u.svaIss), req), "r2 не переносится")
	oldD, err := u.getDelegation(asUser(u.ctx, u.usrA), old)
	require.NoError(t, err)
	require.Equal(t, "REVOKED", oldD["status"])
	for _, id := range []string{u.b, b2} {
		b := u.getBinding(id)
		require.Equal(t, iamv1.AccessBinding_REVOKED, b.GetStatus())
		got, _ := delegationIDOf(t, b)
		require.Equal(t, old, got)
	}
}
