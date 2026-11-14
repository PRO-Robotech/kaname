// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package resourceeffect_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/resourceeffect"
	"github.com/stretchr/testify/require"
)

func objectFacts(t *testing.T, public bool) *catalog.Facts {
	t.Helper()
	rows := catalog.Rows{Modules: []string{"probe", "iam"}, Resources: []catalog.ResourceRow{
		{Module: "probe", Resource: "boxes", ObjectType: "odd_box", PublicReadToChildren: public},
		{Module: "probe", Resource: "items", ObjectType: "odd_item", ParentTypes: []string{"odd_box"}, ParentNames: []string{"box"}},
		{Module: "probe", Resource: "tags", ObjectType: "odd_tag", ParentTypes: []string{"odd_item"}, ParentNames: []string{"item"}},
		{Module: "iam", Resource: "account", ObjectType: "account"},
		{Module: "iam", Resource: "project", ObjectType: "project"},
		{Module: "iam", Resource: "serviceAccount", ObjectType: "service_account"},
	}}
	for _, r := range rows.Resources {
		for _, verb := range []string{"get", "list", "update", "delete"} {
			rows.Verbs = append(rows.Verbs, catalog.VerbRow{Module: r.Module, Resource: r.Resource, Verb: verb, PerObject: true})
		}
	}
	rows.Verbs = append(rows.Verbs, catalog.VerbRow{Module: "iam", Resource: "serviceAccount", Verb: "create", ContainerParent: "account", ContainerRelation: "service_account_creator"})
	f, err := catalog.NewFacts(catalog.Halves{Live: rows})
	require.NoError(t, err)
	return f
}

func objectBinding() resourceeffect.ObjectBinding {
	return resourceeffect.ObjectBinding{
		BindingID: "acb_a", RoleID: "rol_a", Scope: domain.ScopeAnchor{Type: "account", ID: "a"},
		Subjects: []domain.Subject{{Type: domain.SubjectTypeUser, ID: "u"}}, Policy: domain.PolicyOfRole(false, ""),
		Selectors: []domain.RuleSelector{{RuleFP: "read", Arm: domain.ArmAnchor, ObjectTypes: []string{"probe.boxes"}, Verbs: []string{"get"}}},
		Target:    domain.AccessTarget{AllInScope: true},
	}
}

func capturedObject(typ, id string) domain.MirrorObject {
	return domain.MirrorObject{ObjectType: typ, ObjectID: id, ParentProjectID: "p", ParentAccountIDs: []string{"a"}, Labels: map[string]string{"team": "red"}}
}

func objectDesired(t *testing.T, f *catalog.Facts, b resourceeffect.ObjectBinding, o domain.MirrorObject, ancestors ...domain.MirrorObject) []resourceeffect.ObjectDesiredMember {
	t.Helper()
	out, err := resourceeffect.CompileObjectDesired(f, b, o, ancestors)
	require.NoError(t, err)
	return out
}

func TestObjectDesiredFlatSelectorsTargetAndContainment(t *testing.T) {
	f := objectFacts(t, false)
	for _, tc := range []struct {
		name   string
		change func(*resourceeffect.ObjectBinding, *domain.MirrorObject)
		status domain.VerificationStatus
	}{
		{name: "anchor", status: domain.VerificationActive},
		{name: "names_match", change: func(b *resourceeffect.ObjectBinding, _ *domain.MirrorObject) {
			b.Selectors[0].Arm = domain.ArmNames
			b.Selectors[0].ResourceNames = []string{"x"}
		}, status: domain.VerificationActive},
		{name: "names_miss", change: func(b *resourceeffect.ObjectBinding, _ *domain.MirrorObject) {
			b.Selectors[0].Arm = domain.ArmNames
			b.Selectors[0].ResourceNames = []string{"y"}
		}},
		{name: "labels_match", change: func(b *resourceeffect.ObjectBinding, _ *domain.MirrorObject) {
			b.Selectors[0].Arm = domain.ArmLabels
			b.Selectors[0].MatchLabels = map[string]string{"team": "red"}
		}, status: domain.VerificationActive},
		{name: "labels_miss", change: func(b *resourceeffect.ObjectBinding, _ *domain.MirrorObject) {
			b.Selectors[0].Arm = domain.ArmLabels
			b.Selectors[0].MatchLabels = map[string]string{"team": "blue"}
		}},
		{name: "outside_scope_is_rejected", change: func(_ *resourceeffect.ObjectBinding, o *domain.MirrorObject) { o.ParentAccountIDs = []string{"other"} }, status: domain.VerificationRejected},
		{name: "finite_target_match", change: func(b *resourceeffect.ObjectBinding, _ *domain.MirrorObject) {
			b.Target = domain.AccessTarget{Resources: []domain.ResourceRef{{Type: "probe.boxes", ID: "x"}}}
		}, status: domain.VerificationActive},
		{name: "finite_target_other_type", change: func(b *resourceeffect.ObjectBinding, _ *domain.MirrorObject) {
			b.Target = domain.AccessTarget{Resources: []domain.ResourceRef{{Type: "probe.tags", ID: "x"}}}
		}},
		{name: "type_without_catalog", change: func(b *resourceeffect.ObjectBinding, o *domain.MirrorObject) {
			b.Selectors[0].ObjectTypes = []string{"gone.boxes"}
			o.ObjectType = "gone.boxes"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, o := objectBinding(), capturedObject("probe.boxes", "x")
			if tc.change != nil {
				tc.change(&b, &o)
			}
			out := objectDesired(t, f, b, o)
			if tc.status == "" {
				require.Empty(t, out)
				return
			}
			require.Len(t, out, 1)
			require.Equal(t, "read", out[0].RuleFP)
			require.Equal(t, tc.status, out[0].Status)
			if tc.status == domain.VerificationRejected {
				require.Empty(t, out[0].Tuples)
				return
			}
			require.Equal(t, []domain.MembershipTuple{{User: "user:u", Relation: "v_get", Object: "odd_box:x"}, {User: "user:u", Relation: "viewer", Object: "odd_box:x"}}, out[0].Tuples)
		})
	}
}

func TestObjectDesiredKeepsRuleAndSubjectOrderWithoutActiveFiltering(t *testing.T) {
	b := objectBinding()
	b.Subjects = []domain.Subject{{Type: domain.SubjectTypeUser, ID: "u"}, {Type: domain.SubjectTypeGroup, ID: "g"}, {Type: domain.SubjectTypeSystemClass, ID: domain.ClassAuthenticated}}
	b.Selectors[0].Verbs = []string{"get", "update"}
	b.Selectors = append(b.Selectors, domain.RuleSelector{RuleFP: "second", Arm: domain.ArmAnchor, ObjectTypes: []string{"probe.boxes"}, Verbs: []string{"get"}})
	out := objectDesired(t, objectFacts(t, false), b, capturedObject("probe.boxes", "x"))
	require.False(t, b.Active, "pure compiler не вводит дополнительный eligibility gate")
	require.Len(t, out, 2)
	require.Equal(t, []string{"read", "second"}, []string{out[0].RuleFP, out[1].RuleFP})
	var users []string
	for _, tuple := range out[1].Tuples {
		if tuple.Relation == "v_get" {
			users = append(users, tuple.User)
		}
	}
	require.Equal(t, []string{"user:u", "group:g#member", "system_class:authenticated"}, users)
	for _, tuple := range out[0].Tuples {
		if strings.HasPrefix(tuple.User, "system_class:") {
			require.NotContains(t, []string{"v_update", "v_delete", "editor", "admin"}, tuple.Relation)
		}
	}
	b.Active = true
	require.Equal(t, out, objectDesired(t, objectFacts(t, false), b, capturedObject("probe.boxes", "x")))
}

func TestObjectDesiredNestedGrandchildUsesContainerTargetAndAllAncestors(t *testing.T) {
	f := objectFacts(t, false)
	for _, tc := range []string{"match", "missing_container", "other_target", "container_outside", "class_only", "leaf_outside"} {
		t.Run(tc, func(t *testing.T) {
			b := objectBinding()
			b.Subjects = append(b.Subjects, domain.Subject{Type: domain.SubjectTypeSystemClass, ID: domain.ClassAnonymous})
			b.Target = domain.AccessTarget{Resources: []domain.ResourceRef{{Type: "probe.boxes", ID: "box"}}}
			b.Selectors = []domain.RuleSelector{{RuleFP: "grandchild", Arm: domain.ArmAnchor, ObjectTypes: []string{"probe.tags"}, Verbs: []string{"get"}, Container: &domain.ContainerSelector{Type: "probe.boxes", OwnerFP: "owner", Arm: domain.ArmNames, ResourceNames: []string{"box"}}}}
			o := capturedObject("probe.tags", "tag")
			ancestors := []domain.MirrorObject{capturedObject("probe.items", "item"), capturedObject("probe.boxes", "box")}
			switch tc {
			case "missing_container":
				ancestors = ancestors[:1]
			case "other_target":
				b.Target.Resources[0].ID = "other"
			case "container_outside":
				ancestors[1].ParentAccountIDs = []string{"other"}
			case "class_only":
				b.Subjects = b.Subjects[1:]
			case "leaf_outside":
				o.ParentAccountIDs = []string{"other"}
			}
			out := objectDesired(t, f, b, o, ancestors...)
			if tc != "match" && tc != "leaf_outside" {
				require.Empty(t, out)
				return
			}
			require.Len(t, out, 1)
			if tc == "leaf_outside" {
				require.Equal(t, domain.VerificationRejected, out[0].Status)
				require.Empty(t, out[0].Tuples)
				return
			}
			require.Equal(t, domain.VerificationActive, out[0].Status)
			require.Equal(t, []domain.MembershipTuple{{User: "user:u", Relation: "v_get", Object: "odd_tag:tag"}, {User: "user:u", Relation: "viewer", Object: "odd_tag:tag"}}, out[0].Tuples)
		})
	}
}

func TestObjectDesiredCreatorKeepsContainerAndCreatorRelativeEffectsSeparate(t *testing.T) {
	f := objectFacts(t, false)
	b := objectBinding()
	b.Subjects = []domain.Subject{{Type: domain.SubjectTypeServiceAccount, ID: "s1"}, {Type: domain.SubjectTypeServiceAccount, ID: "s2"}, {Type: domain.SubjectTypeUser, ID: "u"}}
	b.Selectors = []domain.RuleSelector{
		{RuleFP: "create", Arm: domain.ArmAnchor, ObjectTypes: []string{"iam.serviceAccount"}, Verbs: []string{"create"}},
		{RuleFP: "own", Arm: domain.ArmAnchor, ObjectTypes: []string{"iam.serviceAccount"}, Verbs: []string{"get", "update"}, CreatedBySubject: true},
	}
	parent := objectDesired(t, f, b, capturedObject("iam.account", "a"))
	require.Len(t, parent, 1)
	require.Equal(t, "create", parent[0].RuleFP)
	require.Equal(t, []domain.MembershipTuple{{User: "service_account:s1", Relation: "service_account_creator", Object: "account:a"}, {User: "service_account:s2", Relation: "service_account_creator", Object: "account:a"}}, parent[0].Tuples)
	child := capturedObject("iam.serviceAccount", "child")
	child.CreatedBy = "service_account:s2"
	out := objectDesired(t, f, b, child)
	require.Len(t, out, 1)
	require.Equal(t, "own", out[0].RuleFP)
	for _, tuple := range out[0].Tuples {
		require.Equal(t, "service_account:s2", tuple.User)
		require.True(t, strings.HasPrefix(tuple.Relation, "v_"))
		require.Equal(t, "service_account:child", tuple.Object)
	}
	require.ElementsMatch(t, []domain.MembershipTuple{{User: "service_account:s2", Relation: "v_get", Object: "service_account:child"}, {User: "service_account:s2", Relation: "v_update", Object: "service_account:child"}, {User: "service_account:s2", Relation: "v_delete", Object: "service_account:child"}}, out[0].Tuples)
	child.CreatedBy = ""
	require.Empty(t, objectDesired(t, f, b, child))
	b.Target = domain.AccessTarget{Resources: []domain.ResourceRef{{Type: "iam.serviceAccount", ID: "child"}}}
	require.Empty(t, objectDesired(t, f, b, capturedObject("iam.account", "a")))
}

func TestObjectDesiredModulePolicyDoesNotInventDelete(t *testing.T) {
	f := objectFacts(t, false)
	b := objectBinding()
	b.Selectors[0].Verbs = []string{"update"}
	tenant := objectDesired(t, f, b, capturedObject("probe.boxes", "x"))
	require.Contains(t, tenant[0].Tuples, domain.MembershipTuple{User: "user:u", Relation: "v_delete", Object: "odd_box:x"})
	b.Policy = domain.PolicyOfRole(true, "probe")
	module := objectDesired(t, f, b, capturedObject("probe.boxes", "x"))
	require.Contains(t, module[0].Tuples, domain.MembershipTuple{User: "user:u", Relation: "v_update", Object: "odd_box:x"})
	require.NotContains(t, module[0].Tuples, domain.MembershipTuple{User: "user:u", Relation: "v_delete", Object: "odd_box:x"})
}

func TestObjectDesiredScopeSelfRequiresOwnAnchorAndWholeTarget(t *testing.T) {
	f := objectFacts(t, false)
	b := objectBinding()
	b.ScopeSelfVerbs = []string{"get"}
	b.Selectors = []domain.RuleSelector{{RuleFP: "content", Arm: domain.ArmAnchor, ObjectTypes: []string{"iam.account"}, Verbs: []string{"get"}}}
	anchor := capturedObject("iam.account", "a")
	out := objectDesired(t, f, b, anchor)
	require.Len(t, out, 2)
	require.Equal(t, "scope_self", out[0].RuleFP)
	require.Equal(t, "content", out[1].RuleFP)
	b.Target = domain.AccessTarget{Resources: []domain.ResourceRef{{Type: "iam.account", ID: "a"}}}
	out = objectDesired(t, f, b, anchor)
	require.Len(t, out, 1)
	require.Equal(t, "content", out[0].RuleFP)
	b.Target = domain.AccessTarget{AllInScope: true}
	b.Selectors = nil
	require.Empty(t, objectDesired(t, f, b, capturedObject("iam.account", "other")))
	b.Scope = domain.ScopeAnchor{Type: "cluster", ID: "cluster_root"}
	require.Empty(t, objectDesired(t, f, b, capturedObject("iam.cluster", "cluster_root")))
}

func TestObjectDesiredPublicReaderRequiresDirectChildAndActiveSelectedOwner(t *testing.T) {
	b := objectBinding()
	b.Subjects = []domain.Subject{{Type: domain.SubjectTypeSystemClass, ID: domain.ClassAuthenticated}, {Type: domain.SubjectTypeUser, ID: "u"}, {Type: domain.SubjectTypeSystemClass, ID: domain.ClassAnonymous}}
	b.Selectors = []domain.RuleSelector{
		{RuleFP: "owner", Arm: domain.ArmNames, ObjectTypes: []string{"probe.boxes"}, ResourceNames: []string{"x"}, Verbs: []string{"get", "list"}},
		{RuleFP: "child", Arm: domain.ArmAnchor, ObjectTypes: []string{"probe.items"}, Verbs: []string{"get", "list"}, Container: &domain.ContainerSelector{Type: "probe.boxes", OwnerFP: "owner", Arm: domain.ArmNames, ResourceNames: []string{"x"}}},
	}
	o := capturedObject("probe.boxes", "x")
	out := objectDesired(t, objectFacts(t, true), b, o)
	require.Len(t, out, 2)
	require.Equal(t, "public_reader:child@system_class:anonymous,system_class:authenticated", out[1].RuleFP)
	require.Equal(t, []domain.MembershipTuple{{User: "system_class:authenticated", Relation: "public_reader", Object: "odd_box:x"}, {User: "system_class:anonymous", Relation: "public_reader", Object: "odd_box:x"}}, out[1].Tuples)
	require.Len(t, objectDesired(t, objectFacts(t, false), b, o), 1)
	b.Selectors[1].ObjectTypes = []string{"probe.tags"}
	require.Len(t, objectDesired(t, objectFacts(t, true), b, o), 1, "public_reader не перепрыгивает прямого ребёнка")
	b.Selectors[1].ObjectTypes = []string{"probe.items"}
	o.ParentAccountIDs = []string{"other"}
	out = objectDesired(t, objectFacts(t, true), b, o)
	require.Len(t, out, 1)
	require.Equal(t, domain.VerificationRejected, out[0].Status)
	require.Empty(t, out[0].Tuples)
}

func TestObjectDesiredIsDeterministicAndDoesNotMutateInputs(t *testing.T) {
	b, before := objectBinding(), objectBinding()
	o, objectBefore := capturedObject("probe.boxes", "x"), capturedObject("probe.boxes", "x")
	f := objectFacts(t, false)
	out := objectDesired(t, f, b, o)
	require.Equal(t, out, objectDesired(t, f, b, o))
	metadataFree := b
	metadataFree.BindingID, metadataFree.RoleID = "", ""
	require.Equal(t, out, objectDesired(t, f, metadataFree, o), "неиспользуемые metadata IDs не меняют pure effect")
	out[0].Tuples[0].User = "changed"
	require.Equal(t, before, b)
	require.Equal(t, objectBefore, o)
	require.Equal(t, "user:u", objectDesired(t, f, b, o)[0].Tuples[0].User)
}

func TestObjectDesiredRejectsMalformedSnapshotWithoutPartialOutput(t *testing.T) {
	f := objectFacts(t, false)
	for _, tc := range []string{"facts", "scope_type", "subject_type", "scope", "object", "subjects", "duplicate_subject", "selector", "container", "ancestor"} {
		t.Run(tc, func(t *testing.T) {
			facts, b, o := f, objectBinding(), capturedObject("probe.boxes", "x")
			var ancestors []domain.MirrorObject
			switch tc {
			case "facts":
				facts = nil
			case "scope_type":
				b.Scope.Type = ""
			case "subject_type":
				b.Subjects[0].Type = "unknown"
			case "scope":
				b.Scope.ID = ""
			case "object":
				o.ObjectID = ""
			case "subjects":
				b.Subjects = nil
			case "duplicate_subject":
				b.Subjects = append(b.Subjects, b.Subjects[0])
			case "selector":
				b.Selectors[0].RuleFP = ""
			case "container":
				b.Selectors[0].Container = &domain.ContainerSelector{}
			case "ancestor":
				ancestors = []domain.MirrorObject{{ObjectType: "probe.items"}}
			}
			out, err := resourceeffect.CompileObjectDesired(facts, b, o, ancestors)
			require.ErrorIs(t, err, resourceeffect.ErrInvalidSnapshot)
			require.Nil(t, out)
		})
	}
}

// Тонкая direct-relation выдача законно не несёт role_id и materializing rules.
// Отсутствие желаемых членов — успешный результат, а не новое eligibility правило.
func TestObjectDesiredThinDirectBindingWithoutRoleIsEmptySuccess(t *testing.T) {
	b := objectBinding()
	b.BindingID, b.RoleID = "", ""
	b.Selectors = nil
	b.ScopeSelfVerbs = nil
	out, err := resourceeffect.CompileObjectDesired(objectFacts(t, false), b, capturedObject("probe.boxes", "x"), nil)
	require.NoError(t, err)
	require.Empty(t, out)
}
