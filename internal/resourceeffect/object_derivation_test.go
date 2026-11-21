// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package resourceeffect_test

import (
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/stretchr/testify/require"
)

// Метка отличает реальные ветви при совпадении FP/объекта, но не меняет
// набор выдаваемых кортежей. Authority проверяет отдельный SQL verifier.
func TestObjectDesiredDerivationIdentifiesActualBranches(t *testing.T) {
	t.Run("ordinary and foreign rejected", func(t *testing.T) {
		b := objectBinding()
		f := objectFacts(t, false)
		o := capturedObject("probe.boxes", "x")
		out := objectDesired(t, f, b, o)
		require.Len(t, out, 1)
		require.Equal(t, "ordinary", out[0].Derivation)
		require.Equal(t, domain.VerificationActive, out[0].Status)
		require.Contains(t, out[0].Tuples, domain.MembershipTuple{User: "user:u", Relation: "v_get", Object: "odd_box:x"})
		o.ParentAccountIDs = []string{"foreign"}
		out = objectDesired(t, f, b, o)
		require.Len(t, out, 1)
		require.Equal(t, "ordinary", out[0].Derivation)
		require.Equal(t, domain.VerificationRejected, out[0].Status)
		require.Empty(t, out[0].Tuples)
	})
	t.Run("nested", func(t *testing.T) {
		b := objectBinding()
		b.Selectors = []domain.RuleSelector{{RuleFP: "child", Arm: domain.ArmAnchor, ObjectTypes: []string{"probe.items"}, Verbs: []string{"get"}, Container: &domain.ContainerSelector{Type: "probe.boxes", OwnerFP: "owner", Arm: domain.ArmNames, ResourceNames: []string{"box"}}}}
		out := objectDesired(t, objectFacts(t, false), b, capturedObject("probe.items", "item"), capturedObject("probe.boxes", "box"))
		require.Len(t, out, 1)
		require.Equal(t, "nested", out[0].Derivation)
		require.Contains(t, out[0].Tuples, domain.MembershipTuple{User: "user:u", Relation: "v_get", Object: "odd_item:item"})
	})
	t.Run("scope and ordinary remain separate", func(t *testing.T) {
		b := objectBinding()
		b.ScopeSelfVerbs = []string{"get"}
		b.Selectors = []domain.RuleSelector{{RuleFP: "content", Arm: domain.ArmAnchor, ObjectTypes: []string{"iam.account"}, Verbs: []string{"get"}}}
		out := objectDesired(t, objectFacts(t, false), b, capturedObject("iam.account", "a"))
		require.Len(t, out, 2)
		require.Equal(t, "scope_self", out[0].Derivation)
		require.Equal(t, "ordinary", out[1].Derivation)
		require.Equal(t, "scope_self", out[0].RuleFP)
		require.Equal(t, "content", out[1].RuleFP)
	})
	t.Run("container", func(t *testing.T) {
		b := objectBinding()
		b.Subjects = []domain.Subject{{Type: domain.SubjectTypeServiceAccount, ID: "bot"}}
		b.Selectors = []domain.RuleSelector{{RuleFP: "create", Arm: domain.ArmAnchor, ObjectTypes: []string{"iam.serviceAccount"}, Verbs: []string{"create"}}}
		out := objectDesired(t, objectFacts(t, false), b, capturedObject("iam.account", "a"))
		require.Len(t, out, 1)
		require.Equal(t, "container", out[0].Derivation)
		require.Equal(t, []domain.MembershipTuple{{User: "service_account:bot", Relation: "service_account_creator", Object: "account:a"}}, out[0].Tuples)
	})
	t.Run("public reader requires verified owner contribution", func(t *testing.T) {
		b := objectBinding()
		b.Subjects = append(b.Subjects, domain.Subject{Type: domain.SubjectTypeSystemClass, ID: domain.ClassAuthenticated})
		b.Selectors = []domain.RuleSelector{{RuleFP: "owner", Arm: domain.ArmNames, ObjectTypes: []string{"probe.boxes"}, ResourceNames: []string{"x"}, Verbs: []string{"get"}},
			{RuleFP: "child", Arm: domain.ArmAnchor, ObjectTypes: []string{"probe.items"}, Verbs: []string{"get", "list"}, Container: &domain.ContainerSelector{Type: "probe.boxes", OwnerFP: "owner", Arm: domain.ArmNames, ResourceNames: []string{"x"}}}}
		out := objectDesired(t, objectFacts(t, true), b, capturedObject("probe.boxes", "x"))
		require.Len(t, out, 2)
		require.Equal(t, "ordinary", out[0].Derivation)
		require.Equal(t, "public_reader", out[1].Derivation)
		require.Equal(t, []domain.MembershipTuple{{User: "system_class:authenticated", Relation: "public_reader", Object: "odd_box:x"}}, out[1].Tuples)
		// Один get не даёт публичное чтение детей: иначе класс получил бы
		// невыданный list. Проверенный ordinary owner остаётся тем же.
		ordinary := out[0]
		b.Selectors[1].Verbs = []string{"get"}
		out = objectDesired(t, objectFacts(t, true), b, capturedObject("probe.boxes", "x"))
		require.Len(t, out, 1)
		require.Equal(t, ordinary, out[0])
		// Отказ при foreign/rejected owner с полным child get+list отдельно
		// проверяет TestObjectDesiredPublicReaderRequiresDirectChildAndActiveSelectedOwner.
	})
}
