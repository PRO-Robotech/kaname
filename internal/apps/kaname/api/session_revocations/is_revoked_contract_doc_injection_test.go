// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package session_revocations

// is_revoked_contract_doc_injection_test.go — опыт: гейт контракта IsRevoked
// способен упасть по каждой стороне сверки и способен смолчать.
//
// Вход берётся из дерева и портится по одному факту; законный близнец отличается
// от инъекции ровно этим фактом.

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// cloneFacts — копия входа, чтобы порча одного опыта не текла в соседний.
func cloneFacts(f isRevokedContractFacts) isRevokedContractFacts {
	out := isRevokedContractFacts{Judged: map[string]bool{}, Texts: map[string]string{}}
	for k, v := range f.Judged {
		out.Judged[k] = v
	}
	for k, v := range f.Texts {
		out.Texts[k] = v
	}
	return out
}

// TestIsRevokedContractGate_FallsOnEachSide — порча по одному факту.
func TestIsRevokedContractGate_FallsOnEachSide(t *testing.T) {
	tree := treeContractFacts(t)
	require.True(t, tree.Judged[sourceFamily],
		"ПРЕДПОСЫЛКА ОПЫТА: ответ на дереве обязан судить семейство")

	for name := range contractClaims {
		t.Run("контракт молчит о семействе: "+name, func(t *testing.T) {
			f := cloneFacts(tree)
			f.Texts[name] = sourceMarker[sourceFamily].ReplaceAllString(f.Texts[name], "row")
			require.Contains(t, auditIsRevokedContract(f),
				name+": ответ судит источник «family», а контракт его не называет")
		})
	}

	t.Run("ответ перестал судить семейство, контракт обещает", func(t *testing.T) {
		f := cloneFacts(tree)
		delete(f.Judged, sourceFamily)
		found := auditIsRevokedContract(f)
		for name := range contractClaims {
			require.Contains(t, found,
				name+": контракт называет источник «family», а ответ по нему не судит")
		}
	})

	t.Run("контракт молчит о записи по идентификатору", func(t *testing.T) {
		f := cloneFacts(tree)
		f.Texts[textRPC] = sourceMarker[sourceRecord].ReplaceAllString(f.Texts[textRPC], "the table")
		require.Contains(t, auditIsRevokedContract(f),
			textRPC+": ответ судит источник «record», а контракт его не называет")
	})
}

// TestIsRevokedContractGate_SilentOnTwins — законные близнецы.
func TestIsRevokedContractGate_SilentOnTwins(t *testing.T) {
	tree := treeContractFacts(t)

	t.Run("дерево", func(t *testing.T) {
		require.Empty(t, auditIsRevokedContract(tree),
			"гейт находит нарушение на согласном дереве — он ловит форму, а не существо")
	})

	t.Run("ни ответ, ни контракт о семействе не говорят", func(t *testing.T) {
		f := cloneFacts(tree)
		delete(f.Judged, sourceFamily)
		for name := range f.Texts {
			f.Texts[name] = sourceMarker[sourceFamily].ReplaceAllString(f.Texts[name], "row")
		}
		require.Empty(t, auditIsRevokedContract(f))
	})
}

// TestIsRevokedContractGate_ReadsCallNodesNotProse — перепись источников судит
// узел вызова: упоминание в комментарии источником не считается.
func TestIsRevokedContractGate_ReadsCallNodesNotProse(t *testing.T) {
	const withCall = `package p
func (h *H) IsRevoked() { h.read.IsRevoked(); tokenrevocation.FamilyRevoked() }`
	const proseOnly = `package p
// FamilyRevoked is asked here.
func (h *H) IsRevoked() { h.read.IsRevoked() /* FamilyRevoked */ }`

	judged, seen := judgedSources(t, "with.go", withCall)
	require.True(t, seen)
	require.True(t, judged[sourceFamily])
	require.True(t, judged[sourceRecord])

	judged, seen = judgedSources(t, "prose.go", proseOnly)
	require.True(t, seen)
	require.False(t, judged[sourceFamily], "упоминание в прозе засчитано за вызов")
	require.True(t, judged[sourceRecord])
}

// TestIsRevokedContractGate_ReadsTheFieldNode — текст берётся с узла поля
// `IsRevokedResponse`, а не с одноимённого поля соседнего сообщения.
func TestIsRevokedContractGate_ReadsTheFieldNode(t *testing.T) {
	const stub = `package p
type Other struct {
	// Family row.
	Revoked bool
}
type IsRevokedResponse struct {
	// A row in the table.
	Revoked bool
}`
	texts := contractTexts(t, map[string]any{"stub.go": stub})
	require.Equal(t, "A row in the table.\n", texts[textRevoked])
	require.False(t, sourceMarker[sourceFamily].MatchString(texts[textRevoked]))
}
