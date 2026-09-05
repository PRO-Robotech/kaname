// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// list_filter_operator_test.go — #460. The filter grammar carries an OPERATOR
// (`=` and `CONTAINS`), and this resource compares exact identifiers: subject,
// role, scope and scopeId are ids, not prose. There is no substring of an id.
//
// Before the fix parseABListFilter took `ast.Value` and dropped `ast.Op`, so
// `subject CONTAINS "usr"` was accepted and answered as `subject = "usr"` — a
// confidently wrong answer: the caller asked for every binding whose subject
// contains "usr" and got back only the one binding whose subject IS "usr",
// with a 200. api-conventions.md §"Принято-и-проигнорировано — ЗАПРЕЩЕНО" allows
// three outcomes — implement, refuse by name, drop from the contract — and
// silently answering something else is not among them.

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
)

// TestABList_460_ContainsRefusedByName — CONTAINS is refused on every whitelisted
// key, and the refusal NAMES the operator: a caller who reads "invalid filter" and
// nothing else cannot tell which token the server would not honour.
func TestABList_460_ContainsRefusedByName(t *testing.T) {
	for _, field := range abListFilterFields {
		t.Run(field+" CONTAINS refused", func(t *testing.T) {
			repo := newABFakeRepo("usr_o", "acc_l460", "", "rol_v", "kacho.view", nil)
			fga := newABQueriesStub()
			h := newListHandler(repo, fga)

			_, err := h.List(newOwnerContext("usr_x"),
				&iamv1.ListAccessBindingsRequest{Filter: field + ` CONTAINS "usr"`})

			require.Error(t, err, "CONTAINS on %q must be refused, not answered as equality", field)
			st, _ := status.FromError(err)
			assert.Equal(t, codes.InvalidArgument, st.Code())
			assert.Contains(t, st.Message(), "CONTAINS",
				"the refusal must name the operator it will not honour")
			assert.Contains(t, st.Message(), field,
				"the refusal must name the field the operator was used on")
		})
	}
}

// TestABList_460_EqualsStillHonoured — the PAIRED positive control. Without it the
// test above stays green on a parser that refuses every filter, including the one
// this resource does support.
func TestABList_460_EqualsStillHonoured(t *testing.T) {
	repo := newABFakeRepo("usr_o", "acc_l460b", "", "rol_v", "kacho.view", nil)
	fga := newABQueriesStub()
	h := newListHandler(repo, fga)

	_, err := h.List(newOwnerContext("usr_x"),
		&iamv1.ListAccessBindingsRequest{Filter: `subject="usr-42"`})
	require.NoError(t, err, "= is the operator this resource supports and must keep working")
	assert.Equal(t, "usr-42", repo.lastListFilter.SubjectID)
}

// TestABList_460_ContainsNeverReachesTheRepo — the refusal happens BEFORE the page
// is read, so no request answers a substring question with an equality page. The
// assertion above is about the caller's error; this one is about the repo never
// having been asked the wrong question.
func TestABList_460_ContainsNeverReachesTheRepo(t *testing.T) {
	repo := newABFakeRepo("usr_o", "acc_l460c", "", "rol_v", "kacho.view", nil)
	fga := newABQueriesStub()
	h := newListHandler(repo, fga)

	_, err := h.List(newOwnerContext("usr_x"),
		&iamv1.ListAccessBindingsRequest{Filter: `subject CONTAINS "usr"`})
	require.Error(t, err)
	assert.Empty(t, repo.lastListFilter.SubjectID,
		"a refused filter must not reach the repo as an equality predicate")
	if msg := status.Convert(err).Message(); strings.Contains(msg, "internal") {
		t.Fatalf("refusal message %q must state the contract, not an internal fault", msg)
	}
}
