// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// subject_proto_derive_test.go — Design-B (flat-authz verb-bearing complete)
// acceptance VBC-16 (subject id-prefix derive, #243). When a binding-Create
// request carries SUBJECT_TYPE_UNSPECIFIED (protojson DiscardUnknown drops a
// lowercase `"type":"user"` to the zero enum on the UI flow), subjectsFromProto
// derives the subject type from the id prefix:
//   usr… → user, sva… → service_account, grp… → group.
// An explicit (non-UNSPECIFIED) enum always wins over the derive. An
// unrecognized prefix (or empty id) leaves the type "" so the domain validator
// rejects it (no validation weakening).
//
// RED until subjectsFromProto derives the type from the id prefix.

import (
	"testing"

	"github.com/stretchr/testify/require"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

func TestSubjectsFromProto_VBC16_DerivePrefix(t *testing.T) {
	cases := []struct {
		name string
		in   *iamv1.Subject
		want domain.SubjectType
	}{
		{
			name: "unspecified + usr prefix → user",
			in:   &iamv1.Subject{Type: iamv1.SubjectType_SUBJECT_TYPE_UNSPECIFIED, Id: "usr_abc123"},
			want: domain.SubjectTypeUser,
		},
		{
			name: "unspecified + sva prefix → service_account",
			in:   &iamv1.Subject{Type: iamv1.SubjectType_SUBJECT_TYPE_UNSPECIFIED, Id: "sva_abc123"},
			want: domain.SubjectTypeServiceAccount,
		},
		{
			name: "unspecified + grp prefix → group",
			in:   &iamv1.Subject{Type: iamv1.SubjectType_SUBJECT_TYPE_UNSPECIFIED, Id: "grp_abc123"},
			want: domain.SubjectTypeGroup,
		},
		{
			name: "explicit USER enum wins over a mismatched id prefix",
			in:   &iamv1.Subject{Type: iamv1.SubjectType_SUBJECT_TYPE_USER, Id: "sva_abc123"},
			want: domain.SubjectTypeUser,
		},
		{
			name: "unspecified + unknown prefix → empty (validator rejects)",
			in:   &iamv1.Subject{Type: iamv1.SubjectType_SUBJECT_TYPE_UNSPECIFIED, Id: "rol_bad"},
			want: domain.SubjectType(""),
		},
		{
			name: "unspecified + empty id → empty (validator rejects)",
			in:   &iamv1.Subject{Type: iamv1.SubjectType_SUBJECT_TYPE_UNSPECIFIED, Id: ""},
			want: domain.SubjectType(""),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := subjectsFromProto([]*iamv1.Subject{tc.in})
			require.Len(t, out, 1)
			require.Equal(t, tc.want, out[0].Type,
				"VBC-16: derived subject type for id %q", tc.in.GetId())
			require.Equal(t, domain.SubjectID(tc.in.GetId()), out[0].ID)
		})
	}
}
