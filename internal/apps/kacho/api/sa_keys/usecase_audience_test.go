// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Phase 3c — Federation OUT unit tests for IssueSAKeyUseCase.resolveAudience.
//
// The use-case must:
//   - prefer caller-supplied Audience verbatim (preserving order, dropping
//     empty + duplicates) when non-empty;
//   - fall back to "<AudiencePrefix>/sa/<svaID>" when caller omits audience
//     and prefix is configured;
//   - return nil when both are empty (Hydra mints `aud`-less tokens).
package sa_keys

import (
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

func TestResolveAudience(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name           string
		audiencePrefix string
		in             IssueInput
		want           []string
	}{
		{
			name:           "external audience verbatim",
			audiencePrefix: "kacho:iam:",
			in: IssueInput{
				ServiceAccountID: "sva_abc",
				Audience:         []string{"sts.example.com"},
			},
			want: []string{"sts.example.com"},
		},
		{
			name:           "multi-audience preserves order",
			audiencePrefix: "kacho:iam:",
			in: IssueInput{
				ServiceAccountID: "sva_abc",
				Audience: []string{
					"sts.example.com",
					"//idp.example.com/pools/p/providers/x",
					"api://acme-prod",
				},
			},
			want: []string{
				"sts.example.com",
				"//idp.example.com/pools/p/providers/x",
				"api://acme-prod",
			},
		},
		{
			name:           "dedup + empty drop",
			audiencePrefix: "kacho:iam:",
			in: IssueInput{
				ServiceAccountID: "sva_abc",
				Audience:         []string{"sts.example.com", "", "sts.example.com", "api://x"},
			},
			want: []string{"sts.example.com", "api://x"},
		},
		{
			name:           "fallback to internal prefix when caller omits audience",
			audiencePrefix: "kacho:iam:",
			in: IssueInput{
				ServiceAccountID: "sva_xyz",
			},
			want: []string{"kacho:iam:/sa/sva_xyz"},
		},
		{
			name:           "fallback also trims trailing slashes from prefix",
			audiencePrefix: "kacho:iam:////",
			in: IssueInput{
				ServiceAccountID: "sva_xyz",
			},
			want: []string{"kacho:iam:/sa/sva_xyz"},
		},
		{
			name:           "no prefix + no audience → nil",
			audiencePrefix: "",
			in: IssueInput{
				ServiceAccountID: "sva_abc",
			},
			want: nil,
		},
		{
			name:           "audience containing only empty entries → fallback",
			audiencePrefix: "kacho:iam:",
			in: IssueInput{
				ServiceAccountID: "sva_abc",
				Audience:         []string{"", ""},
			},
			want: []string{"kacho:iam:/sa/sva_abc"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			u := &IssueSAKeyUseCase{AudiencePrefix: tc.audiencePrefix}
			got := u.resolveAudience(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("len mismatch: got %d (%v) want %d (%v)", len(got), got, len(tc.want), tc.want)
			}
			for i, g := range got {
				if g != tc.want[i] {
					t.Fatalf("[%d]: got %q want %q", i, g, tc.want[i])
				}
			}
		})
	}
}

// TestResolveAudienceFederatedPath — federated mode passes through the same
// resolution; trusted_subjects do not override audience semantics.
func TestResolveAudienceFederatedPath(t *testing.T) {
	t.Parallel()
	u := &IssueSAKeyUseCase{AudiencePrefix: "kacho:iam:"}
	in := IssueInput{
		ServiceAccountID: "sva_fed",
		TrustedSubjects: []domain.TrustedSubject{{
			Issuer:         "https://token.actions.githubusercontent.com",
			SubjectPattern: "^repo:acme/infra:ref:refs/heads/main$",
		}},
		Audience: []string{"sts.example.com"},
	}
	got := u.resolveAudience(in)
	if len(got) != 1 || got[0] != "sts.example.com" {
		t.Fatalf("federated audience leak: got %v want [sts.example.com]", got)
	}
}
