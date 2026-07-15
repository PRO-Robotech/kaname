// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// usecase_registry_audience_test.go — verifies PRO-Robotech/kacho-iam#320:
// a registry ServiceAccount key issued WITHOUT an explicit `audience` must
// still let `docker login` work. The `/iam/token` shim requests
// `audience=<registry service>` from Hydra during the client_credentials
// exchange; Hydra rejects that exchange unless the SA-key's OAuth2 client
// whitelists that audience. So SA-key issuance MUST ALWAYS include the
// configured registry service audience in the Hydra client's `audience`
// whitelist — in addition to the default kacho-internal audience and any
// caller-supplied audience (union, deduplicated).
//
// RED-then-GREEN, test-first: these fail without the RegistryAudience field +
// its union into resolveAudience, and pass once that lands.
package sa_keys

import (
	"context"
	"testing"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
)

const testRegistryAud = "registry.kacho.local"

func containsStr(hay []string, needle string) bool {
	for _, s := range hay {
		if s == needle {
			return true
		}
	}
	return false
}

func countStr(hay []string, needle string) int {
	n := 0
	for _, s := range hay {
		if s == needle {
			n++
		}
	}
	return n
}

// TestResolveAudience_AlwaysIncludesRegistryAudience — the configured registry
// service audience is ALWAYS whitelisted, regardless of caller input, and never
// duplicated.
func TestResolveAudience_AlwaysIncludesRegistryAudience(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name           string
		audiencePrefix string
		registryAud    string
		in             IssueInput
		wantContains   []string
		wantAbsent     []string
	}{
		{
			name:           "caller omits audience → internal default + registry audience",
			audiencePrefix: "kacho:iam:",
			registryAud:    testRegistryAud,
			in:             IssueInput{ServiceAccountID: "sva_docker"},
			wantContains:   []string{"kacho:iam:/sa/sva_docker", testRegistryAud},
		},
		{
			name:           "caller-supplied audience is unioned with registry audience",
			audiencePrefix: "kacho:iam:",
			registryAud:    testRegistryAud,
			in: IssueInput{
				ServiceAccountID: "sva_ext",
				Audience:         []string{"sts.example.com"},
			},
			wantContains: []string{"sts.example.com", testRegistryAud},
		},
		{
			name:           "registry audience already supplied by caller → no duplicate",
			audiencePrefix: "kacho:iam:",
			registryAud:    testRegistryAud,
			in: IssueInput{
				ServiceAccountID: "sva_ext",
				Audience:         []string{testRegistryAud, "sts.example.com"},
			},
			wantContains: []string{"sts.example.com", testRegistryAud},
		},
		{
			name:           "no prefix, no caller audience → registry audience only",
			audiencePrefix: "",
			registryAud:    testRegistryAud,
			in:             IssueInput{ServiceAccountID: "sva_docker"},
			wantContains:   []string{testRegistryAud},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			u := &IssueSAKeyUseCase{AudiencePrefix: tc.audiencePrefix, RegistryAudience: tc.registryAud}
			got := u.resolveAudience(tc.in)
			for _, want := range tc.wantContains {
				if !containsStr(got, want) {
					t.Errorf("resolveAudience(%+v) = %v, want to contain %q", tc.in, got, want)
				}
				if n := countStr(got, want); n > 1 {
					t.Errorf("resolveAudience(%+v) = %v, %q appears %d times (must be deduplicated)", tc.in, got, want, n)
				}
			}
			for _, absent := range tc.wantAbsent {
				if containsStr(got, absent) {
					t.Errorf("resolveAudience(%+v) = %v, must NOT contain %q", tc.in, got, absent)
				}
			}
		})
	}
}

// TestIssue_PrivateKeyJWT_WhitelistsRegistryAudienceByDefault — end-to-end
// through Execute: when the caller omits `audience`, the Hydra CreateOAuthClient
// request MUST whitelist the configured registry service audience so a
// docker/registry SA-key works out of the box (#320). The internal default
// audience is still present alongside it (union), and the response echoes the
// resolved list.
func TestIssue_PrivateKeyJWT_WhitelistsRegistryAudienceByDefault(t *testing.T) {
	repo := &stubSAClientRepo{}
	hydra := &stubHydra{}
	ops := &stubOpsRepo{}
	u := NewIssueSAKeyUseCase(repo, &stubTx{}, hydra, ops)
	u.AudiencePrefix = "https://internal.example/iam"
	u.RegistryAudience = testRegistryAud

	_, err := u.Execute(context.Background(), IssueInput{
		ServiceAccountID: "sva_docker",
		CreatedByUserID:  "usr_admin",
		// No Audience — the docker/registry use-case that triggered #320.
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	waitForOp(t, ops)

	if !hydra.created {
		t.Fatal("Hydra CreateOAuthClient never called")
	}
	if !containsStr(hydra.gotReq.Audience, testRegistryAud) {
		t.Fatalf("Hydra audience = %v, want to contain registry audience %q (#320: docker login fails without it)",
			hydra.gotReq.Audience, testRegistryAud)
	}
	if !containsStr(hydra.gotReq.Audience, "https://internal.example/iam/sa/sva_docker") {
		t.Errorf("Hydra audience = %v, must still contain the kacho-internal default", hydra.gotReq.Audience)
	}

	resp := &iamv1.IssueSAKeyResponse{}
	if err := anyUnmarshalTo(ops.lastResp, resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !containsStr(resp.Audiences, testRegistryAud) {
		t.Errorf("Response.Audiences = %v, want to echo the registry audience %q", resp.Audiences, testRegistryAud)
	}
}
