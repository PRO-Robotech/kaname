// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"encoding/json"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

func TestRIDNewmanRID01SecretAdmission(t *testing.T) {
	for _, tc := range []struct {
		name, caseID, key string
		value             any
		extra             string
		want              bool
	}{
		{"old-C-exact-phase", rid01ExpiredAccessCase, "jwtRIDExpiredCreator", "old", "", true},
		{"current-C-exact-phase", rid01RenewedAccessCase, "jwtRIDCreator", "current", "", true},
		{"assertion-exact-phase", rid01ExpiredKeyCase, "rid01ClientAssertion", "assertion", "", true},
		{"old-C-missing", rid01ExpiredAccessCase, "", "", "", false},
		{"current-C-missing", rid01RenewedAccessCase, "", "", "", false},
		{"assertion-missing", rid01ExpiredKeyCase, "", "", "", false},
		{"old-C-empty", rid01ExpiredAccessCase, "jwtRIDExpiredCreator", "", "", false},
		{"current-C-wrong-type", rid01RenewedAccessCase, "jwtRIDCreator", 1, "", false},
		{"assertion-oversized", rid01ExpiredKeyCase, "rid01ClientAssertion", strings.Repeat("x", (16<<10)+1), "", false},
		{"old-C-wrong-phase", rid01RenewedAccessCase, "jwtRIDCreator", "current", "jwtRIDExpiredCreator", false},
		{"current-C-wrong-phase", rid01ExpiredAccessCase, "jwtRIDExpiredCreator", "old", "jwtRIDCreator", false},
		{"assertion-wrong-phase", rid01RenewedAccessCase, "jwtRIDCreator", "current", "rid01ClientAssertion", false},
		{"unknown-actor", rid01ExpiredKeyCase, "rid01ClientAssertion", "assertion", "jwtRIDOther", false},
		{"unlisted-RID01-case", "registry-installation-rid01-FORGED", "", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vars := map[string]any{"jwtRIDOperator": "O"}
			if tc.key != "" {
				vars[tc.key] = tc.value
			}
			if tc.extra != "" {
				vars[tc.extra] = "extra"
			}
			got, err := ridNewmanClientSecrets("registry-installation-rid01", tc.caseID, vars)
			if tc.want {
				require.NoError(t, err)
				require.Equal(t, []string{"O", tc.value.(string)}, got)
			} else {
				require.Error(t, err)
				require.Nil(t, got)
			}
		})
	}
}
func TestRIDNewmanOwnedRequestPolicy(t *testing.T) {
	for _, tc := range []struct {
		name, caseID, public, issuance, variable string
		want                                     bool
	}{
		{"primary-pair", rid01ExpiredKeyCase, "https://localhost:9098", "https://localhost:9096", "https://localhost:9096", true},
		{"second-pair", rid01ExpiredKeyCase, "https://127.0.0.1:9198", "https://127.0.0.1:9196", "https://127.0.0.1:9196", true},
		{"default-dynamic-port", "registry-installation-rid08-EMPTY-N0", "https://localhost:43217", "https://localhost:9096", "", true},
		{"token-dynamic-port-rejected", rid01ExpiredKeyCase, "https://localhost:43217", "https://localhost:9096", "https://localhost:9096", false},
		{"origin-without-port-rejected", "registry-installation-rid08-EMPTY-N0", "https://localhost", "https://localhost:9096", "", false},
		{"explicit-default443-rejected", "registry-installation-rid08-EMPTY-N0", "https://localhost:443", "https://localhost:9096", "", false},
		{"port-leading-zero-rejected", "registry-installation-rid08-EMPTY-N0", "https://localhost:043217", "https://localhost:9096", "", false},
		{"port-overflow-rejected", "registry-installation-rid08-EMPTY-N0", "https://localhost:65536", "https://localhost:9096", "", false},
		{"default-public-only", "registry-installation-rid08-EMPTY-N0", "https://localhost:9098", "https://localhost:9096", "", true},
		{"RID10-public-only", "registry-installation-rid10-FAULT-PARTIAL", "https://localhost:9098", "https://localhost:9096", "", true},
		{"wrong-phase-origin", rid01RenewedAccessCase, "https://localhost:9098", "https://localhost:9096", "https://localhost:9096", false},
		{"missing-variable", rid01ExpiredKeyCase, "https://localhost:9098", "https://localhost:9096", "", false},
		{"variable-forgery", rid01ExpiredKeyCase, "https://localhost:9098", "https://localhost:9096", "https://localhost:9097", false},
		{"wrong-host", rid01ExpiredKeyCase, "https://localhost:9098", "https://127.0.0.1:9096", "https://127.0.0.1:9096", false},
		{"wrong-pair", rid01ExpiredKeyCase, "https://localhost:9098", "https://localhost:9196", "https://localhost:9196", false},
		{"admin-port", rid01ExpiredKeyCase, "https://localhost:9098", "https://localhost:9097", "https://localhost:9097", false},
		{"public-wrong-port", rid01ExpiredKeyCase, "https://localhost:9097", "https://localhost:9096", "https://localhost:9096", false},
		{"nonloopback", rid01ExpiredKeyCase, "https://example.com:9098", "https://example.com:9096", "https://example.com:9096", false},
		{"http", rid01ExpiredKeyCase, "https://localhost:9098", "http://localhost:9096", "http://localhost:9096", false},
		{"credentials", rid01ExpiredKeyCase, "https://localhost:9098", "https://user:secret@localhost:9096", "https://user:secret@localhost:9096", false},
		{"origin-path", rid01ExpiredKeyCase, "https://localhost:9098", "https://localhost:9096/iam/v1/token", "https://localhost:9096/iam/v1/token", false},
		{"origin-query", rid01ExpiredKeyCase, "https://localhost:9098", "https://localhost:9096?q=1", "https://localhost:9096?q=1", false},
		{"origin-empty-query", rid01ExpiredKeyCase, "https://localhost:9098", "https://localhost:9096?", "https://localhost:9096?", false},
		{"origin-fragment", rid01ExpiredKeyCase, "https://localhost:9098", "https://localhost:9096#x", "https://localhost:9096#x", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vars := map[string]any{}
			if tc.variable != "" {
				vars["rid01IssuanceOrigin"] = tc.variable
			}
			p, err := ridNewmanParentRequestPolicy(tc.caseID, tc.public, tc.issuance, vars)
			if tc.want {
				require.NoError(t, err)
				require.NoError(t, ridNewmanValidateRequestPolicy(tc.caseID, tc.public, p, vars))
			} else {
				require.Error(t, err)
				require.Nil(t, p)
			}
		})
	}
}
func TestRIDNewmanClosedPolicyDecode(t *testing.T) {
	valid := `{"caseId":"registry-installation-rid01-EXPIRED-KEY-REFUSAL","requestName":"registry-installation-rid01-EXPIRED-KEY-REFUSAL :: expired-standing-key-token-refusal","method":"POST","path":"/iam/v1/token","origin":"https://localhost:9096"}`
	for _, tc := range []struct {
		name, raw string
		want      bool
	}{
		{"complete", valid, true}, {"absent", "", true}, {"null", "null", true},
		{"duplicate", strings.Replace(valid, `"method":"POST"`, `"method":"GET","method":"POST"`, 1), false},
		{"unknown-key", strings.TrimSuffix(valid, "}") + `,"extra":"x"}`, false},
		{"missing-key", strings.Replace(valid, `"method":"POST",`, "", 1), false},
		{"wrong-type", strings.Replace(valid, `"method":"POST"`, `"method":1`, 1), false},
		{"trailing", valid + " {}", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ridNewmanDecodeRequestPolicy(json.RawMessage(tc.raw))
			if tc.want {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
	for _, tc := range []struct{ name, field, value string }{
		{"wrong-case", "caseId", rid01RenewedAccessCase}, {"wrong-leaf", "requestName", "forged"}, {"wrong-method", "method", "GET"}, {"wrong-path", "path", "/iam/v1/me"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := map[string]string{}
			require.NoError(t, json.Unmarshal([]byte(valid), &raw))
			raw[tc.field] = tc.value
			b, err := json.Marshal(raw)
			require.NoError(t, err)
			p, err := ridNewmanDecodeRequestPolicy(b)
			require.NoError(t, err)
			require.Error(t, ridNewmanValidateRequestPolicy(rid01ExpiredKeyCase, "https://localhost:9098", p, map[string]any{"rid01IssuanceOrigin": "https://localhost:9096"}))
		})
	}
}
