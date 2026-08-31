// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// provider_hops_test.go — a census of every address iam is given for the identity
// provider, and of the transport each one is given it over.
//
// WHY A CENSUS AND NOT THREE ASSERTIONS. The defect this is written against is not
// "one address was wrong". It is that the facade has THREE hops to the provider,
// one of them was moved to a declared, encrypted, anchored form with a boot guard
// and a gate, and the other two were measured by nobody — so the class read as
// closed while half of it was live. A per-hop assertion reproduces exactly that:
// the next hop added inherits the blind spot. This reads the whole set, states how
// many it examined, and refuses to be silent about a member it has nothing to say
// about.
//
// WHY IT READS DECLARATIONS. Same reason as its neighbour
// gateway/deploy/admin_hop_transport_test.go: the contract is what the profiles
// DECLARE, it needs no chart dependencies, and it therefore can never skip. A
// render-based check is skipped on every machine that has not run `helm dep
// build` — which is exactly when it would be needed.
//
// WHAT IT ASSERTS, per production-class stack:
//
//	(1) every hop's address is DECLARED, never left to iam's derivation from the
//	    issuer. Production refuses to start otherwise
//	    (config.validateProductionProviderAdminHop /
//	    validateProductionProviderPublicHops); this gate is what keeps that refusal
//	    from being discovered on a stand.
//	(2) an address declared https carries its trust anchor. Without one the process
//	    verifies against the system roots, which an internal-CA certificate never
//	    chains to: the address reads as hardened and every call fails.
//	(3) an address declared http is a member of plaintextPendingProviderTLS below —
//	    and every member of that register still has a plaintext address to excuse.
//	    An entry with nothing left to excuse is a FINDING, not a leftover: that is
//	    how a stale exemption outlives the fix it was written for and starts
//	    exempting the hop that just regressed.
package deploy_test

import (
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// stacks — the `-f` chains the stands are actually rolled with, in order. Kept in
// step with deploy/Makefile and helm/umbrella/cutover-fe3455.sh, and identical to
// the table in gateway/deploy/revocation_endpoint_test.go.
var stacks = map[string][]string{
	"dev":         {"values.dev.yaml"},
	"dev-prod":    {"values.dev.yaml", "values.dev-prod.yaml"},
	"prod":        {"values.prod.yaml"},
	"fe3455":      {"values.prod.yaml", "values.fe3455.yaml", "values.fe3455-prod.yaml"},
	"prorobotech": {"values.dev.yaml", "values.prorobotech.yaml"},
}

// hop — one address iam dials on the provider, with the anchor that goes with it.
//
// Each address has TWO spellings an operator may use, and both count as declared
// because iam reads both: the chart knob and the raw environment entry the knob
// renders to. dev-prod declares its JWKS upstream the second way; a gate that only
// knew the first would have called that stack underconfigured and been ignored.
type hop struct {
	name      string
	knob      []string // path under the merged umbrella tree
	env       string   // raw env spelling under kacho-iam.env
	anchor    []string // path to the trust-anchor knob
	anchorEnv string
}

var providerHops = []hop{
	{
		name:      "admin API",
		knob:      []string{"kacho-iam", "kacho", "iam", "hydraAdminUrl"},
		env:       "KACHO_IAM_HYDRA_ADMIN_URL",
		anchor:    []string{"kacho-iam", "kacho", "iam", "hydraAdminCaFile"},
		anchorEnv: "KACHO_IAM_HYDRA_ADMIN_CA_FILE",
	},
	{
		name:      "JWKS upstream",
		knob:      []string{"kacho-iam", "kacho", "iam", "hydraJwksUrl"},
		env:       "KACHO_IAM_HYDRA_JWKS_URL",
		anchor:    []string{"kacho-iam", "kacho", "iam", "hydraJwksCaFile"},
		anchorEnv: "KACHO_IAM_HYDRA_JWKS_CA_FILE",
	},
	{
		name:      "token endpoint",
		knob:      []string{"kacho-iam", "kacho", "iam", "hydraTokenURL"},
		env:       "KACHO_IAM_HYDRA_TOKEN_URL",
		anchor:    []string{"kacho-iam", "kacho", "iam", "hydraTokenCaFile"},
		anchorEnv: "KACHO_IAM_HYDRA_TOKEN_CA_FILE",
	},
}

// plaintextPendingProviderTLS — the hops still addressed in the clear, and the one
// reason they are.
//
// The provider serves its PUBLIC listener without TLS on every profile. That is
// not a knob left unticked: the per-listener override was MEASURED absent on
// 2026-07-30 (deploy/helm/umbrella/templates/hydra-admin-certificate.yaml records
// the measurement), so the shared serve.tls has to move — and it moves the
// ingress, this mirror and the token endpoint together, ≥6 coupled addresses. That
// is its own change with its own acceptance, not something to smuggle in beside a
// boot guard.
//
// The admin API is deliberately NOT a member: it is required to be https, and it
// is, on every production-class profile.
//
// This register is written to expire. It is asserted in both directions below, so
// the day the public listener gets a certificate the entry stops having a subject
// and the gate turns red until it is deleted.
var plaintextPendingProviderTLS = map[string]string{
	"JWKS upstream":  "the provider's public listener has no TLS; moving it is the shared-serve.tls change",
	"token endpoint": "the provider's public listener has no TLS; moving it is the shared-serve.tls change",
}

func TestStacks_ProviderHopsAreDeclaredAndTheirTransportIsAccountedFor(t *testing.T) {
	examinedStacks, examinedHops := 0, 0
	plaintextSeen := map[string]bool{}

	names := make([]string, 0, len(stacks))
	for name := range stacks {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		stack := stacks[name]
		t.Run(name, func(t *testing.T) {
			merged := mergeProfiles(t, stack)
			if !isProductionClass(merged) {
				t.Skipf("%s is dev-class by its own declaration (kacho-iam.authMode) — "+
					"the requirement rides the same exemption as iam's boot guard", name)
			}
			examinedStacks++
			for _, h := range providerHops {
				examinedHops++
				addr, ok := declaredAddress(merged, h)
				if !ok {
					t.Errorf("%s: the %s address is not declared (neither %s nor env %s) — iam then "+
						"DERIVES it from the issuer, which names the public ingress host and does not "+
						"resolve inside the cluster; the derivation is never empty, so the facade reads "+
						"as configured while addressing a host nobody chose, and a production-class iam "+
						"refuses to start", name, h.name, strings.Join(h.knob, "."), h.env)
					continue
				}
				u, err := url.Parse(addr)
				if err != nil || u.Scheme == "" || u.Host == "" {
					t.Errorf("%s: the %s address %q is not an absolute http(s) URL", name, h.name, addr)
					continue
				}
				switch u.Scheme {
				case "https":
					if _, ok := declaredAnchor(merged, h); !ok {
						t.Errorf("%s: the %s address is https (%q) but no anchor is declared "+
							"(neither %s nor env %s) — the provider's in-cluster certificate is issued "+
							"by the internal CA and iam trusts the system roots, so every call on the "+
							"hop fails with an unknown authority while the address reads as hardened",
							name, h.name, addr, strings.Join(h.anchor, "."), h.anchorEnv)
					}
				case "http":
					plaintextSeen[h.name] = true
					if _, allowed := plaintextPendingProviderTLS[h.name]; !allowed {
						t.Errorf("%s: the %s address is in the clear (%q) and is not one of the hops "+
							"pending the provider's public-listener TLS change — a credential or a "+
							"verification anchor on this hop is readable by anything on the path",
							name, h.name, addr)
					}
				default:
					t.Errorf("%s: the %s address has scheme %q, want http or https", name, h.name, u.Scheme)
				}
			}
		})
	}

	// An exemption lives only while it has something to exempt.
	for hopName := range plaintextPendingProviderTLS {
		if !plaintextSeen[hopName] {
			t.Errorf("plaintextPendingProviderTLS still lists %q, but no production-class stack "+
				"addresses it in the clear any more — delete the entry. A register that outlives its "+
				"subject silently exempts whatever regresses into it next", hopName)
		}
	}

	// "Nothing wrong" must be distinguishable from "nothing read".
	if examinedStacks == 0 {
		t.Fatal("no production-class stack was examined — the census read nothing and would " +
			"report success no matter what the profiles say")
	}
	t.Logf("census: %d production-class stacks × %d provider hops = %d declarations examined",
		examinedStacks, len(providerHops), examinedHops)
}

// ── profile reading ──────────────────────────────────────────────────────────

func umbrellaProfile(t *testing.T, profile string) map[string]any {
	t.Helper()
	path := filepath.Join("..", "..", "..", "deploy", "helm", "umbrella", profile)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var tree map[string]any
	if err := yaml.Unmarshal(raw, &tree); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return tree
}

// mergeProfiles overlays the profiles the way helm does: maps merge key by key,
// anything else replaces wholesale.
func mergeProfiles(t *testing.T, stack []string) map[string]any {
	t.Helper()
	merged := map[string]any{}
	for _, profile := range stack {
		merged = mergeInto(merged, umbrellaProfile(t, profile))
	}
	return merged
}

func mergeInto(dst, src map[string]any) map[string]any {
	if dst == nil {
		dst = map[string]any{}
	}
	for k, v := range src {
		if sub, ok := v.(map[string]any); ok {
			if cur, ok := dst[k].(map[string]any); ok {
				dst[k] = mergeInto(cur, sub)
				continue
			}
		}
		dst[k] = v
	}
	return dst
}

func stringAt(tree map[string]any, path ...string) (string, bool) {
	var cur any = tree
	for _, key := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return "", false
		}
		if cur, ok = m[key]; !ok {
			return "", false
		}
	}
	s, ok := cur.(string)
	return strings.TrimSpace(s), ok && strings.TrimSpace(s) != ""
}

// declaredAddress / declaredAnchor accept either spelling, because iam does.
func declaredAddress(tree map[string]any, h hop) (string, bool) {
	if v, ok := stringAt(tree, h.knob...); ok {
		return v, true
	}
	return stringAt(tree, "kacho-iam", "env", h.env)
}

func declaredAnchor(tree map[string]any, h hop) (string, bool) {
	if v, ok := stringAt(tree, h.anchor...); ok {
		return v, true
	}
	return stringAt(tree, "kacho-iam", "env", h.anchorEnv)
}

// isProductionClass reads what the stack declares about ITSELF, rather than
// matching a hard-coded list of stand names: a stale list goes quiet the moment a
// stand changes posture, and then exempts the very stack that just started needing
// the check.
func isProductionClass(tree map[string]any) bool {
	return strings.HasPrefix(declaredPosture(tree), "production")
}

// declaredPosture — посадка, объявленная стеком о САМОМ СЕБЕ.
//
// Адрес канонический — `kacho-iam.authMode` в корне значений сервиса. Прежний
// (`config.authn.mode`) читается следом и ровно потому, что шаблон чарта его тоже
// пока принимает: стек, оставшийся на нём, обязан проверяться, а не выпадать из
// проверки молча.
//
// Порядок здесь несущий, и вот чем он оплачен: когда адрес свели к одному
// написанию, а этот отбор остался на прежнем, ни один стек не опознался боевым —
// все шесть ушли в Skip, перепись прочитала НОЛЬ, и проверка отчиталась бы
// успехом при любом содержимом профилей. Отбор по ключу, который переехал, не
// краснеет: он тихо перестаёт находить предмет.
func declaredPosture(tree map[string]any) string {
	if v, ok := stringAt(tree, "kacho-iam", "authMode"); ok {
		return v
	}
	v, _ := stringAt(tree, "kacho-iam", "config", "authn", "mode")
	return v
}
