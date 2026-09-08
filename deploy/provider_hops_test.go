// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

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
// WHERE THE STACKS COME FROM. This directory is shipped: it is `services/iam/
// deploy/` in the monorepo and `deploy/` in the published product, and BOTH trees
// run this file. So the sources are read from the tree rather than named by a
// fixed count of `..` (see tree_root_test.go for why counting is wrong here):
//
//	chart      the chart's own profiles, beside this file — present in both trees,
//	           and the ones an operator outside our cloud actually rolls with;
//	umbrella   our stand's `-f` chains, under the monorepo root — present only
//	           where the monorepo is.
//
// The two differ by exactly one path segment: the umbrella keeps the service
// behind the subchart alias `kaname`, the chart keeps the same knobs at the root
// of its own document. That segment is the source's prefix, not part of the hop.
// The census prints how many sources it found; a source that yields no
// production-class stack is a FINDING, because that is precisely the shape this
// file had while its paths pointed outside the repository and it read nothing.
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
//	    exempting the hop that just regressed. The register describes OUR stand, so
//	    it is asserted over the umbrella source and only where that source is —
//	    plaintext anywhere else is a finding with no exemption available at all.
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

// profileSource — one place this tree keeps `-f` chains for iam, and the prefix
// its knobs sit behind.
//
// WHY TWO SOURCES AND NOT ONE TABLE. The same chart is installed two ways, and the
// knob paths differ by exactly one segment:
//
//	as a subchart of our umbrella   kaname.kacho.iam.hydraAdminUrl
//	standalone, as shipped          kacho.iam.hydraAdminUrl
//
// The census used to read only the first, addressed as `../../../deploy/helm/
// umbrella/...` — a path that exists in the monorepo and nowhere else. In the
// published artifact the helper aborted on the first profile, so the whole census
// read NOTHING while the register below still claimed two live exemptions. The
// probe travelled; its subject did not.
//
// The chart's own profiles are the source that exists in BOTH trees, and they are
// the ones an operator outside our cloud actually rolls with. The umbrella is
// ours, and it is read whenever it is there.
type profileSource struct {
	label string
	dir   string
	// prefix — where this source keeps the service's own values tree. Empty for
	// the chart's own profiles: there the service IS the root of the document.
	prefix []string
	// chains — the `-f` chains, in order. The chart's own profiles always layer
	// on values.yaml, because helm does.
	chains map[string][]string
	// carriesPlaintextRegister — this source is the one plaintextPendingProviderTLS
	// below describes. See the register's own comment for why it is our stand and
	// not the shipped chart.
	carriesPlaintextRegister bool
}

// umbrellaChains — the `-f` chains our stands are actually rolled with, in order.
// Kept in step with deploy/Makefile and helm/umbrella/cutover-fe3455.sh, and
// identical to the table in gateway/deploy/revocation_endpoint_test.go.
var umbrellaChains = map[string][]string{
	"dev":         {"values.dev.yaml"},
	"dev-prod":    {"values.dev.yaml", "values.dev-prod.yaml"},
	"prod":        {"values.prod.yaml"},
	"fe3455":      {"values.prod.yaml", "values.fe3455.yaml", "values.fe3455-prod.yaml"},
	"prorobotech": {"values.dev.yaml", "values.prorobotech.yaml"},
}

// chartChains — the `-f` chains the shipped chart itself offers. `values.yaml` is
// named first in every chain because helm merges it first whether or not anybody
// passes it.
var chartChains = map[string][]string{
	"dev":  {"values.yaml", "values.dev.yaml"},
	"prod": {"values.yaml", "values.prod.yaml"},
}

// profileSources reads the tree and says which sources it actually has.
//
// The roots are found by CLIMBING to the module marker, never by counting `..`
// (see tree_root_test.go): this directory sits at a different depth in the two
// trees, and a fixed count is correct in one of them and points outside the
// repository in the other.
func profileSources(t *testing.T) []profileSource {
	t.Helper()
	sources := []profileSource{{
		label:  "chart",
		dir:    filepath.Join(serviceRoot(t), "deploy"),
		prefix: nil,
		chains: chartChains,
	}}

	umbrella := filepath.Join(outerRoot(t), "deploy", "helm", "umbrella")
	if st, err := os.Stat(umbrella); err == nil && st.IsDir() {
		sources = append(sources, profileSource{
			label:                    "umbrella",
			dir:                      umbrella,
			prefix:                   []string{"kaname"},
			chains:                   umbrellaChains,
			carriesPlaintextRegister: true,
		})
	}
	return sources
}

// hop — one address iam dials on the provider, with the anchor that goes with it.
//
// Each address has TWO spellings an operator may use, and both count as declared
// because iam reads both: the chart knob and the raw environment entry the knob
// renders to. dev-prod declares its JWKS upstream the second way; a gate that only
// knew the first would have called that stack underconfigured and been ignored.
type hop struct {
	name string
	// knob / anchor — paths under the SERVICE's own values tree. A source that
	// keeps the service behind an alias (our umbrella does) prepends its prefix;
	// the shipped chart keeps the same knobs at the root of its document.
	knob      []string
	env       string // raw env spelling under the service's `env`
	anchor    []string
	anchorEnv string
}

var providerHops = []hop{
	{
		name:      "admin API",
		knob:      []string{"kacho", "iam", "hydraAdminUrl"},
		env:       "KANAME_HYDRA_ADMIN_URL",
		anchor:    []string{"kacho", "iam", "hydraAdminCaFile"},
		anchorEnv: "KANAME_HYDRA_ADMIN_CA_FILE",
	},
	{
		name:      "JWKS upstream",
		knob:      []string{"kacho", "iam", "hydraJwksUrl"},
		env:       "KANAME_HYDRA_JWKS_URL",
		anchor:    []string{"kacho", "iam", "hydraJwksCaFile"},
		anchorEnv: "KANAME_HYDRA_JWKS_CA_FILE",
	},
	{
		name:      "token endpoint",
		knob:      []string{"kacho", "iam", "hydraTokenURL"},
		env:       "KANAME_HYDRA_TOKEN_URL",
		anchor:    []string{"kacho", "iam", "hydraTokenCaFile"},
		anchorEnv: "KANAME_HYDRA_TOKEN_CA_FILE",
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
//
// ITS SUBJECT IS OUR UMBRELLA, AND ONLY THAT. The shipped chart carries no
// provider at all — whoever installs brings their own — so its own values.prod.yaml
// addresses all three hops over https with a pinned anchor and takes no exemption
// (values.prod.yaml says so in as many words). The expiry check therefore runs
// over the umbrella source, and whether that source is present is READ FROM THE
// TREE and printed in the census, never assumed: in a clone that has no umbrella
// the register has nothing to expire, and asserting it there would turn a probe
// red on the absence of our stand rather than on any defect of the product.
var plaintextPendingProviderTLS = map[string]string{
	"JWKS upstream":  "the provider's public listener has no TLS; moving it is the shared-serve.tls change",
	"token endpoint": "the provider's public listener has no TLS; moving it is the shared-serve.tls change",
}

func TestStacks_ProviderHopsAreDeclaredAndTheirTransportIsAccountedFor(t *testing.T) {
	sources := profileSources(t)

	examinedStacks, examinedHops := 0, 0
	plaintextSeen := map[string]bool{}
	registerSource := ""

	for _, src := range sources {
		perSource := 0
		t.Run(src.label, func(t *testing.T) {
			names := make([]string, 0, len(src.chains))
			for name := range src.chains {
				names = append(names, name)
			}
			sort.Strings(names)

			for _, name := range names {
				chain := src.chains[name]
				t.Run(name, func(t *testing.T) {
					merged := mergeProfiles(t, src, chain)
					if !isProductionClass(merged, src.prefix) {
						t.Skipf("%s/%s is dev-class by its own declaration (authMode) — "+
							"the requirement rides the same exemption as iam's boot guard", src.label, name)
					}
					examinedStacks++
					perSource++
					for _, h := range providerHops {
						examinedHops++
						addr, ok := declaredAddress(merged, src.prefix, h)
						if !ok {
							t.Errorf("%s/%s: the %s address is not declared (neither %s nor env %s) — iam then "+
								"DERIVES it from the issuer, which names the public ingress host and does not "+
								"resolve inside the cluster; the derivation is never empty, so the facade reads "+
								"as configured while addressing a host nobody chose, and a production-class iam "+
								"refuses to start", src.label, name, h.name,
								strings.Join(append(append([]string{}, src.prefix...), h.knob...), "."), h.env)
							continue
						}
						u, err := url.Parse(addr)
						if err != nil || u.Scheme == "" || u.Host == "" {
							t.Errorf("%s/%s: the %s address %q is not an absolute http(s) URL", src.label, name, h.name, addr)
							continue
						}
						switch u.Scheme {
						case "https":
							if _, ok := declaredAnchor(merged, src.prefix, h); !ok {
								t.Errorf("%s/%s: the %s address is https (%q) but no anchor is declared "+
									"(neither %s nor env %s) — the provider's in-cluster certificate is issued "+
									"by the internal CA and iam trusts the system roots, so every call on the "+
									"hop fails with an unknown authority while the address reads as hardened",
									src.label, name, h.name, addr,
									strings.Join(append(append([]string{}, src.prefix...), h.anchor...), "."), h.anchorEnv)
							}
						case "http":
							if src.carriesPlaintextRegister {
								plaintextSeen[h.name] = true
							}
							if _, allowed := plaintextPendingProviderTLS[h.name]; !allowed || !src.carriesPlaintextRegister {
								t.Errorf("%s/%s: the %s address is in the clear (%q) and is not one of the hops "+
									"pending the provider's public-listener TLS change — a credential or a "+
									"verification anchor on this hop is readable by anything on the path",
									src.label, name, h.name, addr)
							}
						default:
							t.Errorf("%s/%s: the %s address has scheme %q, want http or https", src.label, name, h.name, u.Scheme)
						}
					}
				})
			}
		})

		// A source that declares chains and yields no production-class stack read
		// nothing this census can judge. That is not "clean": it is the shape the
		// probe had when its paths pointed outside the repository.
		if perSource == 0 {
			t.Errorf("source %q (%s) declared %d chains and none of them came out production-class — "+
				"the census read nothing here and would report success no matter what these profiles say",
				src.label, src.dir, len(src.chains))
		}
		if src.carriesPlaintextRegister {
			registerSource = src.label
		}
	}

	// An exemption lives only while it has something to exempt — asserted over the
	// source whose subject it describes, and only when that source is in the tree.
	if registerSource != "" {
		for hopName := range plaintextPendingProviderTLS {
			if !plaintextSeen[hopName] {
				t.Errorf("plaintextPendingProviderTLS still lists %q, but no production-class %s stack "+
					"addresses it in the clear any more — delete the entry. A register that outlives its "+
					"subject silently exempts whatever regresses into it next", hopName, registerSource)
			}
		}
	}

	// "Nothing wrong" must be distinguishable from "nothing read".
	if examinedStacks == 0 {
		t.Fatal("no production-class stack was examined — the census read nothing and would " +
			"report success no matter what the profiles say")
	}
	labels := make([]string, 0, len(sources))
	for _, src := range sources {
		labels = append(labels, src.label)
	}
	registerNote := "not asserted: this tree carries no umbrella, so the register has no subject here"
	if registerSource != "" {
		registerNote = "asserted over " + registerSource
	}
	t.Logf("census: %d profile sources (%s) → %d production-class stacks × %d provider hops = "+
		"%d declarations examined; plaintext register %s",
		len(sources), strings.Join(labels, ", "), examinedStacks, len(providerHops), examinedHops, registerNote)
}

// ── profile reading ──────────────────────────────────────────────────────────

// sourceProfile reads one profile of one source. A named profile that is not
// there is a FAILURE, not a skip: the chain is what this tree says it rolls with,
// and a chain naming a file nobody ships is a finding about the tree.
func sourceProfile(t *testing.T, src profileSource, profile string) map[string]any {
	t.Helper()
	path := filepath.Join(src.dir, profile)
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
func mergeProfiles(t *testing.T, src profileSource, chain []string) map[string]any {
	t.Helper()
	merged := map[string]any{}
	for _, profile := range chain {
		merged = mergeInto(merged, sourceProfile(t, src, profile))
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

// under prepends the source's prefix to a path inside the service's own values.
func under(prefix []string, path ...string) []string {
	out := make([]string, 0, len(prefix)+len(path))
	out = append(out, prefix...)
	return append(out, path...)
}

// declaredAddress / declaredAnchor accept either spelling, because iam does.
func declaredAddress(tree map[string]any, prefix []string, h hop) (string, bool) {
	if v, ok := stringAt(tree, under(prefix, h.knob...)...); ok {
		return v, true
	}
	return stringAt(tree, under(prefix, "env", h.env)...)
}

func declaredAnchor(tree map[string]any, prefix []string, h hop) (string, bool) {
	if v, ok := stringAt(tree, under(prefix, h.anchor...)...); ok {
		return v, true
	}
	return stringAt(tree, under(prefix, "env", h.anchorEnv)...)
}

// isProductionClass reads what the stack declares about ITSELF, rather than
// matching a hard-coded list of stand names: a stale list goes quiet the moment a
// stand changes posture, and then exempts the very stack that just started needing
// the check.
func isProductionClass(tree map[string]any, prefix []string) bool {
	return strings.HasPrefix(declaredPosture(tree, prefix), "production")
}

// declaredPosture — посадка, объявленная стеком о САМОМ СЕБЕ.
//
// Адрес канонический — `kaname.authMode` в корне значений сервиса. Прежний
// (`config.authn.mode`) читается следом и ровно потому, что шаблон чарта его тоже
// пока принимает: стек, оставшийся на нём, обязан проверяться, а не выпадать из
// проверки молча.
//
// Порядок здесь несущий, и вот чем он оплачен: когда адрес свели к одному
// написанию, а этот отбор остался на прежнем, ни один стек не опознался боевым —
// все шесть ушли в Skip, перепись прочитала НОЛЬ, и проверка отчиталась бы
// успехом при любом содержимом профилей. Отбор по ключу, который переехал, не
// краснеет: он тихо перестаёт находить предмет.
func declaredPosture(tree map[string]any, prefix []string) string {
	if v, ok := stringAt(tree, under(prefix, "authMode")...); ok {
		return v
	}
	v, _ := stringAt(tree, under(prefix, "config", "authn", "mode")...)
	return v
}
