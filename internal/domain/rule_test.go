// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain_test

// rule_test.go — unit tests for the RBAC rules-model 2026 domain layer:
// Rule.Validate (single-module form, wildcard policy, cardinality
// bounds, XOR selector, feed-gate) + the deterministic rules→permissions compiler
// (anchor/names compile; matchLabels excluded; verb-* projects to `*`; compiled
// cap 1024). `Rule.module` is a single string.

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// --- Rule.Validate cardinality + XOR + empties (scalar module) ---

func TestRule_A13_Validate(t *testing.T) {
	base := func() domain.Rule {
		return domain.Rule{
			Module:    "vpc",
			Resources: []string{"subnet"},
			Verbs:     []string{"get"},
		}
	}
	bigList := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = "x" + strings.Repeat("y", i%3+1)
		}
		return out
	}
	cases := []struct {
		name      string
		mutate    func(*domain.Rule)
		systemCtx bool
		wantErr   string // substring; "" means must pass
	}{
		{"happy anchor", func(*domain.Rule) {}, false, ""},
		{"empty resources", func(r *domain.Rule) { r.Resources = nil }, false, "resources"},
		{"empty verbs", func(r *domain.Rule) { r.Verbs = nil }, false, "verbs"},
		{"resources > 16", func(r *domain.Rule) { r.Resources = bigList(17) }, false, "resources"},
		{"verbs > 16", func(r *domain.Rule) { r.Verbs = bigList(17) }, false, "verbs"},
		{"resourceNames > 256", func(r *domain.Rule) {
			rn := make([]string, 257)
			for i := range rn {
				rn[i] = "id" + strings.Repeat("a", i%5+1)
			}
			r.ResourceNames = rn
		}, false, "resourceNames"},
		{"matchLabels > 16 keys", func(r *domain.Rule) {
			ml := make(map[string]string, 17)
			for i := 0; i < 17; i++ {
				ml["k"+strings.Repeat("x", i+1)] = "v"
			}
			r.MatchLabels = ml
		}, false, "matchLabels"},
		{"resourceNames AND matchLabels mutually exclusive", func(r *domain.Rule) {
			r.ResourceNames = []string{"sub5"}
			r.MatchLabels = map[string]string{"env": "prod"}
		}, false, "mutually exclusive"},
		{"matchLabels empty when set", func(r *domain.Rule) {
			r.MatchLabels = map[string]string{}
		}, false, "non-empty when set"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := base()
			c.mutate(&r)
			err := r.Validate(c.systemCtx)
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("Rule.Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Rule.Validate() = nil, want error containing %q", c.wantErr)
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("Rule.Validate() = %v, want substring %q", err, c.wantErr)
			}
		})
	}
}

// --- module empty/missing → INVALID_ARGUMENT single-text ---

func TestRule_Validate_ModuleEmpty(t *testing.T) {
	// (a) empty string module; (b) zero-value module (absent in proto/JSON) — both
	// the same domain state (Module == ""). The rule is otherwise valid (resources/
	// verbs valid, no selector) so multierr accumulates EXACTLY one error → the
	// single stable text. Assertion is precise.
	r := domain.Rule{Module: "", Resources: []string{"subnet"}, Verbs: []string{"get"}}
	err := r.Validate(false)
	if err == nil {
		t.Fatalf("Validate() = nil, want %q", "Illegal argument module (must be non-empty)")
	}
	if !strings.Contains(err.Error(), "Illegal argument module (must be non-empty)") {
		t.Fatalf("Validate() = %v, want substring %q", err, "Illegal argument module (must be non-empty)")
	}
	// single-text precision: no spurious extra "module" errors.
	if strings.Count(err.Error(), "Illegal argument module") != 1 {
		t.Fatalf("Validate() = %v, want exactly one module error", err)
	}
}

// --- unknown module (grammar-valid, not in closed set) → reject ---

func TestRule_Validate_ModuleUnknown(t *testing.T) {
	// "banana" matches ruleModuleRe (^[a-z][a-z0-9-]*$) but is NOT in the closed
	// set {iam,vpc,compute,loadbalancer}. Request-path reject via IsKnownModule.
	r := domain.Rule{Module: "banana", Resources: []string{"subnet"}, Verbs: []string{"get"}}
	err := r.Validate(false)
	if err == nil {
		t.Fatalf("Validate() = nil, want %q", "Illegal argument module (unknown module 'banana')")
	}
	if !strings.Contains(err.Error(), "Illegal argument module (unknown module 'banana')") {
		t.Fatalf("Validate() = %v, want substring %q", err, "Illegal argument module (unknown module 'banana')")
	}
	// single-text precision (resources/verbs valid → exactly one module error).
	if strings.Count(err.Error(), "Illegal argument module") != 1 {
		t.Fatalf("Validate() = %v, want exactly one module error", err)
	}
	// Counter-example (positive): a member of the set validates clean.
	ok := domain.Rule{Module: "vpc", Resources: []string{"subnet"}, Verbs: []string{"get"}}
	if err := ok.Validate(false); err != nil {
		t.Fatalf("Validate(known module) = %v, want nil", err)
	}
}

// --- grammar-invalid token: distinct text "invalid token" (NOT "unknown module") ---

func TestRule_Validate_ModuleInvalidToken(t *testing.T) {
	cases := []string{"VPC", "a b", "1vpc", "-vpc"}
	for _, m := range cases {
		t.Run(m, func(t *testing.T) {
			r := domain.Rule{Module: m, Resources: []string{"subnet"}, Verbs: []string{"get"}}
			err := r.Validate(false)
			if err == nil || !strings.Contains(err.Error(), "Illegal argument module (invalid token") {
				t.Fatalf("Validate(%q) = %v, want 'Illegal argument module (invalid token ...)'", m, err)
			}
			// grammar-invalid → "invalid token", NOT the closed-set "unknown module".
			if strings.Contains(err.Error(), "unknown module") {
				t.Fatalf("Validate(%q) = %v, grammar-invalid must NOT report 'unknown module'", m, err)
			}
		})
	}
}

// --- module-* system-only (custom reject single-text) ---

func TestRule_Validate_ModuleWildcardSystemOnly(t *testing.T) {
	// custom (systemCtx=false): module:"*" without any selector → exactly the
	// system-only text (one violation: wildcard in custom context; resource is
	// concrete, no selector).
	custom := domain.Rule{Module: "*", Resources: []string{"instance"}, Verbs: []string{"get"}}
	err := custom.Validate(false)
	if err == nil || !strings.Contains(err.Error(), "Illegal argument module (wildcard '*' is system-only)") {
		t.Fatalf("custom module-* = %v, want 'Illegal argument module (wildcard '*' is system-only)'", err)
	}
	// seed (systemCtx=true): module:"*" without selector accepted (admin form).
	seed := domain.Rule{Module: "*", Resources: []string{"instance"}, Verbs: []string{"get"}}
	if err := seed.Validate(true); err != nil {
		t.Fatalf("seed module-* = %v, want nil (system relax)", err)
	}
	// seed full superuser `*.*.* ` accepted (admin/edit/view re-seed form).
	su := domain.Rule{Module: "*", Resources: []string{"*"}, Verbs: []string{"*"}}
	if err := su.Validate(true); err != nil {
		t.Fatalf("seed *.*.* = %v, want nil (system superuser)", err)
	}
}

// --- module-* + selector in custom role → multierr accumulates BOTH texts ---

func TestRule_Validate_WildcardPlusSelector_AccumulatesBothErrors(t *testing.T) {
	r := domain.Rule{
		Module: "*", Resources: []string{"instance"}, Verbs: []string{"get"},
		MatchLabels: map[string]string{"env": "prod"},
	}
	err := r.Validate(false)
	if err == nil {
		t.Fatalf("Validate() = nil, want BOTH module-system-only AND wildcard-cannot-combine")
	}
	msg := err.Error()
	wantBoth := []string{
		"Illegal argument module (wildcard '*' is system-only)",
		"Illegal argument: wildcard cannot combine with resourceNames or matchLabels",
	}
	for _, w := range wantBoth {
		if !strings.Contains(msg, w) {
			t.Fatalf("Validate() = %v, missing accumulated text %q", err, w)
		}
	}
}

// --- feed-availability gate (matchLabels only on fed types, scalar) ---

func TestRule_A10_FeedGate(t *testing.T) {
	cases := []struct {
		name    string
		rule    domain.Rule
		wantErr string
	}{
		{"iam.project matchLabels OK", domain.Rule{
			Module: "iam", Resources: []string{"project"}, Verbs: []string{"get"},
			MatchLabels: map[string]string{"tier": "gold"},
		}, ""},
		{"iam.account matchLabels OK", domain.Rule{
			Module: "iam", Resources: []string{"account"}, Verbs: []string{"get"},
			MatchLabels: map[string]string{"tier": "gold"},
		}, ""},
		// Unified visibility model: every iam-native content type is now
		// label-selectable (was rejected under the legacy O-4 split).
		{"iam.role matchLabels OK (unified model)", domain.Rule{
			Module: "iam", Resources: []string{"role"}, Verbs: []string{"get"},
			MatchLabels: map[string]string{"k": "v"},
		}, ""},
		{"iam.user matchLabels OK (unified model)", domain.Rule{
			Module: "iam", Resources: []string{"user"}, Verbs: []string{"get"},
			MatchLabels: map[string]string{"k": "v"},
		}, ""},
		{"iam.serviceAccount matchLabels OK (unified model)", domain.Rule{
			Module: "iam", Resources: []string{"serviceAccount"}, Verbs: []string{"get"},
			MatchLabels: map[string]string{"k": "v"},
		}, ""},
		{"iam.group matchLabels OK (unified model)", domain.Rule{
			Module: "iam", Resources: []string{"group"}, Verbs: []string{"get"},
			MatchLabels: map[string]string{"k": "v"},
		}, ""},
		{"iam.accessBinding matchLabels OK (unified model)", domain.Rule{
			Module: "iam", Resources: []string{"accessBinding"}, Verbs: []string{"get"},
			MatchLabels: map[string]string{"k": "v"},
		}, ""},
		{"vpc.addressPool matchLabels rejected (non-fed)", domain.Rule{
			Module: "vpc", Resources: []string{"addressPool"}, Verbs: []string{"get"},
			MatchLabels: map[string]string{"k": "v"},
		}, "vpc.addressPool is not selectable"},
		{"vpc.subnet matchLabels OK (mirror-fed)", domain.Rule{
			Module: "vpc", Resources: []string{"subnet"}, Verbs: []string{"create"},
			MatchLabels: map[string]string{"env": "prod"},
		}, ""},
		{"iam.role resourceNames OK (NAMES not feed-gated)", domain.Rule{
			Module: "iam", Resources: []string{"role"}, Verbs: []string{"get"},
			ResourceNames: []string{"rol0000000000000abcd"},
		}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.rule.Validate(false)
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("Validate() = %v, want substring %q", err, c.wantErr)
			}
		})
	}
}

// --- compiler arm semantics over a single module ---

func TestRule_Module_HappyCompile(t *testing.T) {
	rules := []domain.Rule{
		{Module: "compute", Resources: []string{"image"}, Verbs: []string{"get"}},                                                      // ANCHOR
		{Module: "vpc", Resources: []string{"subnet"}, Verbs: []string{"create"}, MatchLabels: map[string]string{"env": "prod"}},       // LABELS (excluded)
		{Module: "vpc", Resources: []string{"address"}, Verbs: []string{"get", "update"}, ResourceNames: []string{"addr5k", "addr9m"}}, // NAMES
	}
	perms, err := domain.CompileRules(rules)
	if err != nil {
		t.Fatalf("CompileRules() = %v, want nil", err)
	}
	got := map[string]bool{}
	for _, p := range perms {
		got[string(p)] = true
	}
	want := []string{
		"compute.image.*.get",    // ANCHOR
		"vpc.address.addr5k.get", // NAMES
		"vpc.address.addr5k.update",
		"vpc.address.addr9m.get",
		"vpc.address.addr9m.update",
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("compiled permissions missing %q; got %v", w, perms)
		}
	}
	for _, p := range perms {
		if strings.HasPrefix(string(p), "vpc.subnet.") {
			t.Errorf("matchLabels arm leaked into permissions: %q", p)
		}
	}
	if len(perms) != len(want) {
		t.Errorf("compiled count = %d, want %d (%v)", len(perms), len(want), perms)
	}
}

// single-module ANCHOR with two resources × two verbs → resources×verbs
// unrolled, NO module unroll (module is scalar).
func TestCompileRules_SingleModule(t *testing.T) {
	perms, err := domain.CompileRules([]domain.Rule{
		{Module: "compute", Resources: []string{"instance", "disk"}, Verbs: []string{"get", "list"}},
	})
	if err != nil {
		t.Fatalf("CompileRules() = %v", err)
	}
	got := map[string]bool{}
	for _, p := range perms {
		got[string(p)] = true
	}
	want := []string{
		"compute.instance.*.get", "compute.instance.*.list",
		"compute.disk.*.get", "compute.disk.*.list",
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("missing %q; got %v", w, perms)
		}
	}
	if len(perms) != len(want) {
		t.Errorf("compiled count = %d, want %d (%v)", len(perms), len(want), perms)
	}
}

// verb-* anchor projects to module.resource.*.* (projection keeps `*` verb).
func TestRulesCompile_A04_VerbStar(t *testing.T) {
	perms, err := domain.CompileRules([]domain.Rule{
		{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"*"}},
	})
	if err != nil {
		t.Fatalf("CompileRules() = %v", err)
	}
	if len(perms) != 1 || string(perms[0]) != "compute.instance.*.*" {
		t.Fatalf("verb-* anchor compiled = %v, want [compute.instance.*.*]", perms)
	}
}

// compiled cap — ≤1024 OK; >1024 → error "compiled permissions exceed 1024".
func TestRulesCompile_A12_Cap(t *testing.T) {
	// ANCHOR rule with 32 resources × 32 verbs = 1024 compiled (boundary OK).
	res := make([]string, 32)
	verbs := make([]string, 32)
	for i := 0; i < 32; i++ {
		res[i] = "r" + string(rune('a'+i))
		verbs[i] = "v" + string(rune('a'+i))
	}
	okRule := domain.Rule{Module: "compute", Resources: res, Verbs: verbs}
	perms, err := domain.CompileRules([]domain.Rule{okRule})
	if err != nil {
		t.Fatalf("1024 compiled rejected unexpectedly: %v", err)
	}
	if len(perms) != 1024 {
		t.Fatalf("expected 1024 compiled, got %d", len(perms))
	}

	// One more resource (33×32 = 1056) → over cap.
	overRes := append(append([]string{}, res...), "rZZ")
	_, err = domain.CompileRules([]domain.Rule{
		{Module: "compute", Resources: overRes, Verbs: verbs},
	})
	if err == nil || !strings.Contains(err.Error(), "compiled permissions exceed 1024") {
		t.Fatalf("over-cap CompileRules() = %v, want 'compiled permissions exceed 1024'", err)
	}
}

// CompileRules output must always satisfy domain.Permissions.Validate (4-seg
// grammar parity with the DB CHECK).
func TestRulesCompile_GrammarParity(t *testing.T) {
	perms, err := domain.CompileRules([]domain.Rule{
		{Module: "vpc", Resources: []string{"subnet"}, Verbs: []string{"*"}},
		{Module: "vpc", Resources: []string{"address"}, Verbs: []string{"get"}, ResourceNames: []string{"addr5k"}},
	})
	if err != nil {
		t.Fatalf("CompileRules() = %v", err)
	}
	if err := perms.Validate(); err != nil {
		t.Fatalf("compiled permissions fail 4-seg grammar: %v (%v)", err, perms)
	}
}
