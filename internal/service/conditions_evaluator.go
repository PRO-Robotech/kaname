// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// conditions_evaluator.go — CEL-like evaluator for the 7 built-in
// conditions + cached generic CEL-like predicate evaluation for free-form
// `Condition.expression`.
//
// Design choice: this evaluator is **request-time**, used by the
// `ConditionsService.Evaluate` admin RPC and the AuthorizeService's
// Conditions overlay step. The full CEL evaluation of `Condition.expression`
// in production happens **inside OpenFGA-engine** (FGA-engine pre-compiles the
// CEL on `WriteAuthorizationModel` and runs it on every Check). The
// evaluator here is for:
//
//   - the admin/diagnostic `Evaluate` endpoint (validate an expression sees
//     the expected context — non-fatal mismatch with FGA-engine is OK; both
//     evaluate the same CEL semantics);
//   - `OPA-overlay` step's pre-Check Conditions on AccessBinding.condition_id
//     (read condition, run built-in eval if it's one of the 7 known kinds,
//     short-circuit before the FGA round-trip when context is obviously
//     deny).
//
// For free-form `Condition.expression` outside the 7 builtins, this evaluator
// returns ErrUnsupportedExpression — callers fall back to FGA semantic
// evaluation (Check). Production swap-in of `cel-go` is encapsulated via a
// thin `expressionEvaluator` interface so the change is mechanical.
//
// LRU cache: compiled-builtin-form is trivially cheap, but mapping
// "expression text → builtin kind" is cached per-expression for the lifetime
// of the process. Cache size/TTL are injected from the viper Config
// (`conditions.cache-size` / `conditions.cache-ttl-seconds`, defaults 1000 / 60s)
// at the composition root — never read from the environment in this layer.
package service

import (
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
)

// Default recognition-cache tuning — used by NewBuiltinEvaluator and as the
// floor for a non-positive injected value in NewBuiltinEvaluatorWithCache.
const (
	defaultConditionsCacheSize = 1000
	defaultConditionsCacheTTL  = 60 * time.Second
)

// ErrUnsupportedExpression — caller should fall back to FGA Check.
var ErrUnsupportedExpression = errors.New("conditions: free-form CEL expression — delegate to OpenFGA")

// ConditionsEvaluator — port-iface for evaluating Conditions.
type ConditionsEvaluator interface {
	// Evaluate — return allowed/denied + free-form trace.
	//
	//   * `builtin` selects a known predicate (mfa_fresh, …) when non-zero;
	//   * otherwise `expression` is parsed as a free-form CEL-like predicate
	//     (limited subset — see EvaluateExpression).
	//   * `params` are condition-author-defined parameters (e.g.
	//     `{"allowed_cidrs":[...]}` for source_ip_in_range).
	//   * `context` is the runtime CEL-context (acr_value, amr_claims,
	//     current_time, …) built from Principal at request time.
	Evaluate(builtin iamv1.BuiltinCondition, expression string, params, context map[string]any) (allowed bool, trace string, err error)
}

// BuiltinEvaluator — concrete evaluator implementing the 7 builtins + a
// constrained CEL subset for `Condition.expression`.
type BuiltinEvaluator struct {
	cacheTTL  time.Duration
	cacheSize int

	mu    sync.Mutex
	cache map[string]exprCacheEntry
}

type exprCacheEntry struct {
	kind iamv1.BuiltinCondition
	ok   bool // true = recognised as known builtin form
	exp  time.Time
}

// NewBuiltinEvaluator builds an evaluator with the default recognition-cache
// tuning. Cache size/TTL come from the composition-root config via
// NewBuiltinEvaluatorWithCache in production; this default variant is for tests
// and callers that don't tune the cache. No environment access (config is
// injected at the composition root, never read in the service layer).
func NewBuiltinEvaluator() *BuiltinEvaluator {
	return NewBuiltinEvaluatorWithCache(defaultConditionsCacheSize, defaultConditionsCacheTTL)
}

// NewBuiltinEvaluatorWithCache builds an evaluator with an explicit
// recognition-cache size/TTL, injected from the viper Config in the composition
// root. A non-positive size or ttl falls back to the package default (defensive;
// Config.Validate already rejects non-positive values at boot).
func NewBuiltinEvaluatorWithCache(size int, ttl time.Duration) *BuiltinEvaluator {
	if size <= 0 {
		size = defaultConditionsCacheSize
	}
	if ttl <= 0 {
		ttl = defaultConditionsCacheTTL
	}
	return &BuiltinEvaluator{
		cacheTTL:  ttl,
		cacheSize: size,
		cache:     make(map[string]exprCacheEntry, 64),
	}
}

// Evaluate — see ConditionsEvaluator.
func (e *BuiltinEvaluator) Evaluate(builtin iamv1.BuiltinCondition, expression string, params, context map[string]any) (bool, string, error) {
	kind := builtin
	if kind == iamv1.BuiltinCondition_BUILTIN_CONDITION_UNSPECIFIED && expression != "" {
		kind = e.recogniseExpression(expression)
		if kind == iamv1.BuiltinCondition_BUILTIN_CONDITION_UNSPECIFIED {
			return false, "free-form expression — delegate to FGA", ErrUnsupportedExpression
		}
	}
	switch kind {
	case iamv1.BuiltinCondition_BUILTIN_CONDITION_MFA_FRESH:
		return e.evalMFAFresh(context)
	case iamv1.BuiltinCondition_BUILTIN_CONDITION_NON_EXPIRED:
		return e.evalNonExpired(context, params)
	case iamv1.BuiltinCondition_BUILTIN_CONDITION_SOURCE_IP_IN_RANGE:
		return e.evalSourceIPInRange(context, params)
	// BREAK_GLASS_WINDOW (RBAC v2) and JIT_WINDOW (orphaned by the
	// JIT/PIM pipeline removal — no flow ever sets
	// `activated_at`, so it could never gate on real state) are both
	// deprecated. Their enum values stay `[deprecated=true]` for proto3 wire
	// compatibility but reach the default branch ("unknown builtin") below so
	// bindings carrying either are rejected at evaluation time (fail-closed).
	case iamv1.BuiltinCondition_BUILTIN_CONDITION_BUSINESS_HOURS:
		return e.evalBusinessHours(context, params)
	case iamv1.BuiltinCondition_BUILTIN_CONDITION_DEVICE_COMPLIANT:
		return e.evalDeviceCompliant(context, params)
	default:
		return false, "unknown builtin", ErrUnsupportedExpression
	}
}

// recogniseExpression — best-effort match of an expression to a builtin.
// Substring match because the CEL syntax in stored Conditions is opaque (the
// evaluator delegates real CEL to FGA-engine). A future iteration will
// replace this with a true CEL parser via cel-go.
func (e *BuiltinEvaluator) recogniseExpression(expr string) iamv1.BuiltinCondition {
	e.mu.Lock()
	defer e.mu.Unlock()
	if c, ok := e.cache[expr]; ok && time.Now().Before(c.exp) {
		if c.ok {
			return c.kind
		}
		return iamv1.BuiltinCondition_BUILTIN_CONDITION_UNSPECIFIED
	}
	kind := iamv1.BuiltinCondition_BUILTIN_CONDITION_UNSPECIFIED
	low := strings.ToLower(strings.TrimSpace(expr))
	switch {
	case strings.Contains(low, "mfa_fresh") || (strings.Contains(low, "acr_value") && strings.Contains(low, "webauthn") && strings.Contains(low, "mfa_at")):
		kind = iamv1.BuiltinCondition_BUILTIN_CONDITION_MFA_FRESH
	case strings.Contains(low, "non_expired") || (strings.Contains(low, "current_time") && strings.Contains(low, "valid_until")):
		kind = iamv1.BuiltinCondition_BUILTIN_CONDITION_NON_EXPIRED
	case strings.Contains(low, "source_ip_in_range") || strings.Contains(low, "allowed_cidrs"):
		kind = iamv1.BuiltinCondition_BUILTIN_CONDITION_SOURCE_IP_IN_RANGE
	// `break_glass_window` and `jit_window` / `activated_at`+`ttl_seconds`
	// are deprecated builtin-condition substrings. Expressions referencing
	// them reach the UNSPECIFIED fallback below (delegated to FGA), never a
	// builtin evaluator.
	case strings.Contains(low, "business_hours") || strings.Contains(low, "hour_of_day"):
		kind = iamv1.BuiltinCondition_BUILTIN_CONDITION_BUSINESS_HOURS
	case strings.Contains(low, "device_compliant") || strings.Contains(low, "allowed_attestations"):
		kind = iamv1.BuiltinCondition_BUILTIN_CONDITION_DEVICE_COMPLIANT
	}
	// LRU naive cap.
	if len(e.cache) >= e.cacheSize {
		// Evict expired entries; if none, drop a single arbitrary key.
		now := time.Now()
		for k, v := range e.cache {
			if now.After(v.exp) {
				delete(e.cache, k)
				if len(e.cache) < e.cacheSize {
					break
				}
			}
		}
		if len(e.cache) >= e.cacheSize {
			for k := range e.cache {
				delete(e.cache, k)
				break
			}
		}
	}
	e.cache[expr] = exprCacheEntry{
		kind: kind,
		ok:   kind != iamv1.BuiltinCondition_BUILTIN_CONDITION_UNSPECIFIED,
		exp:  time.Now().Add(e.cacheTTL),
	}
	return kind
}

// ── 7 built-in predicate evaluators ────────────────────────────────

// mfa_fresh: acr_value=="3" && "webauthn" in amr_claims &&
//
//	current_time - mfa_at < 15min.
func (e *BuiltinEvaluator) evalMFAFresh(ctx map[string]any) (bool, string, error) {
	acr, _ := ctx["acr_value"].(string)
	if acr != "3" {
		return false, fmt.Sprintf("mfa_fresh: acr=%q (need 3)", acr), nil
	}
	amr := asStringList(ctx["amr_claims"])
	if !slices.Contains(amr, "webauthn") {
		return false, fmt.Sprintf("mfa_fresh: amr_claims=%v (missing webauthn)", amr), nil
	}
	now := unixTime(ctx["current_time"])
	mfa := unixTime(ctx["mfa_at"])
	if now == 0 || mfa == 0 {
		return false, "mfa_fresh: missing current_time or mfa_at", nil
	}
	if now-mfa >= 15*60 {
		return false, fmt.Sprintf("mfa_fresh: mfa_at is %ds old (need <15min)", now-mfa), nil
	}
	return true, "mfa_fresh: ok", nil
}

// non_expired: current_time < valid_until.
func (e *BuiltinEvaluator) evalNonExpired(ctx, params map[string]any) (bool, string, error) {
	now := unixTime(ctx["current_time"])
	// `valid_until` may live in ctx (binding-provided) or in params (defaults).
	exp := unixTime(ctx["valid_until"])
	if exp == 0 {
		exp = unixTime(params["valid_until"])
	}
	if exp == 0 {
		// No valid_until set → treat as always-valid.
		return true, "non_expired: no valid_until", nil
	}
	if now >= exp {
		return false, fmt.Sprintf("non_expired: current_time=%d >= valid_until=%d", now, exp), nil
	}
	return true, "non_expired: ok", nil
}

// source_ip_in_range: client_ip in allowed_cidrs.
func (e *BuiltinEvaluator) evalSourceIPInRange(ctx, params map[string]any) (bool, string, error) {
	clientIP, _ := ctx["client_ip"].(string)
	if clientIP == "" {
		return false, "source_ip_in_range: no client_ip", nil
	}
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return false, fmt.Sprintf("source_ip_in_range: bad client_ip=%q", clientIP), nil
	}
	cidrs := asStringList(params["allowed_cidrs"])
	if len(cidrs) == 0 {
		cidrs = asStringList(ctx["allowed_cidrs"])
	}
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			continue
		}
		if n.Contains(ip) {
			return true, fmt.Sprintf("source_ip_in_range: %s ∈ %s", clientIP, c), nil
		}
	}
	return false, fmt.Sprintf("source_ip_in_range: %s ∉ %v", clientIP, cidrs), nil
}

// evalJITWindow / evalBreakGlassWindow removed: JIT_WINDOW
// and BREAK_GLASS_WINDOW are deprecated builtins. Their enum values
// are preserved for wire-compat but route to the reject path in Evaluate.

// business_hours: hour_of_day(current_time, tz) in [start_h, end_h).
func (e *BuiltinEvaluator) evalBusinessHours(ctx, params map[string]any) (bool, string, error) {
	now := unixTime(ctx["current_time"])
	if now == 0 {
		return false, "business_hours: no current_time", nil
	}
	tzName, _ := params["tz"].(string)
	if tzName == "" {
		tzName, _ = ctx["tz"].(string)
	}
	if tzName == "" {
		tzName = "UTC"
	}
	loc, err := time.LoadLocation(tzName)
	if err != nil {
		return false, fmt.Sprintf("business_hours: bad tz %q", tzName), nil
	}
	t := time.Unix(now, 0).In(loc)
	startH := int64(unixTime(params["start_h"]))
	endH := int64(unixTime(params["end_h"]))
	if startH == 0 && endH == 0 {
		// Default 9-18 if neither set (operationally reasonable).
		startH = 9
		endH = 18
	}
	h := int64(t.Hour())
	if h < startH || h >= endH {
		return false, fmt.Sprintf("business_hours: hour=%d outside [%d,%d)", h, startH, endH), nil
	}
	return true, "business_hours: ok", nil
}

// device_compliant: device_attestation in allowed_attestations.
func (e *BuiltinEvaluator) evalDeviceCompliant(ctx, params map[string]any) (bool, string, error) {
	att, _ := ctx["device_attestation"].(string)
	if att == "" {
		return false, "device_compliant: no device_attestation", nil
	}
	allowed := asStringList(params["allowed_attestations"])
	if len(allowed) == 0 {
		allowed = asStringList(ctx["allowed_attestations"])
	}
	if !slices.Contains(allowed, att) {
		return false, fmt.Sprintf("device_compliant: %q not in %v", att, allowed), nil
	}
	return true, "device_compliant: ok", nil
}

// ── helpers ──────────────────────────────────────────────────────

func asStringList(v any) []string {
	switch x := v.(type) {
	case []string:
		return x
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// unixTime — coerces an `any` value to a Unix seconds int64. Accepts:
//   - int64 / int / float64 (unix seconds)
//   - string RFC3339
//   - time.Time
func unixTime(v any) int64 {
	switch x := v.(type) {
	case int64:
		return x
	case int:
		return int64(x)
	case int32:
		return int64(x)
	case float64:
		return int64(x)
	case float32:
		return int64(x)
	case string:
		// Try RFC3339 first.
		if t, err := time.Parse(time.RFC3339, x); err == nil {
			return t.Unix()
		}
		// Then unix-string.
		if n, err := strconv.ParseInt(x, 10, 64); err == nil {
			return n
		}
	case time.Time:
		return x.Unix()
	}
	return 0
}

var _ ConditionsEvaluator = (*BuiltinEvaluator)(nil)
