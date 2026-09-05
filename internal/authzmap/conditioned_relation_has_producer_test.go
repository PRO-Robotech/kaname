// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzmap_test

import (
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

// conditionSite — one `with <condition>` clause in the canonical model.
type conditionSite struct {
	Type      string // object type the relation is defined on
	Relation  string // relation name
	Condition string // condition name after `with`
	Line      int    // 1-based line in the canonical DSL
}

func (s conditionSite) String() string {
	return s.Type + "#" + s.Relation + " with " + s.Condition
}

var reWith = regexp.MustCompile(`with (\w+)`)

// parseConditionSites finds every `with <condition>` clause and attributes it to
// the type/relation it constrains.
func parseConditionSites(t *testing.T) ([]conditionSite, int) {
	t.Helper()
	raw, err := os.ReadFile(canonicalModelPath(t))
	require.NoError(t, err)
	lines := strings.Split(string(raw), "\n")
	require.NotEmpty(t, lines, "canonical model read as zero lines")

	var sites []conditionSite
	var curType string
	for i, line := range lines {
		if m := reType.FindStringSubmatch(line); m != nil {
			curType = m[1]
			continue
		}
		// A `condition <name>(...)` block ends the type bodies. Its own body may
		// mention parameter names; it declares nothing about relations.
		if strings.HasPrefix(line, "condition ") {
			curType = ""
			continue
		}
		if curType == "" {
			continue
		}
		m := reDefine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		for _, w := range reWith.FindAllStringSubmatch(line, -1) {
			sites = append(sites, conditionSite{
				Type: curType, Relation: m[1], Condition: w[1], Line: i + 1,
			})
		}
	}
	return sites, len(lines)
}

// TestConditionedRelationHasAProducer — a relation may require a condition only
// if something can produce a tuple that satisfies it.
//
// Ограничение типа читается на записи: когда оно для субъектного типа выглядит
// как `[user with <cond>]`, БЕЗУСЛОВНАЯ строка для этого субъекта условию не
// удовлетворяет и права по этой ветви не даёт.
//
// Здесь стояло «OpenFGA отвергает такую запись» вместе с текстом его отказа.
// Внешнего движка в дереве нет (S6), и называть его нынешним контролёром значило
// бы направлять читателя к тому, чего не существует. Свойство при этом не
// изменилось и стало ПРЯМЕЕ: условие лежит на самой строке прямого факта
// (`relation_fact.condition_name`), и вопрос о доступе вычисляет его сам —
// безусловная строка против условного ограничения просто не даёт основания.
//
// Так что `with` на отношении, чей единственный производитель пишет безусловные
// строки, это отношение НЕ сужает — он делает его прямую субъектную ветвь
// НЕИСПОЛНИМОЙ. The grant then never materializes, the write is refused for
// good (a refusal that repeats identically is not transient), and the row wedges
// its outbox partition. Access still resolves through whatever computed branch
// the relation unions in, so the relation keeps answering — which is why this is
// invisible without a gate: the declaration reads like a restriction, and the
// observable behaviour is that the restriction was simply never in force.
//
// The premise is checked, not assumed (see TestConditionProducerPremise): the
// reconciler is the only producer of tuples derived from an AccessBinding, and
// its tuple value carries no condition, so today NO conditioned direct branch is
// materializable from a grant. Every `with` site must therefore be declared
// below, with what it costs.
func TestConditionedRelationHasAProducer(t *testing.T) {
	sites, lineCount := parseConditionSites(t)
	require.NotZero(t, lineCount, "read zero lines of the canonical model")
	require.NotEmpty(t, sites,
		"found zero `with <condition>` clauses in the canonical model — either the model "+
			"stopped using conditions (then delete this gate together with the exception "+
			"table) or the parser broke. A gate that inspects nothing must be RED, not green.")
	t.Logf("census: %d lines of the canonical model read, %d `with` clause(s) attributed",
		lineCount, len(sites))

	// One relation may restrict several subject types on the same line
	// (`[user with mfa_fresh, service_account with mfa_fresh]`). That is ONE
	// decision about ONE relation, so it is reported once.
	seen := map[string]bool{}
	for _, s := range sites {
		if seen[s.String()] {
			continue
		}
		seen[s.String()] = true
		if _, declared := unproducedConditionSites[s.String()]; !declared {
			t.Errorf("%s:%d declares `with %s` on %s#%s, and nothing in production can write a "+
				"tuple carrying that condition (see TestConditionProducerPremise). Безусловная "+
				"строка против условного ограничения основания не даёт, поэтому оговорка не "+
				"сужает отношение — она снимает его прямую субъектную ветвь и заклинивает "+
				"партицию журнала у всякой выдачи, которая попробует ею воспользоваться. "+
				"Either give the condition a "+
				"producer, or drop the clause; declaring it and listing it below is only for what "+
				"already shipped.",
				canonicalModelRelPath, s.Line, s.Condition, s.Type, s.Relation)
		}
	}
}

// unproducedConditionSites — the conditioned relations that shipped BEFORE this
// gate existed, each with what it actually costs. Keyed by
// `<type>#<relation> with <condition>`.
//
// These are NOT approvals. Each one is a direct-subject branch that cannot be
// written today, recorded so the count is visible and so a NEW one cannot be
// added quietly. An entry leaves this table when its condition gains a producer
// (and then the relation gets a behavioural test), or when the clause is dropped.
//
// WHICH SIDE THIS TABLE SPEAKS ABOUT. It states a fact about the ENGINE, and
// only about it: the engine's tuple has no place for a condition, so the direct
// branch is unwritable there. The relational form inside iam (XC-12 Ф4) carries
// the condition ON THE FACT ROW and evaluates it against the request context —
// `relverdict.evalCondition`, locked by TestAsk_ConditionDecidesTheOutcomeBothWays
// and TestConditionRegistryMatchesTheModel. So this table must NOT be read as
// "the freshness requirement is unimplementable"; it says the engine cannot
// express it. The entries leave when the engine stops being the source of the
// verdict for these types (Ф6) — at which point the requirement IS in force and
// there is nothing left to excuse, which TestNoStaleConditionExceptions turns
// into a finding on its own.
//
// All three are `mfa_fresh`, whose parameters (`acr_value`, `amr_claims`,
// `mfa_at`, `current_time`) are supplied per REQUEST rather than per tuple — so
// only the condition NAME would have to reach the tuple for these to work. Even
// that is out of reach: the reconciler's tuple value has no place to put it.
// Consequence today: each of these relations resolves solely through the
// computed branch it unions (`or admin`), so `ssh`/`console` are exactly `admin`
// and the freshness requirement is not in force anywhere.
//
// `cluster#console` stood here as a third entry and is GONE with its subject: the
// relation unioned nothing, so it was unreachable outright, and it was withdrawn
// from the canonical model (#1820). The entry left by the same change — an
// exception with nothing to exclude is a finding, and TestNoStaleConditionExceptions
// says so on its own.
var unproducedConditionSites = map[string]string{
	"compute_instance#ssh with mfa_fresh": "resolves via `or admin`; the freshness " +
		"requirement on the direct branch is not in force",
	"compute_instance#console with mfa_fresh": "resolves via `or admin`; the freshness " +
		"requirement on the direct branch is not in force",
}

// TestConditionProducerPremise — the premise the gate above rests on, asserted
// rather than assumed.
//
// The claim is: nothing derived from an AccessBinding can carry a condition. The
// reconciler is the only producer of binding-derived tuples, and the value it
// emits is `domain.MembershipTuple`. If that value ever gains a condition field,
// the claim is no longer true, this test fails, and the exception table above has
// to be revisited — which is the point. A gate whose justification can rot
// silently is worth less than no gate.
//
// Read by reflection, not by grep: a field is a field, and a comment that says
// "condition" is not one.
func TestConditionProducerPremise(t *testing.T) {
	rt := reflect.TypeOf(domain.MembershipTuple{})
	var fields []string
	for i := 0; i < rt.NumField(); i++ {
		fields = append(fields, rt.Field(i).Name)
	}
	require.NotEmpty(t, fields, "domain.MembershipTuple has no fields — reflection premise broken")
	t.Logf("premise: domain.MembershipTuple carries %v", fields)

	for _, f := range fields {
		if strings.Contains(strings.ToLower(f), "condition") {
			t.Fatalf("domain.MembershipTuple now carries a condition-bearing field %q. The premise "+
				"of TestConditionedRelationHasAProducer no longer holds: binding-derived tuples CAN "+
				"now be conditioned. Re-examine every entry in unproducedConditionSites — an entry "+
				"whose condition now has a producer must be removed and the relation actually "+
				"exercised by a behavioural test, not left excused.", f)
		}
	}
}

// TestNoStaleConditionExceptions — an exception lives only while it has a
// subject. An entry naming a site the model no longer contains is a false
// statement about the product, and it is the next reader who inherits it as a
// blind spot.
func TestNoStaleConditionExceptions(t *testing.T) {
	sites, _ := parseConditionSites(t)
	present := map[string]bool{}
	for _, s := range sites {
		present[s.String()] = true
	}
	for key := range unproducedConditionSites {
		if !present[key] {
			t.Errorf("unproducedConditionSites excuses %q, which the canonical model no longer "+
				"declares — delete the entry. An exception with nothing left to exclude is a "+
				"finding, not documentation.", key)
		}
	}
}
