// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// own_gates.go — the relation client iam's OWN gates ask.
//
// # WHY THIS EXISTS
//
// The structural facts this package derives were first supplied on ONE surface:
// AuthorizeService, which is the gate the api-gateway per-RPC middleware asks. iam's
// own in-service gates put the same question to the relation store DIRECTLY, so they
// kept resolving the cascade only over pointers the outbox had already delivered.
//
// One subject then got two different answers depending on who asked, and the pair was
// absurd rather than merely inconsistent: the owner of a brand-new account was admitted
// to DELETE it (the edge resolves his `owner` fact from the committed row) and told it
// DOES NOT EXIST when he read it (the in-service read gate asked the store, found no
// tuple, and a read denial is hidden as not-found). The delegated account administrator
// was admitted at the edge on a project-scoped grant and refused inside.
//
// # THE SHAPE OF THE FIX
//
// Not three patched call sites. The gates do not hold a store of their own — they hold
// whatever the composition root handed them, through narrow ports (
// authzguard.RelationChecker, authzfilter.ObjectChecker, clients.RelationStore /
// RelationQueries). So the root hands them THIS, and asking the store directly stops
// being expressible: the store they can reach is the one that gives the same second
// chance the edge gives. A gate added tomorrow inherits it without knowing it exists.
//
// Reached this way, and measured rather than assumed (page_cost_integration_test.go):
//   - authzguard.AllowsVerb — behind account/project/user/group/service-account Get
//     and the conditions read/write gates;
//   - authzguard.RequireScopeRelation — the mutating defense-in-depth gate;
//   - access_binding requireGrantAuthority Path 2 (fgaHoldsScopeAdmin) — binding
//     Create/Delete/Revoke/Update/Get/ListBy*;
//   - authzfilter.Visible / VisibleSet — every page filter;
//   - account ListAllOperations, user Invite, authorize CallerAuthority.
//
// # WHAT IS NOT ROUTED THROUGH IT, AND WHY
//
//   - AuthorizeService keeps the raw transport. It already gives this second chance
//     itself, and it deliberately asks the CHEAP flat cluster super-gate first, so
//     routing it through here would make a cloud administrator pay a structural read
//     before the gate that was going to admit him anyway. The two placements must
//     nevertheless never disagree, so that is asserted on the observable answer, over
//     real OpenFGA, in service/own_gates_agree_with_edge_integration_test.go — not by
//     sharing an eight-line function, which would prove identical code and not
//     identical answers.
//   - seed.VerifyGate keeps the raw transport BY REQUIREMENT: its job is to report
//     whether materialization was DELIVERED. A second chance derived from committed
//     rows would make it answer yes about a queue that has delivered nothing — the
//     gate would still run, still pass, and mean nothing. There is deliberately no
//     "ask without the second chance" method here for it to use: a method whose only
//     caller is hypothetical is a claim the code does not keep, and the root already
//     holds the transport for its own reasons.
//   - The cluster-singleton probes (system-viewer floor, fga-proxy gate,
//     cluster-admin short-circuit, force-logout, WhoAmI flags) are unaffected either
//     way: `cluster` is not a derivable type, so Derivable() answers no and no read
//     is paid.
package authzcascade

import (
	"context"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authztypes"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
)

// Relations — the relation-client surface a gate may hold. Satisfied by
// *clients.OpenFGAHTTPClient.
//
// It is the FULL surface rather than just the two Check methods on purpose: the
// wrapper has to be substitutable for the client at every wiring point in the
// composition root, including the ones that write tuples or list subjects. A narrower
// wrapper would leave the root choosing per call site which value to pass, and that
// choice is exactly the thing that diverged.
type Relations interface {
	clients.RelationStore
	clients.RelationQueries
	// CheckWithContextualTuples — a Check that also carries tuples holding for THIS
	// request only. The second chance is nothing but this call, over facts read from
	// committed rows.
	CheckWithContextualTuples(ctx context.Context, subject, relation, object string,
		condCtx map[string]any, contextual []authztypes.TupleKey) (bool, error)
	// ListUsers — the graph-expanded principal set of (object, relation). Not a Check and
	// not decorated; it is here because a gate that resolves "who can do this" is wired
	// from the same value as the gates that ask "may this subject", and requiring the
	// composition root to keep a second value around for it is exactly how the two
	// surfaces drifted apart.
	ListUsers(ctx context.Context, objectType, objectID, relation string, userTypes []string) (principals []string, storeTruncated bool, err error)
}

// FactSource — the structural facts iam can prove from its own committed rows.
// Satisfied by *Resolver; declared as a port so the cost measurement can count
// resolutions and the fail-closed test can make one fail.
type FactSource interface {
	// Derivable — answerable without touching the database, so a question about an
	// object iam does not own costs no read.
	Derivable(objectType string) bool
	// StructuralFacts — (nil, nil) claims nothing; a non-nil error means the fact
	// could not be READ, which is an unknown answer and not a negative one.
	StructuralFacts(ctx context.Context, objectType, objectID string) ([]authztypes.TupleKey, error)
}

// Client — a Relations that gives a DENIED question a second chance over the
// structural facts of the object it is about.
//
// Only a denial pays: an allow is returned untouched, so the common path costs
// exactly what it did before. A contextual tuple can only ADD a resolution path, so
// this can turn a deny into an allow and never the reverse — which is why supplying
// only TRUE facts about a committed row is the whole safety argument, and why
// cascade_coverage_test.go pins which relations the model reads those facts through.
type Client struct {
	// Relations — embedded, so every method this wrapper does not override is the
	// transport's own. Named (not anonymous-typed) so the overrides can call through.
	Relations
	facts FactSource
}

// Wrap returns the relation client iam's own gates must be given.
//
// A nil FactSource yields a plain pass-through rather than a panic: that is what a
// unit test wiring only a transport gets, and it is the honest behaviour (no facts ⇒
// no second chance). Production must not be in that state, which is why the
// composition root asserts reachability at boot instead of hoping.
func Wrap(inner Relations, facts FactSource) *Client {
	return &Client{Relations: inner, facts: facts}
}

// SecondChanceReachable reports whether a Wrap'd client can actually give the second
// chance. The boot guard reads it, so "the gates silently went back to waiting for a
// queue" cannot be a runtime surprise.
func (c *Client) SecondChanceReachable() bool {
	return c != nil && c.Relations != nil && c.facts != nil
}

// Check — clients.RelationStore / authzguard.RelationChecker.
func (c *Client) Check(ctx context.Context, subject, relation, object string) (bool, error) {
	// Facts already read for this object (a page prefetch, page_memo.go) ride along with
	// the FIRST question instead of being used to re-ask a denied one. Not a shortcut past
	// the ordinary resolve: a contextual tuple can only ADD a resolution path, so one
	// question carrying true facts has exactly the answer the ask-then-re-ask pair has.
	if facts, known := c.memoFacts(ctx, object); known && len(facts) > 0 {
		return c.Relations.CheckWithContextualTuples(ctx, subject, relation, object, nil, facts)
	} else if known {
		return c.Relations.Check(ctx, subject, relation, object) // read, nothing to add
	}
	allowed, err := c.Relations.Check(ctx, subject, relation, object)
	if allowed || err != nil {
		return allowed, err
	}
	return c.secondChance(ctx, subject, relation, object, nil)
}

// CheckWithContext — clients.RelationQueries / authzfilter.ObjectChecker.
func (c *Client) CheckWithContext(
	ctx context.Context, subject, relation, object string, condCtx map[string]any,
) (bool, error) {
	if facts, known := c.memoFacts(ctx, object); known && len(facts) > 0 {
		return c.Relations.CheckWithContextualTuples(ctx, subject, relation, object, condCtx, facts)
	} else if known {
		return c.Relations.CheckWithContext(ctx, subject, relation, object, condCtx)
	}
	allowed, err := c.Relations.CheckWithContext(ctx, subject, relation, object, condCtx)
	if allowed || err != nil {
		return allowed, err
	}
	return c.secondChance(ctx, subject, relation, object, condCtx)
}

// secondChance re-asks a denied question with the structural facts of its object.
//
// Returns (allowed, err). A non-nil err means the fact could not be read; the caller
// must surface that rather than fold it into the denial — the fact is part of the
// decision, and an unread fact is an unknown answer. This is the same line the edge
// draws (service.AuthorizeService.structuralFallback) and the same line the
// neighbouring page filter draws on a Check error.
func (c *Client) secondChance(
	ctx context.Context, subject, relation, object string, condCtx map[string]any,
) (bool, error) {
	if c.facts == nil {
		return false, nil
	}
	ref, ok := parseObjectRef(object)
	if !ok || !c.facts.Derivable(ref.Type) {
		return false, nil // no read for an object iam does not own
	}
	facts, err := c.facts.StructuralFacts(ctx, ref.Type, ref.ID)
	if err != nil {
		return false, err
	}
	if len(facts) == 0 {
		return false, nil
	}
	return c.Relations.CheckWithContextualTuples(ctx, subject, relation, object, condCtx, facts)
}

// Compile-time guards: the wrapper must be substitutable for the transport at every
// port the composition root wires.
var (
	_ Relations               = (*Client)(nil)
	_ clients.RelationStore   = (*Client)(nil)
	_ clients.RelationQueries = (*Client)(nil)
)
