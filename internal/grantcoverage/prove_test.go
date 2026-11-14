// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package grantcoverage

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

func resourceEffect(verb string, ids ...string) Effect {
	objects := Objects{Kind: AllObjects}
	if len(ids) != 0 {
		objects = Objects{Kind: ObjectIDs, IDs: ids}
	}
	return Effect{
		Kind: ResourceUse, Anchor: Anchor{Type: "project", ID: "prj-a"},
		Resource: Resource{Module: "probemod", Type: "boxes", Action: Action{Kind: Verb, Name: verb},
			Region: Region{Objects: objects, Creator: Creator{Kind: AnyCreator}}},
	}
}
func withLabels(e Effect, labels map[string]string) Effect {
	e.Resource.Region.Labels = labels
	return e
}
func withCreator(e Effect, id string) Effect {
	e.Resource.Region.Creator = Creator{Kind: ExactCreator, Subject: domain.Subject{Type: domain.SubjectTypeServiceAccount, ID: domain.SubjectID(id)}}
	return e
}
func withAnchor(e Effect, scope domain.Scope, id string) Effect {
	e.Anchor = Anchor{Type: strings.ToLower(scope.String()), ID: id}
	return e
}
func allVerbs(e Effect) Effect { e.Resource.Action = Action{Kind: AllVerbs}; return e }
func relation(e Effect, name string) Effect {
	e.Resource.Action = Action{Kind: Relation, Name: name}
	return e
}
func bind(role string) Effect {
	return Effect{Kind: BindRole, Anchor: Anchor{Type: "account", ID: "acc-a"}, RoleID: domain.RoleID(role)}
}
func createBinding() Effect { e := bind(""); e.Kind = CreateBinding; return e }
func request(actor, proposed []Effect) Request {
	id := Identity{ModelID: "model-1", CatalogID: "catalog-1", ProjectorVersion: "test-projector/v1"}
	return Request{Identity: id, Actor: EffectSet{Identity: id, Complete: true, Effects: actor},
		Proposed: EffectSet{Identity: id, Complete: true, Effects: proposed}}
}

func TestProveCoverageCounterexamples(t *testing.T) {
	get := resourceEffect("get")
	update := resourceEffect("update")
	a := resourceEffect("get", "a")
	b := resourceEffect("get", "b")
	ab := resourceEffect("get", "a", "b")
	prod := withLabels(get, map[string]string{"env": "prod"})
	prodBlue := withLabels(get, map[string]string{"env": "prod", "team": "blue"})
	cases := []struct {
		name            string
		actor, proposed []Effect
		status          Status
		reason          Reason
	}{
		{"union_across_rules", []Effect{get, update}, []Effect{get, update}, Proved, ReasonNone},
		{"one_missing_verb", []Effect{get}, []Effect{get, update}, NotProved, ReasonUncovered},
		{"split_named_objects", []Effect{a, b}, []Effect{ab}, Proved, ReasonNone},
		{"missing_named_object", []Effect{a}, []Effect{ab}, NotProved, ReasonUncovered},
		{"universal_covers_names", []Effect{get}, []Effect{ab}, Proved, ReasonNone},
		{"names_never_cover_universal", []Effect{a, b}, []Effect{get}, NotProved, ReasonUncovered},
		{"symbolic_star_covers_finite", []Effect{allVerbs(get)}, []Effect{get, update}, Proved, ReasonNone},
		{"symbolic_star_covers_future_verb", []Effect{allVerbs(get)}, []Effect{resourceEffect("futureAction")}, Proved, ReasonNone},
		{"finite_current_verbs_never_cover_star", []Effect{get, update, resourceEffect("create"), resourceEffect("delete"), resourceEffect("list")}, []Effect{allVerbs(get)}, NotProved, ReasonUncovered},
		{"symbolic_star_identity", []Effect{allVerbs(get)}, []Effect{allVerbs(get)}, Proved, ReasonNone},
		{"named_star_never_covers_universal_star", []Effect{allVerbs(a), allVerbs(b)}, []Effect{allVerbs(get)}, NotProved, ReasonUncovered},
		{"broad_labels_cover_stricter", []Effect{prod}, []Effect{prodBlue}, Proved, ReasonNone},
		{"stricter_labels_do_not_cover_broad", []Effect{prodBlue}, []Effect{prod}, NotProved, ReasonUncovered},
		{"label_union_not_assumed_exhaustive", []Effect{prod, withLabels(get, map[string]string{"env": "test"})}, []Effect{get}, NotProved, ReasonUncovered},
		{"one_broader_label_term_suffices", []Effect{withLabels(get, map[string]string{"env": "test"}), prod}, []Effect{prodBlue}, Proved, ReasonNone},
		{"empty_label_value_not_absent", []Effect{withLabels(get, map[string]string{"empty": ""})}, []Effect{get}, NotProved, ReasonUncovered},
		{"named_vs_labels_no_invented_facts", []Effect{prod}, []Effect{a}, NotProved, ReasonUncovered},
		{"labels_vs_named_no_live_enumeration", []Effect{a, b}, []Effect{prod}, NotProved, ReasonUncovered},
		{"normalized_intersection_labels_and_target", []Effect{prod}, []Effect{withLabels(ab, map[string]string{"env": "prod"})}, Proved, ReasonNone},
		{"split_names_with_normalized_constraints", []Effect{withLabels(a, map[string]string{"env": "prod"}), b}, []Effect{withLabels(ab, map[string]string{"env": "prod", "team": "blue"})}, Proved, ReasonNone},
		{"same_resolved_creator", []Effect{withCreator(get, "sa-a")}, []Effect{withCreator(get, "sa-a")}, Proved, ReasonNone},
		{"different_creator", []Effect{withCreator(get, "sa-a")}, []Effect{withCreator(get, "sa-b")}, NotProved, ReasonUncovered},
		{"universal_covers_creator", []Effect{get}, []Effect{withCreator(get, "sa-a")}, Proved, ReasonNone},
		{"creator_never_covers_universal", []Effect{withCreator(get, "sa-a")}, []Effect{get}, NotProved, ReasonUncovered},
		{"exact_normalized_relation", []Effect{relation(get, "reader")}, []Effect{relation(get, "reader")}, Proved, ReasonNone},
		{"verb_relation_same_text_distinct", []Effect{get}, []Effect{relation(get, "get")}, NotProved, ReasonUncovered},
		{"verb_star_never_covers_relation", []Effect{allVerbs(get)}, []Effect{relation(get, "reader")}, NotProved, ReasonUncovered},
		{"relation_no_implied_tier_ranking", []Effect{relation(get, "editor")}, []Effect{relation(get, "reader")}, NotProved, ReasonUncovered},
		{"no_implicit_account_project_cascade", []Effect{withAnchor(get, domain.ScopeAccount, "acc-a")}, []Effect{get}, NotProved, ReasonUncovered},
		{"bind_exact_role_and_scope", []Effect{bind("osetr")}, []Effect{bind("osetr")}, Proved, ReasonNone},
		{"bind_treska_is_not_bind_osetr", []Effect{bind("treska")}, []Effect{bind("osetr")}, NotProved, ReasonUncovered},
		{"bind_other_account", []Effect{bind("osetr")}, []Effect{withAnchor(bind("osetr"), domain.ScopeAccount, "acc-b")}, NotProved, ReasonUncovered},
		{"bind_account_does_not_cover_project", []Effect{bind("osetr")}, []Effect{withAnchor(bind("osetr"), domain.ScopeProject, "prj-a")}, NotProved, ReasonUncovered},
		{"bind_project_does_not_cover_sibling", []Effect{withAnchor(bind("osetr"), domain.ScopeProject, "prj-a")}, []Effect{withAnchor(bind("osetr"), domain.ScopeProject, "prj-b")}, NotProved, ReasonUncovered},
		{"create_binding_exact_scope", []Effect{createBinding()}, []Effect{createBinding()}, Proved, ReasonNone},
		{"create_binding_other_scope", []Effect{createBinding()}, []Effect{withAnchor(createBinding(), domain.ScopeAccount, "acc-b")}, NotProved, ReasonUncovered},
		{"create_not_bind", []Effect{createBinding()}, []Effect{bind("osetr")}, NotProved, ReasonUncovered},
		{"bind_not_create", []Effect{bind("osetr")}, []Effect{createBinding()}, NotProved, ReasonUncovered},
		{"meta_not_resource_use", []Effect{createBinding(), bind("osetr")}, []Effect{get}, NotProved, ReasonUncovered},
		{"proposed_meta_does_not_authorize_itself", []Effect{get}, []Effect{get, createBinding(), bind("osetr")}, NotProved, ReasonUncovered},
		{"mixed_unknown_proposal", []Effect{get}, []Effect{get, {Kind: Unsupported, UnsupportedReason: "children_not_normalized"}}, NotProved, ReasonUnsupported},
		{"unknown_actor_not_dropped", []Effect{get, {Kind: Unsupported, UnsupportedReason: "condition_not_normalized"}}, []Effect{get}, NotProved, ReasonUnsupported},
		{"empty_actor_covers_no_effect", nil, []Effect{get}, NotProved, ReasonUncovered},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Prove(request(tc.actor, tc.proposed))
			if got.Status != tc.status || got.Reason != tc.reason {
				t.Fatalf("got %+v, want status %v reason %s", got, tc.status, tc.reason)
			}
		})
	}
}

func TestResourceCoordinatesAndMetaSeparation(t *testing.T) {
	for _, mutate := range []func(*Effect){
		func(e *Effect) { e.Resource.Module = "other" },
		func(e *Effect) { e.Resource.Type = "other" },
		func(e *Effect) { e.Anchor.ID = "prj-b" },
		func(e *Effect) { e.Anchor.Type = "account"; e.Anchor.ID = "acc-a" },
	} {
		held, wanted := resourceEffect("get"), resourceEffect("get")
		mutate(&held)
		if got := Prove(request([]Effect{held}, []Effect{wanted})); got.Status != NotProved {
			t.Fatalf("coordinate mismatch: %+v", got)
		}
	}
	for _, resourceType := range []string{"role", "accessBinding"} {
		held := withAnchor(allVerbs(resourceEffect("get")), domain.ScopeAccount, "acc-a")
		held.Resource.Module, held.Resource.Type = "iam", resourceType
		for _, wanted := range []Effect{createBinding(), bind("osetr")} {
			if got := Prove(request([]Effect{held}, []Effect{wanted})); got.Status != NotProved {
				t.Fatalf("resource wildcard covered meta: %+v", got)
			}
		}
	}
}

func TestTreskaOsetrRolePartitionIsNotAnAuthorityCoordinate(t *testing.T) {
	// Это только синтетические входы ядра. Никакой Role API здесь не вызывается.
	type roleEffects struct {
		roleID  string
		effects []Effect
	}
	roles := []roleEffects{
		{"treska", []Effect{resourceEffect("get", "a")}},
		{"another-role", []Effect{resourceEffect("get", "b"), resourceEffect("update", "a", "b")}},
	}
	osetr := roleEffects{"osetr", []Effect{resourceEffect("get", "a", "b"), resourceEffect("update", "a", "b")}}
	var held []Effect
	for _, role := range roles {
		if role.roleID == osetr.roleID {
			t.Fatal("fixture must use different role IDs")
		}
		held = append(held, role.effects...)
	}
	if got := Prove(request(held, osetr.effects)); got.Status != Proved {
		t.Fatalf("union: %+v", got)
	}
	// Перестановка и иное разбиение конечных множеств сохраняют доказательство.
	repartitioned := []Effect{resourceEffect("update", "b"), resourceEffect("get", "b", "a"), resourceEffect("update", "a")}
	if got := Prove(request(repartitioned, osetr.effects)); got.Status != Proved {
		t.Fatalf("repartition: %+v", got)
	}
}

func TestValidationCannotDisappearIntoEmptyProof(t *testing.T) {
	cases := []struct {
		name   string
		edit   func(*Request)
		status Status
		reason Reason
	}{
		{"zero_request", func(r *Request) { *r = Request{} }, Invalid, ReasonMalformed},
		{"empty_default_rejected", func(r *Request) { r.Proposed.Effects = nil }, NotProved, ReasonEmpty},
		{"explicit_empty_subset", func(r *Request) { r.Proposed.Effects = nil; r.Empty = ProveEmpty }, Proved, ReasonNone},
		{"both_empty_explicit_subset", func(r *Request) { r.Actor.Effects = nil; r.Proposed.Effects = nil; r.Empty = ProveEmpty }, Proved, ReasonNone},
		{"empty_with_unknown_actor", func(r *Request) {
			r.Actor.Effects = []Effect{{Kind: Unsupported, UnsupportedReason: "custom_relation"}}
			r.Proposed.Effects = nil
			r.Empty = ProveEmpty
		}, NotProved, ReasonUnsupported},
		{"empty_with_invalid_actor", func(r *Request) { r.Actor.Effects = []Effect{{}}; r.Proposed.Effects = nil; r.Empty = ProveEmpty }, Invalid, ReasonMalformed},
		{"empty_with_incomplete_actor", func(r *Request) { r.Actor.Complete = false; r.Proposed.Effects = nil; r.Empty = ProveEmpty }, NotProved, ReasonIncomplete},
		{"incomplete_proposal", func(r *Request) { r.Proposed.Complete = false }, NotProved, ReasonIncomplete},
		{"model_mismatch_same_opaque_effect", func(r *Request) { r.Actor.Identity.ModelID = "model-2" }, NotProved, ReasonIdentity},
		{"catalog_mismatch_same_opaque_effect", func(r *Request) { r.Proposed.Identity.CatalogID = "catalog-2" }, NotProved, ReasonIdentity},
		{"both_sets_wrong_pinned_identity", func(r *Request) { r.Identity.ModelID = "model-2" }, NotProved, ReasonIdentity},
		{"empty_with_model_mismatch", func(r *Request) { r.Actor.Identity.ModelID = "model-2"; r.Proposed.Effects = nil; r.Empty = ProveEmpty }, NotProved, ReasonIdentity},
		{"unknown_empty_policy", func(r *Request) { r.Empty = EmptyPolicy(255) }, Invalid, ReasonMalformed},
		{"missing_catalog_identity", func(r *Request) { r.Identity.CatalogID = "" }, Invalid, ReasonMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := request([]Effect{resourceEffect("get")}, []Effect{resourceEffect("get")})
			tc.edit(&r)
			got := Prove(r)
			if got.Status != tc.status || got.Reason != tc.reason {
				t.Fatalf("got %+v, want %v/%s", got, tc.status, tc.reason)
			}
		})
	}
}

func TestMalformedSelectorsAndTaggedPayloads(t *testing.T) {
	cases := []struct {
		name string
		edit func(*Effect)
	}{
		{"unknown_effect", func(e *Effect) { e.Kind = EffectKind(255) }},
		{"unknown_scope", func(e *Effect) { e.Anchor.Type = "unknown" }},
		{"anchor_type_id_mismatch", func(e *Effect) { e.Anchor.Type = "account" }},
		{"missing_anchor", func(e *Effect) { e.Anchor.ID = "" }},
		{"unknown_action", func(e *Effect) { e.Resource.Action.Kind = ActionKind(255) }},
		{"literal_star_verb", func(e *Effect) { e.Resource.Action.Name = "*" }},
		{"star_with_name", func(e *Effect) { e.Resource.Action = Action{Kind: AllVerbs, Name: "get"} }},
		{"wildcard_module", func(e *Effect) { e.Resource.Module = "*" }},
		{"wildcard_type", func(e *Effect) { e.Resource.Type = "*" }},
		{"unknown_object_selector", func(e *Effect) { e.Resource.Region.Objects.Kind = ObjectKind(255) }},
		{"finite_empty_selector", func(e *Effect) { e.Resource.Region.Objects = Objects{Kind: ObjectIDs} }},
		{"universal_with_hidden_ids", func(e *Effect) { e.Resource.Region.Objects.IDs = []string{"a"} }},
		{"empty_object_id", func(e *Effect) { e.Resource.Region.Objects = Objects{Kind: ObjectIDs, IDs: []string{""}} }},
		{"symbolic_object_id", func(e *Effect) { e.Resource.Region.Objects = Objects{Kind: ObjectIDs, IDs: []string{"*"}} }},
		{"empty_label_key", func(e *Effect) { e.Resource.Region.Labels = map[string]string{"": "prod"} }},
		{"invalid_utf8_label", func(e *Effect) { e.Resource.Region.Labels = map[string]string{"env": string([]byte{0xff})} }},
		{"unknown_creator", func(e *Effect) { e.Resource.Region.Creator.Kind = CreatorKind(255) }},
		{"unresolved_creator", func(e *Effect) { e.Resource.Region.Creator = Creator{Kind: ExactCreator} }},
		{"universal_creator_hidden_subject", func(e *Effect) {
			e.Resource.Region.Creator.Subject = domain.Subject{Type: domain.SubjectTypeUser, ID: "usr-a"}
		}},
		{"creator_group_not_concrete", func(e *Effect) {
			e.Resource.Region.Creator = Creator{Kind: ExactCreator, Subject: domain.Subject{Type: domain.SubjectTypeGroup, ID: "grp-a"}}
		}},
		{"resource_hidden_role", func(e *Effect) { e.RoleID = "osetr" }},
		{"resource_hidden_unsupported", func(e *Effect) { e.UnsupportedReason = "condition" }},
		{"meta_hidden_resource", func(e *Effect) { e.Kind = CreateBinding }},
		{"bind_missing_role", func(e *Effect) { *e = bind("") }},
		{"bind_wildcard_role", func(e *Effect) { *e = bind("*") }},
		{"unsupported_missing_reason", func(e *Effect) { *e = Effect{Kind: Unsupported} }},
		{"unsupported_hidden_resource", func(e *Effect) { e.Kind = Unsupported; e.UnsupportedReason = "condition" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := resourceEffect("get")
			tc.edit(&e)
			for _, actor := range []bool{false, true} {
				r := request([]Effect{resourceEffect("get")}, []Effect{resourceEffect("get")})
				if actor {
					r.Actor.Effects = append(r.Actor.Effects, e)
				} else {
					r.Proposed.Effects = append(r.Proposed.Effects, e)
				}
				got := Prove(r)
				if got.Status != Invalid || got.Reason != ReasonMalformed {
					t.Fatalf("actor=%v: %+v", actor, got)
				}
			}
		})
	}
}

func TestResolvedCreatorIncludesSubjectType(t *testing.T) {
	held := withCreator(resourceEffect("get"), "same-id")
	wanted := held
	wanted.Resource.Region.Creator.Subject.Type = domain.SubjectTypeUser
	if got := Prove(request([]Effect{held}, []Effect{wanted})); got.Status != NotProved || got.Reason != ReasonUncovered {
		t.Fatalf("different subject types with same ID: %+v", got)
	}
}

func TestWholeProposalAndFailureLocation(t *testing.T) {
	r := request([]Effect{resourceEffect("get")}, []Effect{resourceEffect("get"), resourceEffect("update")})
	if got := Prove(r); got != (Result{Status: NotProved, Reason: ReasonUncovered, Side: ProposedSide, Index: 1}) {
		t.Fatalf("got %+v", got)
	}
	r.Actor.Effects = append(r.Actor.Effects, Effect{Kind: Unsupported, UnsupportedReason: "condition"})
	if got := Prove(r); got != (Result{Status: NotProved, Reason: ReasonUnsupported, Side: ActorSide, Index: 1}) {
		t.Fatalf("got %+v", got)
	}
	if (Result{}).Status == Proved {
		t.Fatal("zero result must never prove")
	}
}

func TestPureInputImmutability(t *testing.T) {
	actor := []Effect{withLabels(resourceEffect("get", "b", "a"), map[string]string{"env": "prod"}), withCreator(resourceEffect("update", "b", "a"), "sa-a")}
	proposed := []Effect{withLabels(resourceEffect("get", "a", "b"), map[string]string{"team": "blue", "env": "prod"}), withCreator(resourceEffect("update", "a"), "sa-a")}
	r := request(actor, proposed)
	before, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	first := Prove(r)
	if first.Status != Proved {
		t.Fatalf("fixture: %+v", first)
	}
	for i := 0; i < 10; i++ {
		if got := Prove(r); got != first {
			t.Fatalf("result changed: %+v vs %+v", got, first)
		}
	}
	after, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("input changed")
	}
}

func TestStructuralAndWorkLimitsFailClosed(t *testing.T) {
	cases := []struct {
		name string
		edit func(*Request)
	}{
		{"effects", func(r *Request) { r.Actor.Effects = make([]Effect, MaxEffects+1) }},
		{"combined_effects", func(r *Request) { r.Actor.Effects = make([]Effect, MaxEffects) }},
		{"selector_entries", func(r *Request) {
			r.Actor.Effects[0].Resource.Region.Objects = Objects{Kind: ObjectIDs, IDs: make([]string, MaxSelectorEntries+1)}
		}},
		{"string_bytes", func(r *Request) { r.Actor.Effects[0].Resource.Type = strings.Repeat("x", MaxStringBytes+1) }},
		{"aggregate_bytes", func(r *Request) {
			r.Actor.Effects = make([]Effect, MaxInputBytes/MaxStringBytes+1)
			for i := range r.Actor.Effects {
				r.Actor.Effects[i] = resourceEffect("get")
				r.Actor.Effects[i].Resource.Type = strings.Repeat("x", MaxStringBytes)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := request([]Effect{resourceEffect("get")}, []Effect{resourceEffect("get")})
			tc.edit(&r)
			if got := Prove(r); got.Status != Invalid || got.Reason != ReasonLimit {
				t.Fatalf("got %+v", got)
			}
		})
	}
	// Совместимые пары стоят N²: ограничиваем работу явно, без переполнения.
	actor, proposed := make([]Effect, 1100), make([]Effect, 1100)
	for i := range actor {
		actor[i] = resourceEffect("get", "a")
	}
	actor[len(actor)-1] = resourceEffect("get", "b")
	for i := range proposed {
		proposed[i] = resourceEffect("get", "b")
	}
	if got := Prove(request(actor, proposed)); got.Status != NotProved || got.Reason != ReasonWorkLimit {
		t.Fatalf("work limit: %+v", got)
	}
}

func TestCoverageRequiresProjectorIdentity(t *testing.T) {
	get := resourceEffect("get")
	req := request([]Effect{get}, []Effect{get})
	if got := Prove(req); got.Status != Proved {
		t.Fatalf("positive control: %+v", got)
	}
	req.Proposed.Identity.ProjectorVersion = "test-projector/v2"
	if got := Prove(req); got.Reason != ReasonIdentity {
		t.Fatalf("cross-version: %+v", got)
	}
	req = request([]Effect{get}, []Effect{get})
	req.Identity.ProjectorVersion = ""
	req.Actor.Identity.ProjectorVersion = ""
	req.Proposed.Identity.ProjectorVersion = ""
	if got := Prove(req); got.Status == Proved {
		t.Fatal("пустая общая версия не должна доказывать покрытие")
	}
}
