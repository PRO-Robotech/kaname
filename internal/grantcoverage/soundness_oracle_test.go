// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Независимый оракул конечного мира: успешное доказательство не даёт лишних прав.
package grantcoverage

import (
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// Точка — конкретное разрешение, а не импликация селекторов.
// Мир включает отсутствующие метки и представителей будущих объектов/действий.
type oraclePoint struct {
	kind                EffectKind
	anchor              Anchor
	role                domain.RoleID
	module, typ, object string
	action              Action
	labels              map[string]string
	creator             domain.Subject
}

func oracleContains(e Effect, p oraclePoint) bool {
	if e.Kind != p.kind || e.Anchor != p.anchor {
		return false
	}
	if p.kind == CreateBinding {
		return true
	}
	if p.kind == BindRole {
		return e.RoleID == p.role
	}
	r := e.Resource
	if r.Module != p.module || r.Type != p.typ {
		return false
	}
	if r.Action.Kind == AllVerbs {
		if p.action.Kind != Verb {
			return false
		}
	} else if r.Action != p.action {
		return false
	}
	if r.Region.Objects.Kind == ObjectIDs {
		present := false
		for _, id := range r.Region.Objects.IDs {
			if id == p.object {
				present = true
			}
		}
		if !present {
			return false
		}
	}
	for key, value := range r.Region.Labels {
		actual, present := p.labels[key]
		if !present || value != actual {
			return false
		}
	}
	return r.Region.Creator.Kind == AnyCreator || r.Region.Creator.Subject == p.creator
}
func oracleUnion(es []Effect, p oraclePoint) bool {
	for _, e := range es {
		if oracleContains(e, p) {
			return true
		}
	}
	return false
}
func oracleWorld() []oraclePoint {
	var out []oraclePoint
	anchors := []Anchor{{Type: "account", ID: "acc-a"}, {Type: "project", ID: "prj-a"}, {Type: "project", ID: "prj-b"}}
	creators := []domain.Subject{{}, {Type: domain.SubjectTypeUser, ID: "same"}, {Type: domain.SubjectTypeServiceAccount, ID: "same"}, {Type: domain.SubjectTypeServiceAccount, ID: "other"}}
	actions := []Action{{Kind: Verb, Name: "get"}, {Kind: Verb, Name: "update"}, {Kind: Verb, Name: "future"}, {Kind: Relation, Name: "get"}, {Kind: Relation, Name: "reader"}}
	for _, a := range anchors {
		out = append(out, oraclePoint{kind: CreateBinding, anchor: a})
		for _, role := range []domain.RoleID{"r1", "r2", "future-role"} {
			out = append(out, oraclePoint{kind: BindRole, anchor: a, role: role})
		}
		for _, mod := range []string{"probemod", "other"} {
			for _, typ := range []string{"boxes", "items"} {
				for _, id := range []string{"x", "y", "future-object"} {
					for _, env := range []string{"<absent>", "", "prod", "dev"} {
						for _, team := range []string{"<absent>", "a", "b"} {
							labels := map[string]string{}
							if env != "<absent>" {
								labels["env"] = env
							}
							if team != "<absent>" {
								labels["team"] = team
							}
							for _, c := range creators {
								for _, act := range actions {
									out = append(out, oraclePoint{kind: ResourceUse, anchor: a, module: mod, typ: typ, object: id, action: act, labels: labels, creator: c})
								}
							}
						}
					}
				}
			}
		}
	}
	return out
}

// TestFiniteWorldSoundness проверяет: Proved влечёт семантическое включение.
// Отказы неполного вычисления допустимы. Перечисляются состояния мира;
// алгоритм regionCovers и полнота производственного normalizer не повторяются.
func TestFiniteWorldSoundness(t *testing.T) {
	world := oracleWorld()
	seed := uint32(0x1034)
	next := func(n int) int { seed = 1664525*seed + 1013904223; return int(seed % uint32(n)) }
	makeEffect := func() Effect {
		anchors := []Anchor{{Type: "account", ID: "acc-a"}, {Type: "project", ID: "prj-a"}, {Type: "project", ID: "prj-b"}}
		e := Effect{Kind: EffectKind(1 + next(3)), Anchor: anchors[next(len(anchors))]}
		if e.Kind == BindRole {
			e.RoleID = []domain.RoleID{"r1", "r2"}[next(2)]
			return e
		}
		if e.Kind == CreateBinding {
			return e
		}
		e.Resource = Resource{Module: []string{"probemod", "other"}[next(2)], Type: []string{"boxes", "items"}[next(2)],
			Action: []Action{{Kind: Verb, Name: "get"}, {Kind: Verb, Name: "update"}, {Kind: Relation, Name: "get"}, {Kind: Relation, Name: "reader"}, {Kind: AllVerbs}}[next(5)],
			Region: Region{Objects: Objects{Kind: AllObjects}, Creator: Creator{Kind: AnyCreator}}}
		if next(2) == 1 {
			e.Resource.Region.Objects = Objects{Kind: ObjectIDs, IDs: [][]string{{"x"}, {"y"}, {"x", "y"}}[next(3)]}
		}
		e.Resource.Region.Labels = map[string]string{}
		if next(2) == 1 {
			e.Resource.Region.Labels["env"] = []string{"", "prod", "dev"}[next(3)]
		}
		if next(2) == 1 {
			e.Resource.Region.Labels["team"] = []string{"a", "b"}[next(2)]
		}
		if next(2) == 1 {
			e.Resource.Region.Creator = Creator{Kind: ExactCreator, Subject: []domain.Subject{{Type: domain.SubjectTypeUser, ID: "same"}, {Type: domain.SubjectTypeServiceAccount, ID: "same"}, {Type: domain.SubjectTypeServiceAccount, ID: "other"}}[next(3)]}
		}
		return e
	}
	identity := Identity{ModelID: "oracle-model", CatalogID: "oracle-catalog", ProjectorVersion: "test-projector/v1"}
	proved := 0
	for i := 0; i < 180; i++ {
		actor := []Effect{makeEffect(), makeEffect(), makeEffect()}
		proposed := []Effect{makeEffect(), makeEffect()}
		// Положительные контроли перемежаются с остальными запросами.
		// Расширение источника не использует производственный алгоритм сравнения.
		if i%3 == 0 {
			proposed = []Effect{actor[0]}
			if actor[0].Kind == ResourceUse {
				actor[0].Resource.Region = Region{Objects: Objects{Kind: AllObjects}, Creator: Creator{Kind: AnyCreator}}
				if actor[0].Resource.Action.Kind == Verb {
					actor[0].Resource.Action = Action{Kind: AllVerbs}
				}
			}
		}
		req := Request{Identity: identity, Actor: EffectSet{Identity: identity, Complete: true, Effects: actor}, Proposed: EffectSet{Identity: identity, Complete: true, Effects: proposed}}
		result := Prove(req)
		if result.Status != Proved {
			continue
		}
		proved++
		for _, point := range world {
			if oracleUnion(proposed, point) && !oracleUnion(actor, point) {
				t.Fatalf("false proof case=%d point=%+v request=%+v", i, point, req)
			}
		}
	}
	if proved < 60 {
		t.Fatalf("missing positive controls: proved=%d", proved)
	}
}

// Исчерпание вычисления отличается от отсутствия права. Будущее подключение
// к API не должно превращать этот исход в PermissionDenied.
func TestWorkExhaustionDependsOnOrderingButIsDistinct(t *testing.T) {
	makeUse := func(id string) Effect {
		return Effect{Kind: ResourceUse, Anchor: Anchor{Type: "project", ID: "prj-a"}, Resource: Resource{Module: "probemod", Type: "boxes", Action: Action{Kind: Verb, Name: "get"}, Region: Region{Objects: Objects{Kind: ObjectIDs, IDs: []string{id}}, Creator: Creator{Kind: AnyCreator}}}}
	}
	actor, proposed := make([]Effect, 1100), make([]Effect, 1100)
	for i := range actor {
		actor[i] = makeUse("a")
		proposed[i] = makeUse("b")
	}
	actor[len(actor)-1] = makeUse("b")
	identity := Identity{ModelID: "oracle-model", CatalogID: "oracle-catalog", ProjectorVersion: "test-projector/v1"}
	req := Request{Identity: identity, Actor: EffectSet{Identity: identity, Complete: true, Effects: actor}, Proposed: EffectSet{Identity: identity, Complete: true, Effects: proposed}}
	if r := Prove(req); r.Status != NotProved || r.Reason != ReasonWorkLimit {
		t.Fatalf("late witness: %+v", r)
	}
	actor[0], actor[len(actor)-1] = actor[len(actor)-1], actor[0]
	if r := Prove(req); r.Status != Proved {
		t.Fatalf("early witness: %+v", r)
	}
}
