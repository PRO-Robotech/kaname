// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"bytes"
	"context"
	"encoding/json"
	"sort"
	"strings"

	"github.com/PRO-Robotech/kaname/internal/authzplan"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/grantcapability"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	"github.com/PRO-Robotech/kaname/internal/hierarchy"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
)

const nativeReadPage = 256
const nativeReadNodes = 4096

// Бюджет считает returned rows и retained derived slots, не storage I/O.
// Передаётся один на весь discovery. Caller объединяет его с source
// census; конструктор на каждый question заново создавать нельзя.
type nativeReadBudget struct {
	rows, reads int
	shared      *relverdict.AdministrativeReadBudget
}

func (b *nativeReadBudget) charge(rows, reads int) error {
	if b == nil || rows < 0 || reads < 0 || rows > 100000-b.rows || reads > 4096-b.reads {
		return kaname.ErrSourceReadLimit
	}
	if b.shared != nil {
		if err := chargeNativePolicyBudget(b.shared, rows, reads); err != nil {
			return err
		}
	}
	b.rows += rows
	b.reads += reads
	return nil
}

type nativeReadNode struct{ typ, id string }
type nativeReadFactSlot struct {
	node     nativeReadNode
	relation string
}
type nativeReadShape struct {
	scopes     map[nativeReadNode]bool
	facts      map[nativeReadFactSlot]bool
	verbs      map[string]bool
	capability bool
}

// Это captured dependency description, НЕ held-fence/authority proof. Пакет
// не локализует triggers и не устанавливает checker до coherent integration.
type nativeReadBoundary struct {
	bundle        *granteffect.Bundle
	questions     map[nativePolicyQuestion]nativeReadShape
	accounts      map[string]bool
	guards        map[string]bool
	globalReasons map[string]bool
	epochs        json.RawMessage
}
type nativeReadSnapshot interface {
	parents(context.Context, nativeReadNode, nativeReadNode, int) ([]nativeReadNode, error)
	account(context.Context, nativeReadNode) (string, error)
}

func nativeNodeLess(a, b nativeReadNode) bool {
	return a.typ < b.typ || (a.typ == b.typ && a.id < b.id)
}
func (p *nativeReadBoundary) reason(s string) { p.globalReasons[s] = true }
func (p *nativeReadBoundary) global() bool    { return p == nil || len(p.globalReasons) > 0 }
func (p *nativeReadBoundary) guardKeys() []string {
	keys := []string{"*"}
	if p.global() {
		return keys
	}
	for k := range p.guards {
		if k != "*" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}
func captureNativeReadBoundary(ctx context.Context, bundle *granteffect.Bundle, questions *nativePolicyQuestions, snapshot nativeReadSnapshot, budget *nativeReadBudget) (*nativeReadBoundary, error) {
	if bundle.Validate() != nil || snapshot == nil || budget == nil {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	roots, err := questions.ordered(ctx)
	if err != nil {
		return nil, err
	}
	p := &nativeReadBoundary{bundle: bundle, questions: map[nativePolicyQuestion]nativeReadShape{}, accounts: map[string]bool{}, guards: map[string]bool{"*": true}, globalReasons: map[string]bool{}}
	// RR-local cache не превращает чужой parent graph в общий mutable cache.
	cache := map[nativeReadNode][]nativeReadNode{}
	accounts := map[nativeReadNode]string{}
	for _, q := range roots {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		if err = budget.charge(1, 0); err != nil {
			return nil, err
		}
		shape := nativeReadShape{scopes: map[nativeReadNode]bool{}, facts: map[nativeReadFactSlot]bool{}, verbs: map[string]bool{}}
		root := nativeReadNode{q.objectType, q.objectID}
		var plan authzplan.Plan
		if grantcapability.IsInternalObjectType(q.objectType) {
			ref := grantcapability.Reference{ObjectType: q.objectType, ObjectID: q.objectID, Relation: q.relation}
			coordinate, e := grantcapability.Decode(ref)
			if e != nil {
				return nil, e
			}
			if e = bundle.GrantCapabilityPlan(q.objectType, q.relation); e != nil {
				return nil, e
			}
			root = nativeReadNode{coordinate.Anchor.Type, coordinate.Anchor.ID}
			shape.capability = true
			// Capability arm не читает class facts и не наследует scope. Canonical
			// referent/role/source guards остаются в полном policy source planner.
			if coordinate.RoleID != "" {
				p.guards["role:"+string(coordinate.RoleID)] = true
			}
		} else {
			plan, err = bundle.Plan(q.objectType, q.relation)
			if err != nil {
				return nil, err
			}
			if !plan.Expressible() || len(plan.Conditioned) > 0 {
				p.reason("compiled plan has unknown or conditioned terms")
			}
			for _, a := range plan.Atoms {
				switch a.Kind {
				case authzplan.AtomFact:
				case authzplan.AtomBinding:
					if a.ParentType != "" || !authzplan.IsVerb(a.Relation) {
						p.reason("unsupported binding atom")
					}
					if !shape.verbs[a.Relation] {
						if err = budget.charge(1, 0); err != nil {
							return nil, err
						}
						shape.verbs[a.Relation] = true
					}
				default:
					p.reason("unknown atom kind")
				}
			}
		}
		type item struct {
			node  nativeReadNode
			depth int
		}
		queue := []item{{root, 0}}
		for i := 0; i < len(queue); i++ {
			if err = ctx.Err(); err != nil {
				return nil, err
			}
			node := queue[i].node
			if shape.scopes[node] {
				continue
			}
			if err = budget.charge(1, 0); err != nil {
				return nil, err
			}
			shape.scopes[node] = true
			if len(shape.scopes) > nativeReadNodes {
				return nil, kaname.ErrSourceReadLimit
			}
			account, ok := accounts[node]
			if !ok {
				if err = budget.charge(8, 1); err != nil {
					return nil, err
				}
				account, err = snapshot.account(ctx, node)
				if err != nil {
					return nil, err
				}
				if err = budget.charge(1, 0); err != nil {
					return nil, err
				}
				accounts[node] = account
			}
			if account != "" {
				p.accounts[account] = true
				p.guards["scope:"+account] = true
			} else if node.typ != "cluster" || node.id != domain.ClusterSingletonID {
				p.reason("canonical account absent or unsupported")
			}
			if len(p.guards) > nativeReadNodes || len(p.accounts) > kaname.MaxAuthorityFenceAccounts {
				p.reason("native footprint exceeds local guard budget")
			}
			for _, a := range plan.Atoms {
				if a.Kind == authzplan.AtomFact && ((a.ParentType == "" && node == root) || (a.ParentType != "" && a.ParentType == node.typ)) {
					slot := nativeReadFactSlot{node, a.Relation}
					if !shape.facts[slot] {
						if err = budget.charge(1, 0); err != nil {
							return nil, err
						}
						shape.facts[slot] = true
					}
				}
			}
			if shape.capability {
				continue
			}
			parents, ok := cache[node]
			if !ok {
				after := nativeReadNode{}
				for {
					if err = ctx.Err(); err != nil {
						return nil, err
					}
					if err = budget.charge(0, 1); err != nil {
						return nil, err
					}
					page, e := snapshot.parents(ctx, node, after, nativeReadPage)
					if e != nil {
						return nil, e
					}
					if len(page) > nativeReadPage {
						return nil, kaname.ErrSourceReadLimit
					}
					if err = budget.charge(len(page), 0); err != nil {
						return nil, err
					}
					for _, parent := range page {
						if !nativeQuestionToken(parent.typ) || !nativeQuestionToken(parent.id) || !nativeNodeLess(after, parent) {
							return nil, kaname.ErrCanonicalSourceInvalid
						}
						after = parent
						parents = append(parents, parent)
						if len(parents) > nativeReadNodes {
							return nil, kaname.ErrSourceReadLimit
						}
					}
					if len(page) < nativeReadPage {
						break
					}
				}
				cache[node] = parents
			}
			// Полностью прочитанные четыре родителя допустимы. Глубина обхода
			// и число непосредственных родителей имеют разные границы.
			if len(parents) > hierarchy.MaxImmediateParents {
				p.reason("native parent fanout exceeds query limit")
			}
			if queue[i].depth >= hierarchy.MaxPointerHops {
				if len(parents) > 0 {
					p.reason("native ancestor depth reaches query limit")
				}
				continue
			}
			for _, parent := range parents {
				queue = append(queue, item{parent, queue[i].depth + 1})
			}
			if len(queue) > 100000 {
				return nil, kaname.ErrSourceReadLimit
			}
		}
		p.questions[q] = shape
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	return p, nil
}

// requireQuestion — точная typed root boundary. Не вызывает inner checker и
// потому не выдаёт captured token за held guard. Проверяется до SQL dispatch.
func (p *nativeReadBoundary) requireQuestion(bundle *granteffect.Bundle, subject, relation, object string) error {
	if p == nil || bundle == nil || p.bundle != bundle || bundle.Validate() != nil {
		return kaname.ErrSourceUnconfirmed
	}
	typ, id, ok := strings.Cut(object, ":")
	if !ok {
		return kaname.ErrSourceUnconfirmed
	}
	if _, ok = p.questions[nativePolicyQuestion{subject, relation, typ, id}]; !ok {
		return kaname.ErrSourceUnconfirmed
	}
	return nil
}
func (p *nativeReadBoundary) requireScope(q nativePolicyQuestion, node nativeReadNode) error {
	if p == nil || p.global() {
		return kaname.ErrSourceUnconfirmed
	}
	shape, ok := p.questions[q]
	if !ok || !shape.scopes[node] {
		return kaname.ErrSourceUnconfirmed
	}
	return nil
}
func (p *nativeReadBoundary) requireFactSlot(q nativePolicyQuestion, node nativeReadNode, relation string) error {
	if err := p.requireScope(q, node); err != nil {
		return err
	}
	if !p.questions[q].facts[nativeReadFactSlot{node, relation}] {
		return kaname.ErrSourceUnconfirmed
	}
	return nil
}

// Closed class subset — только dependency classification, НЕ permission и
// НЕ новый SQL trigger. Condition не исчезает из полного native evaluation.
func nativeKnownClassRead(node nativeReadNode, relation, subject, condition string, params json.RawMessage) bool {
	if node.typ != "iam_access_binding" || !nativeQuestionToken(node.id) || condition != "" || !bytes.Equal(bytes.TrimSpace(params), []byte("{}")) {
		return false
	}
	if subject != "system_class:anonymous" && subject != "system_class:authenticated" {
		return false
	}
	return relation == "viewer" || relation == "v_get" || relation == "v_list"
}
