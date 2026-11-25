// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package granteffect

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/grantcapability"
	"github.com/PRO-Robotech/kaname/internal/grantcoverage"
	"github.com/PRO-Robotech/kaname/internal/hierarchy"
)

const maxInitialRegistrationAncestorPaths = 64

// RegistrationAncestor is the held NEW ancestor at the end of a model path
// from the registered object. Each nonempty prefix also needs its own image.
type RegistrationAncestor struct {
	Path   []authzmodel.EffectHop
	Object domain.MirrorObject
}

// InitialRegistrationImage describes a project-scoped external object and its
// canonical NEW ancestors. The writer must establish that OLD is absent and
// hold the registered scope, paths and source census at the decision time.
// This value checks coordinates and specializes effects. It is not a witness
// of source completeness or authority by itself.
type InitialRegistrationImage struct {
	Root      domain.ResourceRef
	New       domain.MirrorObject
	Ancestors []RegistrationAncestor
}

// CompileInitialRegistrationBinding specializes the effects of one held
// binding for one recipient. The writer must supply all binding subjects,
// examine every recipient and check source validity and Grant independently.
func (b *Bundle) CompileInitialRegistrationBinding(binding Binding, image InitialRegistrationImage) MetadataDelta {
	if b.Validate() != nil {
		return MetadataDelta{}
	}
	if len(binding.Subjects) == 0 {
		return b.compiler.initialRegistrationFailure("binding recipient census omitted")
	}
	return b.compiler.compileInitialRegistration(b.compiler.Compile(binding), image, nil)
}

// CompileInitialRegistrationDirect applies the same specialization to a
// direct source, including a new owner tuple or a held inherited source.
func (b *Bundle) CompileInitialRegistrationDirect(source Direct, image InitialRegistrationImage) MetadataDelta {
	if b.Validate() != nil {
		return MetadataDelta{}
	}
	return b.compiler.compileInitialRegistration(b.compiler.CompileDirect(source), image, &source)
}

func (c *Compiler) initialRegistrationFailure(detail string) MetadataDelta {
	result := Set{identity: c.identity, obligations: []Obligation{{Code: "initial_registration", Detail: detail}}}
	return MetadataDelta{Before: result, After: result}
}

func (c *Compiler) compileInitialRegistration(source Set, image InitialRegistrationImage, direct *Direct) MetadataDelta {
	rootType, nodes, err := c.initialRegistrationNodes(image)
	if err != nil {
		return c.initialRegistrationFailure(err.Error())
	}
	if direct != nil && !initialRegistrationDirectCoordinate(*direct, image, rootType) {
		return c.initialRegistrationFailure("direct source is outside the held registration coordinates")
	}
	if !source.Complete() {
		return MetadataDelta{Before: c.initialRegistrationFailure("incomplete registration source").Before, After: source}
	}
	after := Set{identity: c.identity, steps: source.steps}
	for _, effect := range source.effects {
		after.steps += 1 + len(effect.Constraints)
		if after.steps > MaxSteps {
			return c.initialRegistrationFailure("registration effect work limit")
		}
		path, relevant, err := initialRegistrationRootPath(effect, rootType)
		if err != nil {
			return c.initialRegistrationFailure(err.Error())
		}
		if !relevant {
			continue
		}
		exactEffect, matches, err := specializeInitialRegistrationEffect(effect, path, rootType, nodes)
		if err != nil {
			return c.initialRegistrationFailure(err.Error())
		}
		if matches {
			c.append(&after, exactEffect)
		}
		if after.limited {
			return MetadataDelta{Before: c.initialRegistrationFailure("registration effect output limit").Before, After: after}
		}
	}
	return MetadataDelta{Before: Set{identity: c.identity}, After: after}
}

func initialRegistrationDirectCoordinate(source Direct, image InitialRegistrationImage, rootType string) bool {
	if source.ObjectType == rootType && source.ObjectID == image.Root.ID {
		return true
	}
	for _, ancestor := range image.Ancestors {
		last := ancestor.Path[len(ancestor.Path)-1] // Checked by initialRegistrationNodes.
		if last.To == source.ObjectType && ancestor.Object.ObjectID == source.ObjectID {
			return true
		}
	}
	return false
}

func (c *Compiler) initialRegistrationNodes(image InitialRegistrationImage) (string, map[string]domain.MirrorObject, error) {
	root := image.New
	rootType, ok := c.facts.FGAObjectType(image.Root.Type)
	if !ok || strings.HasPrefix(image.Root.Type, "iam.") || grantcapability.IsInternalObjectType(rootType) ||
		domain.FeedSourceForType(image.Root.Type) != domain.FeedMirror ||
		image.Root.Type != root.ObjectType || image.Root.ID != root.ObjectID || !materializedToken(root.ObjectID) ||
		!materializedToken(root.ParentProjectID) || domain.ScopeProject.ValidateAgainst("project", root.ParentProjectID) != nil ||
		len(root.ParentAccountIDs) != 1 || !materializedToken(root.ParentAccountIDs[0]) ||
		domain.ScopeAccount.ValidateAgainst("account", root.ParentAccountIDs[0]) != nil ||
		!initialRegistrationLabelsValid(root) || len(image.Ancestors) > maxInitialRegistrationAncestorPaths {
		return "", nil, fmt.Errorf("invalid project-scoped registration image")
	}
	nodes := map[string]domain.MirrorObject{"": root}
	coordinates := map[domain.ResourceRef]domain.MirrorObject{image.Root: root}
	projectPath := false
	accountThroughProject := false
	for _, ancestor := range image.Ancestors {
		path, obj := ancestor.Path, ancestor.Object
		typ, known := c.facts.FGAObjectType(obj.ObjectType)
		if obj.ObjectType == "iam.cluster" && obj.ObjectID == domain.ClusterSingletonID {
			typ, known = "cluster", true
		}
		if len(path) == 0 || len(path) > hierarchy.MaxPointerHops || path[0].From != rootType ||
			!known || path[len(path)-1].To != typ || !materializedToken(obj.ObjectID) || !initialRegistrationLabelsValid(obj) ||
			!initialRegistrationAncestorScope(root, obj, typ) {
			return "", nil, fmt.Errorf("invalid registration ancestor")
		}
		for i, hop := range path {
			if hop.To == rootType || (i > 0 && path[i-1].To != hop.From) ||
				!c.plans.EffectDirectAccepts(hop.From, hop.Pointer, hop.To, "", "") {
				return "", nil, fmt.Errorf("registration ancestor path does not match the model")
			}
		}
		key := authzmodel.EffectPathKey(path)
		if _, duplicate := nodes[key]; duplicate {
			return "", nil, fmt.Errorf("duplicate registration ancestor path")
		}
		ref := domain.ResourceRef{Type: obj.ObjectType, ID: obj.ObjectID}
		if prior, seen := coordinates[ref]; seen && !reflect.DeepEqual(prior, obj) {
			return "", nil, fmt.Errorf("inconsistent registration ancestor images")
		}
		nodes[key], coordinates[ref] = obj, obj
		projectPath = projectPath || (len(path) == 1 && typ == "project")
		accountThroughProject = accountThroughProject || (len(path) == 2 && path[0].To == "project" && typ == "account")
	}
	for _, ancestor := range image.Ancestors {
		for n := 1; n < len(ancestor.Path); n++ {
			if _, ok := nodes[authzmodel.EffectPathKey(ancestor.Path[:n])]; !ok {
				return "", nil, fmt.Errorf("registration ancestor prefix omitted")
			}
		}
	}
	if !projectPath || !accountThroughProject {
		return "", nil, fmt.Errorf("canonical project and owning account path required")
	}
	return rootType, nodes, nil
}

func initialRegistrationAncestorScope(root, obj domain.MirrorObject, typ string) bool {
	switch typ {
	case "cluster":
		return obj.ObjectType == "iam.cluster" && obj.ObjectID == domain.ClusterSingletonID &&
			obj.ParentProjectID == "" && len(obj.ParentAccountIDs) == 0
	case "account":
		return obj.ObjectType == "iam.account" && obj.ObjectID == root.ParentAccountIDs[0] &&
			obj.ParentProjectID == "" && slices.Equal(obj.ParentAccountIDs, root.ParentAccountIDs)
	case "project":
		return obj.ObjectType == "iam.project" && obj.ObjectID == root.ParentProjectID &&
			obj.ParentProjectID == root.ParentProjectID && slices.Equal(obj.ParentAccountIDs, root.ParentAccountIDs)
	default:
		return obj.ParentProjectID == root.ParentProjectID && slices.Equal(obj.ParentAccountIDs, root.ParentAccountIDs)
	}
}

func initialRegistrationLabelsValid(obj domain.MirrorObject) bool {
	for _, labels := range []map[string]string{obj.Labels, obj.AccessLabels} {
		if len(labels) > grantcoverage.MaxSelectorEntries {
			return false
		}
		typed := make(domain.Labels, len(labels))
		for key, value := range labels {
			if !utf8.ValidString(value) || strings.IndexByte(value, 0) >= 0 {
				return false
			}
			typed[domain.LabelKey(key)] = domain.LabelVal(value)
		}
		if typed.Validate() != nil {
			return false
		}
	}
	return true
}

// initialRegistrationRootPath finds the single occurrence of the new object
// on each affected model derivation, including a descendant's constraint path.
func initialRegistrationRootPath(e Effect, typ string) ([]authzmodel.EffectHop, bool, error) {
	relevant := e.Type == typ
	var root []authzmodel.EffectHop
	for _, constraint := range e.Constraints {
		for i, hop := range constraint.Path {
			if hop.To != typ {
				continue
			}
			path := constraint.Path[:i+1]
			if relevant && !slices.Equal(root, path) {
				return nil, false, fmt.Errorf("registration root is ambiguous in an effect path")
			}
			root, relevant = path, true
		}
	}
	return root, relevant, nil
}

func specializeInitialRegistrationEffect(e Effect, root []authzmodel.EffectHop, typ string, nodes map[string]domain.MirrorObject) (Effect, bool, error) {
	e.Constraints = cloneConstraints(e.Constraints)
	rootConstrained := false
	for i := range e.Constraints {
		constraint := &e.Constraints[i]
		if len(constraint.Path) < len(root) || !slices.Equal(constraint.Path[:len(root)], root) {
			// A separate branch or a descendant-side condition stays symbolic.
			continue
		}
		obj, ok := nodes[authzmodel.EffectPathKey(constraint.Path[len(root):])]
		if !ok {
			return Effect{}, false, fmt.Errorf("effect requires an unwitnessed registration ancestor")
		}
		if !initialRegistrationConstraintMatches(*constraint, obj) {
			return Effect{}, false, nil
		}
		constraint.Region.Objects = grantcoverage.Objects{Kind: grantcoverage.ObjectIDs, IDs: []string{obj.ObjectID}}
		rootConstrained = rootConstrained || len(constraint.Path) == len(root)
	}
	if !rootConstrained {
		constraint := exact(typ, nodes[""].ObjectID)[0]
		constraint.Path = slices.Clone(root)
		e.Constraints = append(e.Constraints, constraint)
	}
	return e, true, nil
}

func initialRegistrationConstraintMatches(c Constraint, obj domain.MirrorObject) bool {
	if c.Within != nil && !obj.IsContainedIn(*c.Within) {
		return false
	}
	if c.Region.Objects.Kind != grantcoverage.AllObjects &&
		(c.Region.Objects.Kind != grantcoverage.ObjectIDs || !contains(c.Region.Objects.IDs, obj.ObjectID)) {
		return false
	}
	if c.Region.Creator.Kind != grantcoverage.AnyCreator &&
		(c.Region.Creator.Kind != grantcoverage.ExactCreator ||
			obj.CreatedBy != domain.FGASubjectRef(string(c.Region.Creator.Subject.Type), string(c.Region.Creator.Subject.ID))) {
		return false
	}
	if !obj.MatchesLabels(c.Region.Labels) {
		return false
	}
	// Пустая карта ограничения не задаёт защищённого селектора.
	return len(c.Region.AccessLabels) == 0 || obj.MatchesAccessLabels(c.Region.AccessLabels)
}
