// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"context"
	"go/ast"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCallerIdentityObjectLazyCOWRepeatedBorrowedSources(t *testing.T) {
	for _, initial := range []bool{false, true} {
		p := callerSoundnessProgram(t, "", `child:=Box{};parent:=child;parent=child;parent=child;sibling:=child;_=parent;_=sibling`, `&Handler{}`)
		g, refs := newCallerGraph(p), callerOwnershipSources(p)
		g.lifetimeScanning = initial
		inputs := g.sources(callerVariable(p.root, refs["parent"].expr))
		if len(inputs) != 3 {
			t.Fatal("fixture lost distinct assignment expressions")
		}
		var child map[callerObjectKey]bool
		for _, src := range inputs {
			objects, u, owned := g.callerObjectsOwned(src, map[callerObjectSourceID]bool{})
			if u || owned || len(objects) != 2 {
				t.Fatal("fixture did not publish exact child provenance")
			}
			child = objects
		}
		before := maps.Clone(child)
		writes, baseline := g.work.ObjectUnionWrites, g.work.ObjectUnionBaselineWrites
		// Отказ публикации оставляет родителю настоящее владение новой картой.
		g.objectMemoWeight = callerLifetimeStepLimit
		got, unknown, owned := g.callerObjectsOwned(refs["parent"], map[callerObjectSourceID]bool{})
		want := maps.Clone(before)
		want[callerOwnershipZero(refs["parent"])] = true
		if unknown || !owned || !maps.Equal(got, want) || !maps.Equal(child, before) {
			t.Fatal("COW lost mandatory storage or changed borrowed child")
		}
		if g.work.ObjectUnionWrites-writes != len(before) || g.work.ObjectUnionBaselineWrites-baseline != len(inputs)*len(before) {
			t.Fatal("equal borrowed children must require only one final storage clone")
		}
		delete(got, callerOwnershipZero(refs["child"]))
		if !maps.Equal(child, before) {
			t.Fatal("owned parent mutation reached child memo")
		}
		sibling, u := g.callerObjects(refs["sibling"], map[callerObjectSourceID]bool{})
		if u || !sibling[callerOwnershipZero(refs["child"])] || sibling[callerOwnershipZero(refs["parent"])] {
			t.Fatal("sibling inherited parent mutation or storage")
		}
	}
}

func TestCallerIdentityObjectLazyCOWNovelSources(t *testing.T) {
	p := callerSoundnessProgram(t, "", `child:=Box{};extra:=Box{};last:=Box{};parent:=child;parent=extra;parent=last;_=parent`, `&Handler{}`)
	g, refs := newCallerGraph(p), callerOwnershipSources(p)
	inputs := g.sources(callerVariable(p.root, refs["parent"].expr))
	want := map[callerObjectKey]bool{callerOwnershipZero(refs["parent"]): true}
	var borrowed []map[callerObjectKey]bool
	for _, src := range inputs {
		objects, u, owned := g.callerObjectsOwned(src, map[callerObjectSourceID]bool{})
		if u || owned || len(objects) != 2 {
			t.Fatal("missing published disjoint child")
		}
		borrowed = append(borrowed, objects)
		maps.Copy(want, objects)
	}
	writes := g.work.ObjectUnionWrites
	g.objectMemoWeight = callerLifetimeStepLimit
	got, u, owned := g.callerObjectsOwned(refs["parent"], map[callerObjectSourceID]bool{})
	if u || !owned || !maps.Equal(got, want) || g.work.ObjectUnionWrites-writes != 6 {
		t.Fatal("first novel child must clone two keys once, then insert four novel keys")
	}
	clear(got)
	for _, child := range borrowed {
		if len(child) != 2 {
			t.Fatal("owned parent cleared a borrowed child")
		}
	}
}

func TestCallerIdentityObjectLazyCOWBorrowedSubsetAndUnknown(t *testing.T) {
	for _, mode := range []string{"full", "initial"} {
		t.Run(mode, func(t *testing.T) {
			p := callerSoundnessProgram(t, `var shared=&Box{};func choose()*Box{if true{return shared};if false{return shared};if false{return nil};return source.Value().(*Box)}`, `parent:=choose();_=parent`, `&Handler{}`)
			g, refs := newCallerGraph(p), callerOwnershipSources(p)
			g.safeExternal = map[string]bool{"fixture/source": true}
			g.lifetimeScanning = mode == "initial"
			call := g.sources(callerVariable(p.root, refs["parent"].expr))[0]
			callExpr := call.expr.(*ast.CallExpr)
			fn := callerFunction(call.pkg, callExpr.Fun)
			// Reachability и привязки устанавливаются до прогрева конечной эпохи.
			g.bindCaller(call.pkg, callerNode{fn: call.fk.fn, lit: call.fk.lit}, callExpr, callerNode{fn: fn})
			returns := g.index.returns[callerKey(callerNode{fn: fn})][0]
			if len(returns) != 4 {
				t.Fatal("fixture lost equal, empty, or unknown return")
			}
			want := map[callerObjectKey]bool{}
			var children []callerObjectAnswer
			for i, src := range returns {
				objects, unknown, owned := g.callerObjectsOwned(src, map[callerObjectSourceID]bool{})
				if owned || unknown != (i == 3) || (i < 2 && len(objects) != 2) || (i >= 2 && len(objects) != 0) {
					t.Fatalf("return %d fixture: objects=%v unknown=%v owned=%v", i, objects, unknown, owned)
				}
				maps.Copy(want, objects)
				children = append(children, callerObjectAnswer{maps.Clone(objects), unknown})
			}
			if len(want) != 2 || !maps.Equal(children[0].objects, children[1].objects) {
				t.Fatal("fixture did not establish exact equal children and empty subsets")
			}
			memo := g.objectMemo
			if g.lifetimeScanning {
				memo = g.initialObjectMemo
			}
			for i, src := range returns {
				answer, present := memo[g.internObjectSource(src)]
				if !present || answer.unknown != children[i].unknown || !maps.Equal(answer.objects, children[i].objects) {
					t.Fatalf("return %d not published before measured union: present=%v answer=%v", i, present, answer)
				}
			}
			writes, epoch, memoEpoch, resets := g.work.ObjectUnionWrites, g.bindingEpoch, g.objectMemoEpoch, g.work.ObjectEpochResets
			g.objectMemoWeight = callerLifetimeStepLimit
			got, unknown, owned := g.callerObjectsOwned(call, map[callerObjectSourceID]bool{})
			if g.bindingEpoch != epoch || g.objectMemoEpoch != memoEpoch || g.work.ObjectEpochResets != resets || g.objectMemoWeight != callerLifetimeStepLimit {
				t.Fatalf("measured union invalidated fixture: binding=%d/%d memo=%d/%d resets=%d/%d weight=%d", g.bindingEpoch, epoch, g.objectMemoEpoch, memoEpoch, g.work.ObjectEpochResets, resets, g.objectMemoWeight)
			}
			if !unknown || owned || !maps.Equal(got, want) || g.work.ObjectUnionWrites != writes {
				t.Fatalf("stable borrowed union: objects=%v want=%v unknown=%v owned=%v writes=%d", got, want, unknown, owned, g.work.ObjectUnionWrites-writes)
			}
			for i, src := range returns {
				answer, present := memo[g.internObjectSource(src)]
				objects, u, childOwned := g.callerObjectsOwned(src, map[callerObjectSourceID]bool{})
				if !present || answer.unknown != children[i].unknown || !maps.Equal(answer.objects, children[i].objects) || u != children[i].unknown || childOwned || !maps.Equal(objects, children[i].objects) {
					t.Fatalf("union changed immutable child %d: present=%v unknown=%v owned=%v objects=%v", i, present, u, childOwned, objects)
				}
			}
		})
	}
}

func TestCallerIdentityObjectCancellationDuringCOWClone(t *testing.T) {
	p := callerSoundnessProgram(t, "", `child:=Box{};parent:=child;_=parent`, `&Handler{}`)
	g, refs := newCallerGraph(p), callerOwnershipSources(p)
	input := g.sources(callerVariable(p.root, refs["parent"].expr))[0]
	child, u := g.callerObjects(input, map[callerObjectSourceID]bool{})
	if u || len(child) != 2 {
		t.Fatal("missing borrowed base before cancellation")
	}
	before, writes, retained := maps.Clone(child), g.work.ObjectUnionWrites, g.work.ObjectRetained
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	trigger := &callerObjectCancelContext{Context: ctx, cancel: cancel, reached: func() bool { return g.work.ObjectUnionWrites > writes }}
	g.ctx = trigger
	seen := map[callerObjectSourceID]bool{}
	got, unknown, owned := g.callerObjectsOwned(refs["parent"], seen)
	if !trigger.triggered || got != nil || !unknown || owned || len(seen) != 0 || g.work.ObjectRetained != retained || !maps.Equal(child, before) {
		t.Fatal("cancelled first clone published partial state or changed its borrowed base")
	}
}

func TestCallerIdentityObjectCancellationWarmMemo(t *testing.T) {
	for _, initial := range []bool{false, true} {
		for _, expired := range []bool{false, true} {
			p := callerSoundnessProgram(t, "", `child:=Box{};_=child`, `&Handler{}`)
			g, refs := newCallerGraph(p), callerOwnershipSources(p)
			g.lifetimeScanning = initial
			warm, u := g.callerObjects(refs["child"], map[callerObjectSourceID]bool{})
			if u || len(warm) != 2 {
				t.Fatal("missing warm complete answer")
			}
			before, retained, hits := maps.Clone(warm), g.work.ObjectRetained, g.work.ObjectHits
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if expired {
				ctx, cancel = context.WithDeadline(context.Background(), time.Unix(0, 0))
				defer cancel()
			}
			g.ctx = ctx
			seen := map[callerObjectSourceID]bool{}
			got, unknown, owned := g.callerObjectsOwned(refs["child"], seen)
			if got != nil || !unknown || owned || len(seen) != 0 || g.work.ObjectRetained != retained || g.work.ObjectHits != hits || !maps.Equal(warm, before) {
				t.Fatal("cancelled warm memo supplied a completed answer or changed publications")
			}
		}
	}
}

// Контекст отменяется по наблюдаемому состоянию графа, число опросов не задано.
type callerObjectCancelContext struct {
	context.Context
	cancel    context.CancelFunc
	reached   func() bool
	triggered bool
}

func (c *callerObjectCancelContext) Err() error {
	if !c.triggered && c.reached() {
		c.triggered = true
		c.cancel()
	}
	return c.Context.Err()
}

func TestCallerIdentityObjectCancellationMidDescent(t *testing.T) {
	for _, initial := range []bool{false, true} {
		p := callerSoundnessProgram(t, "", `leaf:=Box{};middle:=leaf;root:=middle;tail:=Box{};root=tail;_=root`, `&Handler{}`)
		g, refs := newCallerGraph(p), callerOwnershipSources(p)
		g.lifetimeScanning = initial
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		seen := map[callerObjectSourceID]bool{}
		middle := g.sources(callerVariable(p.root, refs["root"].expr))[0]
		middleID := g.internObjectSource(middle)
		trigger := &callerObjectCancelContext{Context: ctx, cancel: cancel, reached: func() bool { return seen[middleID] }}
		g.ctx = trigger
		got, unknown, owned := g.callerObjectsOwned(refs["root"], seen)
		if !trigger.triggered || got != nil || !unknown || owned || len(seen) != 0 || len(g.objectMemo) != 0 || len(g.initialObjectMemo) != 0 || len(g.fieldQueries) != 0 || g.work.ObjectRetained != 0 {
			t.Fatal("cancelled descent continued, published partial provenance, or leaked traversal state")
		}
		g.closeCallerEffects()
		if !g.effectIncomplete || g.effectScanning {
			t.Fatal("cancelled effect closure reported completion or leaked scanning state")
		}
	}
}

func TestCallerIdentityCancellationJudgeInvalid(t *testing.T) {
	p := callerSoundnessProgram(t, "", `child:=Box{};_=child`, `&Handler{}`)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rootStarted, rootEnded := false, false
	report := judgeCallerIdentityObserved(ctx, p, nil, map[string]bool{"fixture/source": true}, func(phase string, _ CallerIdentityWork) {
		if strings.HasPrefix(phase, "rpc-solve:root:start ") {
			rootStarted = true
			cancel()
		}
		rootEnded = rootEnded || strings.HasPrefix(phase, "rpc-solve:root:end ")
	})
	if !rootStarted || rootEnded || report.Invalid != context.Canceled.Error() {
		t.Fatal("cancelled root was accepted as completed coverage")
	}
	// Подставляется только валидный типизированный вход загрузчика; публичный
	// вызов сам проходит program, judge и преобразование Invalid в ошибку.
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "cmd", "kaname"), 0755); err != nil {
		t.Fatal(err)
	}
	listing := &surfaceListing{moduleRoot: root, rootPkg: p.root.path, modulePath: p.root.path, ownerPrefix: ownerPrefixOf(p.root.path), fset: p.fset, base: p, byPath: map[string]*surfaceListed{}}
	for _, pkg := range p.pkgs {
		listed := &surfaceListed{ImportPath: pkg.path, Name: pkg.types.Name()}
		for _, imported := range pkg.types.Imports() {
			listed.Imports = append(listed.Imports, imported.Path())
		}
		listing.byPath[pkg.path] = listed
		listing.order = append(listing.order, listed)
	}
	key := root + "\x00./cmd/kaname/..."
	bindingPairListingsMu.Lock()
	_, exists := bindingPairListings[key]
	if !exists {
		bindingPairListings[key] = listing
	}
	bindingPairListingsMu.Unlock()
	if exists {
		t.Fatal("unique fixture loader key was already occupied")
	}
	t.Cleanup(func() {
		bindingPairListingsMu.Lock()
		defer bindingPairListingsMu.Unlock()
		if bindingPairListings[key] == listing {
			delete(bindingPairListings, key)
		}
	})
	publicCtx, cancelPublic := context.WithCancel(context.Background())
	defer cancelPublic()
	loaded, publicRootStarted, publicRootEnded := false, false, false
	publicReport, err := CallerIdentityFindings(publicCtx, root, nil, nil, func(phase string, _ CallerIdentityWork) {
		loaded = loaded || phase == "load:end"
		if strings.HasPrefix(phase, "rpc-solve:root:start ") {
			publicRootStarted = true
			cancelPublic()
		}
		publicRootEnded = publicRootEnded || strings.HasPrefix(phase, "rpc-solve:root:end ")
	})
	if !loaded || !publicRootStarted || publicRootEnded || publicReport.Invalid != context.Canceled.Error() {
		t.Fatal("public caller gate did not reach and invalidate the cancelled root")
	}
	if err == nil || !strings.Contains(err.Error(), publicReport.Invalid) {
		t.Fatal("public caller gate did not map cancellation Invalid to its error")
	}
}

func TestCallerIdentityObjectLazyCOWLargerOwnedChild(t *testing.T) {
	for _, initial := range []bool{false, true} {
		p := callerSoundnessProgram(t, "", `small:=Box{};middle:=small;large:=middle;parent:=small;parent=large;_=parent`, `&Handler{}`)
		g, refs := newCallerGraph(p), callerOwnershipSources(p)
		g.lifetimeScanning = initial
		input := g.sources(callerVariable(p.root, refs["parent"].expr))[0]
		base, u := g.callerObjects(input, map[callerObjectSourceID]bool{})
		if u || len(base) != 2 {
			t.Fatal("missing borrowed small accumulator")
		}
		before := maps.Clone(base)
		want := maps.Clone(base)
		for _, src := range g.sources(callerVariable(p.root, refs["middle"].expr)) {
			objects, unknown, owned := g.callerObjectsOwned(src, map[callerObjectSourceID]bool{})
			if unknown || owned || !maps.Equal(objects, base) {
				t.Fatal("nested small source was not independently prewarmed")
			}
		}
		for _, name := range []string{"middle", "large", "parent"} {
			want[callerOwnershipZero(refs[name])] = true
		}
		writes, transfers := g.work.ObjectUnionWrites, g.work.ObjectUnionTransfers
		g.objectMemoWeight = callerLifetimeStepLimit
		got, unknown, owned := g.callerObjectsOwned(refs["parent"], map[callerObjectSourceID]bool{})
		if unknown || !owned || !maps.Equal(got, want) || g.work.ObjectUnionTransfers <= transfers || g.work.ObjectUnionWrites-writes != len(base) {
			t.Fatal("larger owned child was not transferred without rewriting the borrowed subset")
		}
		clear(got)
		if !maps.Equal(base, before) {
			t.Fatal("owned transfer made the old borrowed accumulator writable")
		}
	}
}

func TestCallerIdentityObjectCancellationFieldAndLifetimeCleanup(t *testing.T) {
	g, field := callerInitialObjectFixture(t)
	selector := field.expr.(*ast.SelectorExpr)
	base := field
	base.expr = selector.X
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	trigger := &callerObjectCancelContext{Context: ctx, cancel: cancel, reached: func() bool { return len(g.fieldQueries) > 0 }}
	g.ctx = trigger
	seen := map[callerFieldKey]bool{}
	got, unknown := g.embeddedCallerSources(base, fieldPath(field.pkg.info.Selections[selector]), seen)
	if !trigger.triggered || got != nil || !unknown || len(seen) != 0 || len(g.fieldQueries) != 0 || g.lifetimeScanning || g.effectScanning {
		t.Fatal("cancelled field query leaked partial snapshot or traversal state")
	}
	g, field = callerInitialObjectFixture(t)
	ctx, cancelLifetime := context.WithCancel(context.Background())
	defer cancelLifetime()
	trigger = &callerObjectCancelContext{Context: ctx, cancel: cancelLifetime, reached: func() bool { return g.lifetimeScanning }}
	g.ctx = trigger
	unknown = g.callerLifetimeUnknown(field)
	if !trigger.triggered || !unknown || g.lifetimeScanning || g.effectScanning || !g.effectIncomplete {
		t.Fatal("cancelled lifetime proof leaked scanning state or completed effects")
	}
}

func TestCallerIdentityObjectLazyCOWMandatoryStorage(t *testing.T) {
	for _, initial := range []bool{false, true} {
		p := callerSoundnessProgram(t, "", `var zero *Box;opaque:=source.Value();parent:=Box{};alias:=parent;parent=alias;_=zero;_=opaque;_=parent`, `&Handler{}`)
		g, refs := newCallerGraph(p), callerOwnershipSources(p)
		g.safeExternal = map[string]bool{"fixture/source": true}
		g.lifetimeScanning = initial
		zero, u := g.callerObjects(refs["zero"], map[callerObjectSourceID]bool{})
		if u || len(zero) != 1 || !zero[callerOwnershipZero(refs["zero"])] {
			t.Fatal("no-ref zero variable lost its mandatory storage key")
		}
		opaque, u := g.callerObjects(refs["opaque"], map[callerObjectSourceID]bool{})
		if !u || len(opaque) != 1 || !opaque[callerOwnershipZero(refs["opaque"])] {
			t.Fatal("unknown empty child lost UNKNOWN or mandatory storage")
		}
		parent, u := g.callerObjects(refs["parent"], map[callerObjectSourceID]bool{})
		if u || len(parent) != 3 || !parent[callerOwnershipZero(refs["parent"])] || !parent[callerOwnershipZero(refs["alias"])] {
			t.Fatal("anchored alias cycle lost an already represented storage key")
		}
	}
}
