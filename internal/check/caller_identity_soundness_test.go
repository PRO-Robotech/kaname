// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"strings"
	"testing"
)

type callerFixtureImporter map[string]*types.Package

func (i callerFixtureImporter) Import(path string) (*types.Package, error) {
	p := i[path]
	if p == nil {
		return nil, fmt.Errorf("fixture import missing: %s", path)
	}
	return p, nil
}

// Малый типизированный радиус проходит тот же registration/receiver/field
// resolver. Никакой lawful production baseline не нужен для soundness-проб.
func callerSoundnessProgram(t *testing.T, setup, body, registration string, startup ...string) *surfaceProgram {
	t.Helper()
	startupCode, registrar := strings.Join(startup, "\n"), "nil"
	if len(startup) > 1 {
		startupCode = startup[0]
		if startup[1] != "" {
			registrar = startup[1]
		}
	}
	fset := token.NewFileSet()
	p := &surfaceProgram{fset: fset, byPath: map[string]*surfaceSrcPkg{}}
	imports := callerFixtureImporter{}
	add := func(path, source string) {
		f, err := parser.ParseFile(fset, path+"/fixture.go", source, 0)
		if err != nil {
			t.Fatal(err)
		}
		info := &types.Info{Types: map[ast.Expr]types.TypeAndValue{}, Defs: map[*ast.Ident]types.Object{}, Uses: map[*ast.Ident]types.Object{}, Selections: map[*ast.SelectorExpr]*types.Selection{}, Implicits: map[ast.Node]types.Object{}, Instances: map[*ast.Ident]types.Instance{}}
		pkg, err := (&types.Config{Importer: imports}).Check(path, fset, []*ast.File{f}, info)
		if err != nil {
			t.Fatal(err)
		}
		sp := &surfaceSrcPkg{path: path, types: pkg, files: []*ast.File{f}, info: info, own: true}
		imports[path] = pkg
		p.pkgs = append(p.pkgs, sp)
		p.byPath[path] = sp
	}
	add("google.golang.org/grpc", `package grpc; type ServiceRegistrar interface{RegisterService(any,any)}`)
	add("fixture/service", `package service; import "google.golang.org/grpc"; type FixtureServiceServer interface{RPC()};func RegisterFixtureServiceServer(s grpc.ServiceRegistrar,h FixtureServiceServer){s.RegisterService(nil,h)}`)
	add("github.com/PRO-Robotech/corelib/operations", `package operations;func PrincipalFromContext(){}`)
	add("fixture/source", `package source;var Shared,Other any;var SharedFn,OtherFn func();func Value()any{return nil};func Callback(fn func(any)){fn(Value())};func Mutate(value any){}
func Assign[T any](dst *T,value T){*dst=value};func AssignFirst[T any](dst []*T,value T){*dst[0]=value}
func Invoke(value any){value.(func())()}
type Cell[T any] struct{Dest *T}
func(cell Cell[T])Set(value T){*cell.Dest=value}
type Pending[T any] struct{Dest *T;Value T}
func(cell Pending[T])Set(){*cell.Dest=cell.Value}
type Slot[T any] struct{Value T}
func(slot *Slot[T])Set(value T){slot.Value=value}`)
	add("github.com/PRO-Robotech/kaname/internal/authzguard", `package authzguard;var callerNarrowedArguments=map[string][]string{}`)
	add("fixture/app", `package main
 import("fixture/service";"fixture/source";"github.com/PRO-Robotech/corelib/operations")
 type Reader interface{read()}
 type Concrete struct{}
 func(Concrete)read(){operations.PrincipalFromContext()}
 type Benign struct{}
 func(Benign)read(){}
 type Box struct{reader Reader}
 type Handler struct{reader Reader}
 type Outer struct{*Handler}
 func anchor(){operations.PrincipalFromContext()}
 func(h *Handler)RPC(){anchor();`+body+`}
 func unused(reader Reader)*Box{return &Box{reader:reader}}
 var _=source.Value
 `+setup+`
 func main(){`+startupCode+`;service.RegisterFixtureServiceServer(`+registrar+`,`+registration+`)}
 `)
	p.root = p.byPath["fixture/app"]
	p.root.root = true
	return p
}

func TestCallerIdentitySoundnessReviewRoots(t *testing.T) {
	const capturedReadField = "type Holder struct{F func()}"
	const rpc = "fixture/service/FixtureService/RPC"
	const producer = "github.com/PRO-Robotech/corelib/operations.PrincipalFromContext"
	base := []CallerReadDeclaration{{RPC: rpc, Producer: producer, Site: "fixture/app.anchor", Kind: CallerObservation, Reason: "Fixture nonempty population."}}
	for _, tc := range []struct{ name, setup, body, registration, mode, startup, registrar string }{
		{name: "post_write", body: `box:=&Box{};box.reader=Concrete{};box.reader.read()`, registration: `&Handler{}`, mode: "reader"},
		{name: "post_write_over_benign", body: `box:=&Box{reader:Benign{}};box.reader=Concrete{};box.reader.read()`, registration: `&Handler{}`, mode: "reader"},
		{name: "post_write_alias", body: `box:=&Box{};alias:=box;alias.reader=Concrete{};box.reader.read()`, registration: `&Handler{}`, mode: "reader"},
		{name: "post_write_unrelated", body: `other:=&Box{};other.reader=Concrete{};box:=&Box{reader:Benign{}};box.reader.read()`, registration: `&Handler{}`, mode: "benign"},
		{name: "post_write_helper", setup: `func put(box *Box,reader Reader){box.reader=reader}`, body: `box:=&Box{};put(box,Concrete{});box.reader.read()`, registration: `&Handler{}`, mode: "reader"},
		{name: "returned_alias", setup: `func identity(box *Box)*Box{return box}`, body: `box:=&Box{};alias:=identity(box);alias.reader=Concrete{};box.reader.read()`, registration: `&Handler{}`, mode: "reader"},
		{name: "returned_alias_uncovered", setup: `func identity(box *Box)*Box{return box}`, body: `box:=&Box{};alias:=identity(box);alias.reader=source.Value().(Reader);box.reader.read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "returned_alias_tuple", setup: `func identity(box *Box)(int,*Box){return 0,box}`, body: `box:=&Box{};_,alias:=identity(box);alias.reader=Concrete{};box.reader.read()`, registration: `&Handler{}`, mode: "reader"},
		{name: "returned_alias_branch", setup: `func identity(box,other *Box,choose bool)*Box{if choose{return box};return other}`, body: `box:=&Box{};other:=&Box{};alias:=identity(box,other,true);alias.reader=Concrete{};box.reader.read()`, registration: `&Handler{}`, mode: "reader"},
		{name: "returned_alias_named", setup: `func identity(box *Box)(out *Box){out=box;return}`, body: `box:=&Box{};alias:=identity(box);alias.reader=Concrete{};box.reader.read()`, registration: `&Handler{}`, mode: "reader"},
		{name: "post_write_benign", body: `box:=&Box{};box.reader=Benign{};box.reader.read()`, registration: `&Handler{}`, mode: "benign"},
		{name: "post_write_uncovered", body: `box:=&Box{};box.reader=source.Value().(Reader);box.reader.read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "post_write_opaque_alias", body: `box:=&Box{};alias:=source.Value().(*Box);alias.reader=Concrete{};box.reader.read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "registered_promoted", body: `h.reader.read()`, registration: `&Outer{Handler:&Handler{reader:Concrete{}}}`, mode: "reader"},
		{name: "registered_direct", body: `h.reader.read()`, registration: `&Handler{reader:Concrete{}}`, mode: "reader"},
		{name: "registered_promoted_uncovered", body: `h.reader.read()`, registration: `&Outer{Handler:&Handler{reader:source.Value().(Reader)}}`, mode: "unknown"},
		{name: "shadowed_nil", setup: `type Embedded struct{Concrete};func factory()*Embedded{nil:=&Embedded{Concrete:Concrete{}};return nil}`, body: `factory().read()`, registration: `&Handler{}`, mode: "reader"},
		{name: "builtin_nil", setup: `type Embedded struct{Concrete};func factory()*Embedded{return nil}`, body: `factory().read()`, registration: `&Handler{}`, mode: "benign"},
		{name: "shadowed_nil_uncovered", setup: `type Embedded struct{Concrete};func factory(nil *Embedded)*Embedded{return nil}`, body: `factory(source.Value().(*Embedded)).read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "queue_reader", setup: callerQueueFixture, body: `w:=&Worker{};w.put(Concrete{});w.launch()`, registration: `&Handler{}`, mode: "reader"},
		{name: "queue_benign", setup: callerQueueFixture, body: `w:=&Worker{};w.put(Benign{});w.launch()`, registration: `&Handler{}`, mode: "benign"},
		{name: "queue_opaque", setup: callerQueueFixture, body: `w:=&Worker{};w.put(source.Value().(Reader));w.launch()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "queue_mutation", setup: callerQueueFixture, body: `w:=&Worker{};w.put(Benign{});alias:=w;alias.backlog[0]=Job{reader:Concrete{}};w.launch()`, registration: `&Handler{}`, mode: "reader"},
		{name: "fluent_reader", setup: callerFluentFixture, body: `box:=newBox().withReader(Concrete{}).again();box.reader.read()`, registration: `&Handler{}`, mode: "reader"},
		{name: "fluent_benign", setup: callerFluentFixture, body: `box:=newBox().withReader(Benign{}).again();box.reader.read()`, registration: `&Handler{}`, mode: "benign"},
		{name: "fluent_opaque", setup: callerFluentFixture, body: `box:=newBox().withReader(source.Value().(Reader)).again();box.reader.read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "fluent_escape", setup: callerFluentFixture, body: `box:=newBox().withReader(Benign{});alias:=box.again();alias.reader=source.Value().(Reader);box.reader.read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "option_reader", setup: callerOptionFixture, body: `box:=options(withReader(Concrete{}));box.reader.read()`, registration: `&Handler{}`, mode: "reader"},
		{name: "option_benign", setup: callerOptionFixture, body: `box:=options(withReader(Benign{}));box.reader.read()`, registration: `&Handler{}`, mode: "benign"},
		{name: "option_absent", setup: callerOptionFixture, body: `box:=options();if box.reader!=nil{box.reader.read()}`, registration: `&Handler{}`, mode: "benign"},
		{name: "option_opaque", setup: callerOptionFixture, body: `box:=options(withReader(source.Value().(Reader)));box.reader.read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "option_mutation_escape", setup: callerOptionFixture, body: `box:=options(func(out *Box){alias:=out;alias.reader=source.Value().(Reader)});box.reader.read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "callback_parameter_reader", setup: `func transaction(reader Reader,fn func(Reader)){fn(reader)}`, body: `transaction(Concrete{},func(tx Reader){box:=Box{reader:tx};box.reader.read()})`, registration: `&Handler{}`, mode: "reader"},
		{name: "callback_parameter_benign", setup: `func transaction(reader Reader,fn func(Reader)){fn(reader)}`, body: `transaction(Benign{},func(tx Reader){box:=Box{reader:tx};box.reader.read()})`, registration: `&Handler{}`, mode: "benign"},
		{name: "callback_parameter_opaque", setup: `func transaction(reader Reader,fn func(Reader)){fn(reader)}`, body: `transaction(source.Value().(Reader),func(tx Reader){box:=Box{reader:tx};box.reader.read()})`, registration: `&Handler{}`, mode: "unknown"},
		{name: "external_callback_parameter_untraced", body: `source.Callback(func(tx any){box:=Box{reader:tx.(Reader)};box.reader.read()})`, registration: `&Handler{}`, mode: "unknown"},
		{name: "zero_object_external_escape", body: `var box Box;source.Mutate(&box);box.reader.read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "zero_object_external_alias_escape", body: `var box Box;alias:=&box;source.Mutate(alias);box.reader.read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "zero_object_unrelated_escape", body: `var box Box;other:=&Box{};source.Mutate(other);box.reader.read()`, registration: `&Handler{}`, mode: "benign"},
		{name: "unanchored_mutation_owner", body: `var alias *Box;alias=alias;alias.reader=Concrete{};box:=&Box{};box.reader.read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "queue_callback_reader", setup: callerCallbackQueueFixture, body: `w:=&Worker{};w.put(func(){Concrete{}.read()});w.launch()`, registration: `&Handler{}`, mode: "reader"},
		{name: "queue_callback_benign", setup: callerCallbackQueueFixture, body: `w:=&Worker{};w.put(func(){Benign{}.read()});w.launch()`, registration: `&Handler{}`, mode: "benign"},
		{name: "queue_callback_opaque", setup: callerCallbackQueueFixture, body: `w:=&Worker{};w.put(source.Value().(func()));w.launch()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "zero_pointer_external_assign", body: `var box *Box;source.Assign(&box,&Box{reader:Concrete{}});box.reader.read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "zero_pointer_external_opaque", body: `var box *Box;source.Assign(&box,source.Value().(*Box));box.reader.read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "zero_pointer_external_alias", body: `var box *Box;alias:=&box;source.Assign(alias,&Box{reader:Concrete{}});box.reader.read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "zero_pointer_unrelated_assign", body: `var box *Box;var other *Box;source.Assign(&other,&Box{reader:Concrete{}});if box!=nil{box.reader.read()}`, registration: `&Handler{}`, mode: "benign"},
		{name: "zero_pointer_local_reader", body: `var box *Box;box=&Box{reader:Concrete{}};box.reader.read()`, registration: `&Handler{}`, mode: "reader"},
		{name: "zero_pointer_local_indirect", setup: `func assign(dst **Box,value *Box){*dst=value}`, body: `var box *Box;assign(&box,&Box{reader:Concrete{}});box.reader.read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "zero_container_external_assign", body: `var box Box;source.AssignFirst([]*Box{&box},Box{reader:Concrete{}});box.reader.read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "zero_container_external_opaque", body: `var box Box;source.AssignFirst(source.Value().([]*Box),Box{reader:Concrete{}});box.reader.read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "zero_container_unrelated_assign", body: `var box Box;var other Box;source.AssignFirst([]*Box{&other},Box{reader:Concrete{}});if box.reader!=nil{box.reader.read()}`, registration: `&Handler{}`, mode: "benign"},
		{name: "zero_struct_local_reader", body: `var box Box;box.reader=Concrete{};box.reader.read()`, registration: `&Handler{}`, mode: "reader"},
		{name: "zero_slice_external_assign", body: `var boxes []Box;source.Assign(&boxes,[]Box{{reader:Concrete{}}});boxes[0].reader.read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "zero_slice_unrelated_assign", body: `var boxes []Box;var other []Box;source.Assign(&other,[]Box{{reader:Concrete{}}});if len(boxes)>0{boxes[0].reader.read()}`, registration: `&Handler{}`, mode: "benign"},
		{name: "zero_slice_local_reader", body: `var boxes []Box;boxes=[]Box{{reader:Concrete{}}};boxes[0].reader.read()`, registration: `&Handler{}`, mode: "reader"},
		{name: "zero_boxed_callback_capture", body: `var box Box;callback:=func(){box.reader=Concrete{}};source.Invoke(any(callback));box.reader.read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "zero_boxed_callback_alias_capture", body: `var box Box;alias:=&box;callback:=func(){alias.reader=Concrete{}};boxed:=any(callback);source.Invoke(boxed);box.reader.read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "zero_boxed_callback_benign_capture", body: `var box Box;callback:=func(){box.reader=Benign{}};source.Invoke(any(callback));box.reader.read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "zero_boxed_callback_opaque_capture", body: `var box Box;callback:=func(){box.reader=source.Value().(Reader)};source.Invoke(any(callback));box.reader.read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "zero_boxed_callback_unrelated_capture", body: `var box Box;var other Box;callback:=func(){other.reader=Concrete{}};source.Invoke(any(callback));if box.reader!=nil{box.reader.read()}`, registration: `&Handler{}`, mode: "benign"},
		{name: "zero_boxed_callback_local_reader", setup: `func invoke(value any){value.(func())()}`, body: `var box Box;callback:=func(){box.reader=Concrete{}};invoke(any(callback));box.reader.read()`, registration: `&Handler{}`, mode: "reader"},
		{name: "zero_direct_callback_local_reader", setup: `func invoke(fn func()){fn()}`, body: `var box Box;invoke(func(){box.reader=Concrete{}});box.reader.read()`, registration: `&Handler{}`, mode: "reader"},
		// Без полного доказательства zero внешние получатели и контейнеры
		// остаются UNKNOWN; исходный литерал контейнера не доказывает alias.
		{name: "literal_receiver_external_assign", body: `box:=&Box{};cell:=source.Cell[Box]{Dest:box};cell.Set(Box{reader:Concrete{}});box.reader.read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "literal_receiver_external_noargs", body: `box:=&Box{};cell:=source.Pending[Box]{Dest:box,Value:Box{reader:Concrete{}}};cell.Set();box.reader.read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "literal_container_external_assign", body: `box:=&Box{};source.AssignFirst([]*Box{box},Box{reader:Concrete{}});box.reader.read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "zero_receiver_external_assign", body: `var box Box;cell:=source.Cell[Box]{Dest:&box};cell.Set(Box{reader:Concrete{}});box.reader.read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "zero_receiver_external_noargs", body: `var box Box;cell:=source.Pending[Box]{Dest:&box,Value:Box{reader:Concrete{}}};cell.Set();box.reader.read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "zero_receiver_unrelated_assign", body: `var box Box;var other Box;cell:=source.Cell[Box]{Dest:&other};cell.Set(Box{reader:Concrete{}});box.reader.read()`, registration: `&Handler{}`, mode: "benign"},
		{name: "zero_container_alias_write", body: `var box Box;destinations:=[]*Box{nil};alias:=destinations;alias[0]=&box;source.AssignFirst(destinations,Box{reader:Concrete{}});box.reader.read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "zero_container_alias_opaque_write", body: `var box Box;destinations:=[]*Box{nil};alias:=destinations;alias[0]=source.Value().(*Box);source.AssignFirst(destinations,Box{reader:Concrete{}});box.reader.read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "zero_container_alias_unrelated_write", body: `var box Box;var other Box;destinations:=[]*Box{nil};alias:=destinations;alias[0]=&other;source.AssignFirst(destinations,Box{reader:Concrete{}});box.reader.read()`, registration: `&Handler{}`, mode: "benign"},
		// Возможная запись boxed callback учитывается и при явном основании
		// &Box{}: неизвестный вызов не становится доказательством nil.
		{name: "literal_boxed_callback_capture", body: `box:=&Box{};callback:=func(){box.reader=Concrete{}};source.Invoke(any(callback));box.reader.read()`, registration: `&Handler{}`, mode: "unknown_reader"},
		{name: "literal_boxed_callback_alias_capture", body: `box:=&Box{};alias:=box;callback:=func(){alias.reader=Concrete{}};boxed:=any(callback);source.Invoke(boxed);box.reader.read()`, registration: `&Handler{}`, mode: "unknown_reader"},
		{name: "literal_boxed_callback_benign_capture", body: `box:=&Box{};callback:=func(){box.reader=Benign{}};source.Invoke(any(callback));box.reader.read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "literal_boxed_callback_opaque_capture", body: `box:=&Box{};callback:=func(){box.reader=source.Value().(Reader)};source.Invoke(any(callback));box.reader.read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "literal_boxed_callback_unrelated_capture", body: `box:=&Box{reader:Benign{}};other:=&Box{};callback:=func(){other.reader=Concrete{}};source.Invoke(any(callback));box.reader.read()`, registration: `&Handler{}`, mode: "benign"},
		{name: "literal_unused_callback_capture", body: `box:=&Box{};callback:=func(){box.reader=Concrete{}};_=callback;box.reader.read()`, registration: `&Handler{}`, mode: "unknown_reader"},
		{name: "literal_direct_callback_local_reader", setup: `func invoke(fn func()){fn()}`, body: `box:=&Box{};invoke(func(){box.reader=Concrete{}});box.reader.read()`, registration: `&Handler{}`, mode: "reader"},
		{name: "literal_boxed_callback_local_reader", setup: `func invoke(value any){value.(func())()}`, body: `box:=&Box{};callback:=func(){box.reader=Concrete{}};invoke(any(callback));box.reader.read()`, registration: `&Handler{}`, mode: "reader"},
		{name: "literal_receiver_unrelated_assign", body: `box:=&Box{reader:Benign{}};var other Box;cell:=source.Cell[Box]{Dest:&other};cell.Set(Box{reader:Concrete{}});box.reader.read()`, registration: `&Handler{}`, mode: "benign"},
		{name: "literal_container_unrelated_assign", body: `box:=&Box{reader:Benign{}};var other Box;destinations:=[]*Box{nil};alias:=destinations;alias[0]=&other;source.AssignFirst(destinations,Box{reader:Concrete{}});box.reader.read()`, registration: `&Handler{}`, mode: "benign"},
		{name: "lifetime_nil_receiver", body: `box:=&Box{reader:nil};cell:=source.Cell[Box]{Dest:box};cell.Set(Box{reader:Concrete{}});box.reader.read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "lifetime_nil_receiver_noargs", body: `box:=&Box{reader:nil};cell:=source.Pending[Box]{Dest:box,Value:Box{reader:Concrete{}}};cell.Set();box.reader.read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "lifetime_nil_bound_receiver", body: `box:=&Box{reader:nil};cell:=source.Cell[Box]{Dest:box};set:=cell.Set;set(Box{reader:Concrete{}});box.reader.read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "lifetime_nil_container_alias", body: `box:=&Box{reader:nil};destinations:=[]*Box{nil};alias:=destinations;alias[0]=box;source.AssignFirst(destinations,Box{reader:Concrete{}});box.reader.read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "lifetime_nil_container_slice_alias", body: `box:=&Box{reader:nil};destinations:=[]*Box{nil};alias:=destinations[:];alias[0]=box;source.AssignFirst(destinations,Box{reader:Concrete{}});box.reader.read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "lifetime_nil_container_append_alias", body: `box:=&Box{reader:nil};destinations:=[]*Box{nil};alias:=append(destinations[:0],box);_=alias;source.AssignFirst(destinations,Box{reader:Concrete{}});box.reader.read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "lifetime_nil_local_indirect", setup: `func assign(dst *Box,value Box){*dst=value}`, body: `box:=&Box{reader:nil};assign(box,Box{reader:Concrete{}});box.reader.read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "lifetime_nil_receiver_unrelated", body: `box:=&Box{reader:nil};other:=&Box{};cell:=source.Cell[Box]{Dest:other};cell.Set(Box{reader:Concrete{}});box.reader.read()`, registration: `&Handler{}`, mode: "benign"},
		{name: "lifetime_nil_container_alias_unrelated", body: `box:=&Box{reader:nil};other:=&Box{};destinations:=[]*Box{nil};alias:=destinations;alias[0]=other;source.AssignFirst(destinations,Box{reader:Concrete{}});box.reader.read()`, registration: `&Handler{}`, mode: "benign"},
		{name: "lifetime_nil_local_indirect_unrelated", setup: `func assign(dst *Box,value Box){*dst=value}`, body: `box:=&Box{reader:nil};other:=&Box{};assign(other,Box{reader:Concrete{}});box.reader.read()`, registration: `&Handler{}`, mode: "benign"},
		{name: "lifetime_benign_receiver", body: `box:=&Box{reader:Benign{}};cell:=source.Cell[Box]{Dest:box};cell.Set(Box{reader:Concrete{}});box.reader.read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "lifetime_benign_receiver_noargs", body: `box:=&Box{reader:Benign{}};cell:=source.Pending[Box]{Dest:box,Value:Box{reader:Concrete{}}};cell.Set();box.reader.read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "lifetime_benign_bound_receiver", body: `box:=&Box{reader:Benign{}};cell:=source.Cell[Box]{Dest:box};set:=cell.Set;set(Box{reader:Concrete{}});box.reader.read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "lifetime_benign_container_alias", body: `box:=&Box{reader:Benign{}};destinations:=[]*Box{nil};alias:=destinations;alias[0]=box;source.AssignFirst(destinations,Box{reader:Concrete{}});box.reader.read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "lifetime_benign_container_slice_alias", body: `box:=&Box{reader:Benign{}};destinations:=[]*Box{nil};alias:=destinations[:];alias[0]=box;source.AssignFirst(destinations,Box{reader:Concrete{}});box.reader.read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "lifetime_benign_container_append_alias", body: `box:=&Box{reader:Benign{}};destinations:=[]*Box{nil};alias:=append(destinations[:0],box);_=alias;source.AssignFirst(destinations,Box{reader:Concrete{}});box.reader.read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "lifetime_benign_local_indirect", setup: `func assign(dst *Box,value Box){*dst=value}`, body: `box:=&Box{reader:Benign{}};assign(box,Box{reader:Concrete{}});box.reader.read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "lifetime_benign_receiver_unrelated", body: `box:=&Box{reader:Benign{}};other:=&Box{};cell:=source.Cell[Box]{Dest:other};cell.Set(Box{reader:Concrete{}});box.reader.read()`, registration: `&Handler{}`, mode: "benign"},
		{name: "lifetime_benign_container_alias_unrelated", body: `box:=&Box{reader:Benign{}};other:=&Box{};destinations:=[]*Box{nil};alias:=destinations;alias[0]=other;source.AssignFirst(destinations,Box{reader:Concrete{}});box.reader.read()`, registration: `&Handler{}`, mode: "benign"},
		{name: "lifetime_benign_local_indirect_unrelated", setup: `func assign(dst *Box,value Box){*dst=value}`, body: `box:=&Box{reader:Benign{}};other:=&Box{};assign(other,Box{reader:Concrete{}});box.reader.read()`, registration: `&Handler{}`, mode: "benign"},

		{name: "lifetime_explicit_nil_pointer", body: `var box *Box=nil;source.Assign(&box,&Box{reader:Concrete{}});box.reader.read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "lifetime_explicit_nil_pointer_unrelated", body: `var box *Box=nil;var other *Box;source.Assign(&other,&Box{reader:Concrete{}});box.reader.read()`, registration: `&Handler{}`, mode: "benign"},
		{name: "lifetime_named_callback_indirect", setup: `var shared=&Box{reader:Benign{}};func mutateShared(){*shared=Box{reader:Concrete{}}}`, body: `source.Invoke(any(mutateShared));shared.reader.read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "lifetime_named_callback_unrelated", setup: `var other=&Box{};func mutateOther(){*other=Box{reader:Concrete{}}}`, body: `box:=&Box{reader:Benign{}};source.Invoke(any(mutateOther));box.reader.read()`, registration: `&Handler{}`, mode: "benign"},
		{name: "lifetime_constructor_receiver", setup: `func newBox()*Box{box:=&Box{reader:nil};cell:=source.Cell[Box]{Dest:box};cell.Set(Box{reader:Concrete{}});return box}`, body: `box:=newBox();box.reader.read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "lifetime_constructor_unrelated", setup: `func newBox()*Box{box:=&Box{reader:Benign{}};other:=&Box{};cell:=source.Cell[Box]{Dest:other};cell.Set(Box{reader:Concrete{}});return box}`, body: `box:=newBox();box.reader.read()`, registration: `&Handler{}`, mode: "benign"},

		{name: "field_address_foreign", body: `box:=&Box{reader:Benign{}};source.Assign[Reader](&box.reader,Concrete{});box.reader.read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "field_address_foreign_unrelated", body: `box:=&Box{reader:Benign{}};other:=&Box{};source.Assign[Reader](&other.reader,Concrete{});box.reader.read()`, registration: `&Handler{}`, mode: "benign"},
		{name: "field_address_local", setup: `func put(dst *Reader,value Reader){*dst=value}`, body: `box:=&Box{reader:Benign{}};put(&box.reader,Concrete{});box.reader.read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "field_address_local_unrelated", setup: `func put(dst *Reader,value Reader){*dst=value}`, body: `box:=&Box{reader:Benign{}};other:=&Box{};put(&other.reader,Concrete{});box.reader.read()`, registration: `&Handler{}`, mode: "benign"},
		{name: "field_address_same_owner_other_field", setup: `type PairBox struct{reader,other Reader}`, body: `box:=&PairBox{reader:Benign{},other:Benign{}};source.Assign[Reader](&box.other,Concrete{});box.reader.read()`, registration: `&Handler{}`, mode: "benign"},
		{name: "field_address_same_owner_other_field_local", setup: `type PairBox struct{reader,other Reader};func put(dst *Reader,value Reader){*dst=value}`, body: `box:=&PairBox{reader:Benign{},other:Benign{}};put(&box.other,Concrete{});box.reader.read()`, registration: `&Handler{}`, mode: "benign"},
		{name: "direct_container_alias_reader", body: `boxes:=[]*Box{{reader:Benign{}}};alias:=boxes;alias[0]=&Box{reader:Concrete{}};boxes[0].reader.read()`, registration: `&Handler{}`, mode: "reader"},
		{name: "direct_container_append_reader", body: `boxes:=[]*Box{{reader:Benign{}}};alias:=append(boxes[:0],&Box{reader:Concrete{}});_=alias;boxes[0].reader.read()`, registration: `&Handler{}`, mode: "reader"},
		{name: "direct_container_alias_unrelated", body: `boxes:=[]*Box{{reader:Benign{}}};other:=[]*Box{{}};alias:=other;alias[0]=&Box{reader:Concrete{}};boxes[0].reader.read()`, registration: `&Handler{}`, mode: "benign"},
		{name: "direct_container_append_unrelated", body: `boxes:=[]*Box{{reader:Benign{}}};other:=[]*Box{{}};alias:=append(other[:0],&Box{reader:Concrete{}});_=alias;boxes[0].reader.read()`, registration: `&Handler{}`, mode: "benign"},
		{name: "startup_scalar_out_disjoint", setup: `type Name string;type Decision struct{name Name};type Recorder struct{};func(Recorder)save(p *Name){*p=source.Value().(*Decision).name}`, startup: `var failed Name;Recorder{}.save(&failed);_=string(failed)`, body: `h.reader.read()`, registration: `&Handler{reader:Benign{}}`, mode: "benign"},
		{name: "startup_scalar_out_unresolved_receiver", setup: `type Name string;type Decision struct{name Name};type Recorder struct{};func(Recorder)save(p *Name){*p=source.Value().(*Decision).name}`, startup: `var failed Name;Recorder{}.save(&failed);_=string(failed)`, body: `h.reader.read()`, registration: `source.Value().(*Handler)`, mode: "unknown"},
		{name: "startup_scalar_out_reader", setup: `type Name string;type Decision struct{name Name};type Recorder struct{};func(Recorder)save(p *Name){*p=source.Value().(*Decision).name}`, startup: `var failed Name;Recorder{}.save(&failed);_=string(failed)`, body: `h.reader.read()`, registration: `&Handler{reader:Concrete{}}`, mode: "reader"},
		{name: "startup_scalar_out_addressed_receiver", setup: `type Name string;type Decision struct{name Name};type Recorder struct{};func(Recorder)save(p *Name){*p=source.Value().(*Decision).name}`, startup: `var failed Name;Recorder{}.save(&failed);_=string(failed)`, body: `source.Assign(&h,source.Value().(*Handler));h.reader.read()`, registration: `&Handler{reader:Benign{}}`, mode: "unknown"},
		{name: "startup_scalar_out_other_address", setup: `type Name string;type Decision struct{name Name};func save(p *Name){*p=source.Value().(*Decision).name}`, startup: `var failed Name;source.Mutate(&failed);save(&failed)`, body: `h.reader.read()`, registration: `&Handler{reader:Benign{}}`, mode: "unknown"},
		{name: "startup_scalar_out_method_value", setup: `type Name string;type Decision struct{name Name};type Recorder struct{};func(Recorder)save(p *Name){*p=source.Value().(*Decision).name}`, startup: `var failed Name;Recorder{}.save(&failed);f:=Recorder{}.save;f(&failed)`, body: `h.reader.read()`, registration: `&Handler{reader:Benign{}}`, mode: "unknown"},
		{name: "startup_scalar_out_opaque_destination", setup: `type Name string;type Decision struct{name Name};func save(p *Name){*p=source.Value().(*Decision).name}`, startup: `var failed Name;save(&failed);save(source.Value().(*Name))`, body: `h.reader.read()`, registration: `&Handler{reader:Benign{}}`, mode: "unknown"},
		{name: "startup_scalar_out_interface", setup: `type Name string;type Decision struct{name Name};type Recorder struct{};type saver interface{save(*Name)};func(Recorder)save(p *Name){*p=source.Value().(*Decision).name}`, startup: `var failed Name;Recorder{}.save(&failed);var other saver=Recorder{};other.save(source.Value().(*Name))`, body: `h.reader.read()`, registration: `&Handler{reader:Benign{}}`, mode: "unknown"},
		{name: "startup_out_actual_reader_field", setup: `type Decision struct{reader Reader};func save(p *Reader){*p=source.Value().(*Decision).reader}`, body: `save(&h.reader);h.reader.read()`, registration: `&Handler{reader:Benign{}}`, mode: "unknown"},
		{name: "startup_init_foreign", setup: `var shared=&Box{reader:Benign{}};func init(){source.Assign(shared,Box{reader:Concrete{}})}`, body: `shared.reader.read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "startup_multiple_init_foreign", setup: `var shared=&Box{reader:Benign{}};func init(){};func init(){source.Assign(shared,Box{reader:Concrete{}})}`, body: `shared.reader.read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "startup_init_unrelated", setup: `var shared=&Box{reader:Benign{}};var other=&Box{};func init(){source.Assign(other,Box{reader:Concrete{}})}`, body: `shared.reader.read()`, registration: `&Handler{}`, mode: "benign"},
		{name: "startup_initializer_foreign", setup: `var shared=&Box{reader:Benign{}};func warm()bool{source.Assign(shared,Box{reader:Concrete{}});return true};var _=warm()`, body: `shared.reader.read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "startup_initializer_unrelated", setup: `var shared=&Box{reader:Benign{}};var other=&Box{};func warm()bool{source.Assign(other,Box{reader:Concrete{}});return true};var _=warm()`, body: `shared.reader.read()`, registration: `&Handler{}`, mode: "benign"},
		{name: "startup_receiver", setup: `var shared=&Box{reader:Benign{}};func init(){cell:=source.Cell[Box]{Dest:shared};cell.Set(Box{reader:Concrete{}})}`, body: `shared.reader.read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "startup_receiver_noargs", setup: `var shared=&Box{reader:Benign{}};func init(){cell:=source.Pending[Box]{Dest:shared,Value:Box{reader:Concrete{}}};cell.Set()}`, body: `shared.reader.read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "startup_receiver_bound", setup: `var shared=&Box{reader:Benign{}};func init(){cell:=source.Cell[Box]{Dest:shared};set:=cell.Set;set(Box{reader:Concrete{}})}`, body: `shared.reader.read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "startup_named_callback", setup: `var shared=&Box{reader:Benign{}};func mutateShared(){*shared=Box{reader:Concrete{}}};func init(){source.Invoke(any(mutateShared))}`, body: `shared.reader.read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "startup_main_foreign", setup: `var shared=&Box{reader:Benign{}}`, startup: `source.Assign(shared,Box{reader:Concrete{}})`, body: `shared.reader.read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "startup_main_unrelated", setup: `var shared=&Box{reader:Benign{}};var other=&Box{}`, startup: `source.Assign(other,Box{reader:Concrete{}})`, body: `shared.reader.read()`, registration: `&Handler{}`, mode: "benign"},
		{name: "startup_constructor_local_reader", setup: `func configure(h *Handler){h.reader=Concrete{}};func makeHandler()*Handler{h:=&Handler{reader:Benign{}};configure(h);return h}`, body: `h.reader.read()`, registration: `makeHandler()`, mode: "reader"},
		{name: "startup_constructor_local_unrelated", setup: `func configure(h *Handler){h.reader=Concrete{}};func makeHandler()*Handler{h:=&Handler{reader:Benign{}};other:=&Handler{};configure(other);return h}`, body: `h.reader.read()`, registration: `makeHandler()`, mode: "benign"},
		{name: "guarded_explicit_nil", body: `box:=&Box{reader:nil};if box.reader!=nil{box.reader.read()}`, registration: `&Handler{}`, mode: "benign"},
		{name: "guarded_omitted_zero", body: `box:=&Box{};if box.reader!=nil{box.reader.read()}`, registration: `&Handler{}`, mode: "benign"},
		{name: "guarded_nil_unrelated_receiver", body: `box:=&Box{reader:nil};other:=&Box{};cell:=source.Cell[Box]{Dest:other};cell.Set(Box{reader:Concrete{}});if box.reader!=nil{box.reader.read()}`, registration: `&Handler{}`, mode: "benign"},

		{name: "registrar_local_mutation", setup: `type Registrar struct{};func(Registrar)RegisterService(_ any,h any){h.(*Handler).reader=Concrete{}}`, registrar: `Registrar{}`, body: `h.reader.read()`, registration: `&Handler{reader:Benign{}}`, mode: "reader"},
		{name: "registrar_local_benign", setup: `type Registrar struct{};func(Registrar)RegisterService(_ any,h any){}`, registrar: `Registrar{}`, body: `h.reader.read()`, registration: `&Handler{reader:Benign{}}`, mode: "benign"},
		{name: "registrar_nil_pointer_mutation", setup: `type Registrar struct{};func(*Registrar)RegisterService(_ any,h any){h.(*Handler).reader=Concrete{}}`, registrar: `(*Registrar)(nil)`, body: `h.reader.read()`, registration: `&Handler{reader:Benign{}}`, mode: "reader"},
		// Один и тот же box.F вызывает метод, выбранный при захвате r.read.
		{name: "captured_interface_field_reader", setup: capturedReadField, body: "var r Reader=Concrete{}; box:=Holder{F:r.read};box.F()", registration: "&Handler{}", mode: "reader"},
		{name: "captured_interface_field_benign", setup: capturedReadField, body: "var r Reader=Benign{}; box:=Holder{F:r.read};box.F()", registration: "&Handler{}", mode: "benign"},
		{name: "captured_interface_field_opaque", setup: capturedReadField, body: "r:=source.Value().(Reader); box:=Holder{F:r.read};box.F()", registration: "&Handler{}", mode: "unknown"},
		// Когда тот же callback владеет указателем на Worker, проверка времени
		// жизни его поля reader видит достижимый через box.F объект Worker.
		// Объявление известного READ не должно погасить независимый UNKNOWN.
		{name: "captured_interface_mutable_receiver_reader", setup: callerCapturedFieldSetup, body: "var r Runner=&Worker{reader:Concrete{}}; box:=Holder{F:r.run};box.F(Benign{})", registration: "&Handler{}", mode: "unknown_reader"},
		{name: "captured_interface_mutable_receiver_benign", setup: callerCapturedFieldSetup, body: "var r Runner=&Worker{reader:Benign{}}; box:=Holder{F:r.run};box.F(Benign{})", registration: "&Handler{}", mode: "unknown"},
		{name: "captured_interface_mutable_receiver_opaque", setup: callerCapturedFieldSetup, body: "r:=source.Value().(Runner); box:=Holder{F:r.run};box.F(Benign{})", registration: "&Handler{}", mode: "unknown"},
		{name: "registrar_opaque", registrar: `source.Value().(interface{RegisterService(any,any)})`, body: `h.reader.read()`, registration: `&Handler{reader:Benign{}}`, mode: "unknown"},
		{name: "qualified_interface_address", body: `source.Assign[any](&source.Shared,Concrete{});source.Shared.(Reader).read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "qualified_interface_address_unrelated", body: `source.Assign[any](&source.Other,Concrete{});if source.Shared!=nil{source.Shared.(Reader).read()}`, registration: `&Handler{}`, mode: "benign"},
		{name: "qualified_function_address", body: `source.Assign[func()](&source.SharedFn,func(){Concrete{}.read()});source.SharedFn()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "qualified_function_address_unrelated", body: `source.Assign[func()](&source.OtherFn,func(){Concrete{}.read()});if source.SharedFn!=nil{source.SharedFn()}`, registration: `&Handler{}`, mode: "benign"},
		{name: "implicit_field_receiver_address", setup: `type Holder struct{slot source.Slot[Reader]}`, body: `holder:=&Holder{};holder.slot.Set(Concrete{});holder.slot.Value.read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "implicit_field_receiver_address_bound", setup: `type Holder struct{slot source.Slot[Reader]}`, body: `holder:=&Holder{};set:=holder.slot.Set;set(Concrete{});holder.slot.Value.read()`, registration: `&Handler{}`, mode: "unknown"},
		{name: "implicit_field_receiver_address_unrelated", setup: `type Holder struct{slot source.Slot[Reader]}`, body: `holder:=&Holder{};other:=&Holder{};other.slot.Set(Concrete{});if holder.slot.Value!=nil{holder.slot.Value.read()}`, registration: `&Handler{}`, mode: "benign"},
		{name: "implicit_field_receiver_address_bound_unrelated", setup: `type Holder struct{slot source.Slot[Reader]}`, body: `holder:=&Holder{};other:=&Holder{};set:=other.slot.Set;set(Concrete{});if holder.slot.Value!=nil{holder.slot.Value.read()}`, registration: `&Handler{}`, mode: "benign"},
		{name: "explicit_nil_reader", body: `var reader Reader=nil;if reader!=nil{reader.read()}`, registration: `&Handler{}`, mode: "benign"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := callerSoundnessProgram(t, tc.setup, tc.body, tc.registration, tc.startup, tc.registrar)
			judge := func(declarations []CallerReadDeclaration) CallerIdentityReport {
				return judgeCallerIdentity(p, declarations, map[string]bool{"fixture/source": true})
			}
			report := judge(base)
			if report.Invalid != "" {
				t.Fatal(report.Invalid)
			}
			if tc.mode == "unknown" || tc.mode == "unknown_reader" {
				if tc.name == "external_callback_parameter_untraced" && report.Work.UnboundCallbackQueries == 0 {
					t.Fatal("external callback parameter lost its unknown provenance diagnostic")
				}
				unresolved := false
				for _, f := range report.Findings {
					unresolved = unresolved || strings.Contains(f, "неразрешённый")
				}
				if !unresolved {
					t.Fatalf("opaque input accepted: %+v", report)
				}
				if tc.mode == "unknown" {
					return
				}
			}
			if tc.mode == "benign" {
				if len(report.Findings) != 0 {
					t.Fatalf("lawful benign twin: %v", report.Findings)
				}
				return
			}
			var read *CallerIdentityRead
			for i := range report.Reads {
				r := &report.Reads[i]
				if r.Site == "(fixture/app.Concrete).read" {
					read = r
					break
				}
			}
			if read == nil || read.Coordinate == "" {
				t.Fatalf("real producer not visited: %+v", report)
			}
			undeclared := false
			for _, f := range report.Findings {
				undeclared = undeclared || strings.Contains(f, "чтение личности без объявления") && strings.Contains(f, read.Coordinate)
			}
			if !undeclared || tc.mode == "reader" && len(report.Findings) != 1 {
				t.Fatalf("undeclared negative: %+v", report)
			}
			declared := append(append([]CallerReadDeclaration{}, base...), CallerReadDeclaration{RPC: rpc, Producer: producer, Site: read.Site, Kind: CallerObservation, Reason: "Same reader, only declaration differs."})
			twin := judge(declared)
			if tc.mode == "unknown_reader" {
				unresolved := false
				for _, f := range twin.Findings {
					if strings.Contains(f, "чтение личности без объявления") {
						t.Fatalf("declared producer remains undeclared: %+v", twin)
					}
					unresolved = unresolved || strings.Contains(f, "неразрешённый")
				}
				if !unresolved || len(twin.Reads) != len(report.Reads) {
					t.Fatalf("declaration erased unknown callback provenance: %+v", twin)
				}
				return
			}
			if len(twin.Findings) != 0 || len(twin.Reads) != len(report.Reads) {
				t.Fatalf("lawful declaration twin: %+v", twin)
			}
		})
	}
}

const callerQueueFixture = `type Job struct{reader Reader};type Worker struct{backlog []Job}
func(w *Worker)put(reader Reader){j:=Job{reader:reader};w.backlog=append(w.backlog,j)}
func(w *Worker)dequeue()Job{j:=w.backlog[0];w.backlog[0]=Job{};w.backlog=w.backlog[1:];return j}
func(w *Worker)launch(){j:=w.dequeue();j.reader.read()}`

const callerCallbackQueueFixture = `type Job struct{fn func()};type Worker struct{backlog []Job}
func(w *Worker)put(fn func()){j:=Job{fn:fn};w.backlog=append(w.backlog,j)}
func(w *Worker)dequeue()Job{j:=w.backlog[0];w.backlog[0]=Job{};w.backlog=w.backlog[1:];return j}
func(w *Worker)launch(){j:=w.dequeue();j.fn()}`

const callerFluentFixture = `func newBox()*Box{return &Box{}}
func(box *Box)withReader(reader Reader)*Box{box.reader=reader;return box}
func(box *Box)again()*Box{return box}`

const callerOptionFixture = `type Option func(*Box)
func withReader(reader Reader)Option{return func(out *Box){out.reader=reader}}
func options(opts ...Option)Box{var out Box;for _,apply:=range opts{apply(&out)};return out}`

// Memo сохраняет завершённый ответ, а не часть рекурсивного обхода;
// новые live bindings и следующий RPC имеют отдельный срок жизни.
func TestCallerIdentityResolutionMemoUsesOnlyStableAnswers(t *testing.T) {
	p := callerSoundnessProgram(t, "", `var reader Reader=Concrete{};reader.read();benign:=Benign{};_=benign;var cyclic Reader;cyclic=cyclic`, `&Handler{}`)
	g := newCallerGraph(p)
	var reader, cyclic valueSrc
	var readerVar *types.Var
	var benign valueSrc
	sp := p.root
	ast.Inspect(sp.files[0], func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.ValueSpec:
			for _, id := range x.Names {
				if id.Name == "reader" {
					readerVar = sp.info.Defs[id].(*types.Var)
					reader = valueSrc{pkg: sp, expr: id, tuple: -1}
				}
				if id.Name == "cyclic" {
					cyclic = valueSrc{pkg: sp, expr: id, tuple: -1}
				}
			}
		case *ast.CompositeLit:
			if named := namedOf(sp.info.TypeOf(x)); named != nil && named.Obj().Name() == "Benign" {
				benign = valueSrc{pkg: sp, expr: x, tuple: -1}
			}
		}
		return true
	})
	if readerVar == nil || benign.expr == nil || cyclic.expr == nil {
		t.Fatal("fixture sources missing")
	}
	first, u := g.resolve(reader, true, map[callerResolveKey]bool{})
	if u || len(first) != 1 {
		t.Fatalf("initial source: %v %v", first, u)
	}
	before := g.work.ResolveHits
	second, u := g.resolve(reader, true, map[callerResolveKey]bool{})
	if u || len(second) != 1 || g.work.ResolveHits <= before {
		t.Fatalf("completed source not reused: %+v", g.work)
	}
	g.lifetimeScanning = true
	initial, initialUnknown := g.resolve(reader, true, map[callerResolveKey]bool{})
	initialHits := g.work.ResolveInitialHits
	g.resolve(reader, true, map[callerResolveKey]bool{})
	g.lifetimeScanning = false
	if initialUnknown || len(initial) != 1 || g.work.ResolveInitialHits <= initialHits {
		t.Fatal("complete initial provenance was not independently reused")
	}
	objects, objectUnknown := g.callerObjects(reader, map[callerObjectSourceID]bool{})
	benignObject := callerObjectKey{pkg: benign.pkg, expr: benign.expr}
	if objectUnknown || objects[benignObject] {
		t.Fatal("object provenance did not retain the initial binding")
	}
	g.addCallerLive(readerVar, benign)
	changedObjects, objectUnknown := g.callerObjects(reader, map[callerObjectSourceID]bool{})
	if objectUnknown || !changedObjects[benignObject] {
		t.Fatal("object provenance retained a stale binding")
	}
	_, objectUnknown = g.callerObjects(cyclic, map[callerObjectSourceID]bool{})
	if !objectUnknown {
		t.Fatal("unanchored object cycle became a complete value")
	}
	changed, u := g.resolve(reader, true, map[callerResolveKey]bool{})
	if u || len(changed) != 2 {
		t.Fatalf("stale answer after binding change: %v %v", changed, u)
	}
	g.lifetimeScanning = true
	initial, initialUnknown = g.resolve(reader, true, map[callerResolveKey]bool{})
	if initialUnknown || len(initial) != 2 {
		t.Fatal("initial provenance retained a stale binding")
	}
	initialCuts := g.work.ResolveCycleCuts
	g.resolve(cyclic, true, map[callerResolveKey]bool{})
	g.resolve(cyclic, true, map[callerResolveKey]bool{})
	g.lifetimeScanning = false
	if g.work.ResolveCycleCuts < initialCuts+2 {
		t.Fatal("initial provenance cached a partial recursive answer")
	}
	before = g.work.ResolveCycleCuts
	g.resolve(cyclic, true, map[callerResolveKey]bool{})
	g.resolve(cyclic, true, map[callerResolveKey]bool{})
	if g.work.ResolveCycleCuts < before+2 {
		t.Fatalf("partial recursive answer reused: %+v", g.work)
	}
	checkCallerInitialMemoIsolation(t)
	t.Logf("WORK %+v", g.work)
}

// Прогретый кеш начальных источников не должен скрывать реальную позднюю запись времени жизни.
func checkCallerInitialMemoIsolation(t *testing.T) {
	t.Helper()
	p := callerSoundnessProgram(t, "", `box:=&Box{reader:Benign{}};source.Assign(box,Box{reader:Concrete{}});box.reader.read()`, `&Handler{}`)
	g := newCallerGraph(p)
	g.safeExternal = map[string]bool{"fixture/source": true}
	var src valueSrc
	for node, body := range g.bodies {
		if node.fn == nil || node.fn.Name() != "RPC" {
			continue
		}
		g.markCallerCalled(node)
		ast.Inspect(body.node, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "reader" {
				src = valueSrc{pkg: body.sp, fk: callerKey(node), expr: sel, tuple: -1}
			}
			return true
		})
	}
	if src.expr == nil {
		t.Fatal("initial/full isolation fixture missing")
	}
	g.lifetimeScanning = true
	initial, unknown := g.resolve(src, true, map[callerResolveKey]bool{})
	hits := g.work.ResolveInitialHits
	g.resolve(src, true, map[callerResolveKey]bool{})
	g.lifetimeScanning = false
	if unknown || len(initial) != 1 || g.work.ResolveInitialHits <= hits {
		t.Fatal("initial field provenance did not complete and reuse")
	}
	// Незавершённый запрос поля может временно не иметь источника.
	// Этот снимок нельзя кешировать как начальный nil-ответ после завершения запроса.
	selector := src.expr.(*ast.SelectorExpr)
	base := src
	base.expr = selector.X
	g.resolveMemo = nil
	g.fieldQueries = append(g.fieldQueries, callerFieldQuery{
		source: callerResolveKeyFor(base, true),
		fields: fieldPath(src.pkg.info.Selections[selector]),
	})
	g.lifetimeScanning = true
	g.resolve(src, true, map[callerResolveKey]bool{})
	g.resolve(src, true, map[callerResolveKey]bool{})
	g.fieldQueries = nil
	afterSnapshot, snapshotUnknown := g.resolve(src, true, map[callerResolveKey]bool{})
	g.lifetimeScanning = false
	if snapshotUnknown || len(afterSnapshot) != 1 || afterSnapshot[0].nilValue || afterSnapshot[0].typ != initial[0].typ {
		t.Fatal("partial field snapshot escaped into the initial cache")
	}
	_, unknown = g.resolve(src, true, map[callerResolveKey]bool{})
	if !unknown {
		t.Fatal("initial cache bypassed the actual opaque lifetime write")
	}
}

func TestCallerIdentityResolutionMemoBudgetRecomputesCompleteAnswers(t *testing.T) {
	p := callerSoundnessProgram(t, "", `var reader Reader=Concrete{};reader=Benign{};reader.read()`, `&Handler{}`)
	g := newCallerGraph(p)
	g.resolveEntryCap, g.resolveValueCap = 1, 1
	var src valueSrc
	ast.Inspect(p.root.files[0], func(n ast.Node) bool {
		if spec, ok := n.(*ast.ValueSpec); ok {
			for _, id := range spec.Names {
				if id.Name == "reader" {
					src = valueSrc{pkg: p.root, expr: id, tuple: -1}
				}
			}
		}
		return true
	})
	if src.expr == nil {
		t.Fatal("fixture reader missing")
	}
	first, u := g.resolve(src, true, map[callerResolveKey]bool{})
	before := g.work.ResolveEvaluations
	second, v := g.resolve(src, true, map[callerResolveKey]bool{})
	if u || v || len(first) != 2 || len(second) != 2 || first[0] != second[0] || first[1] != second[1] {
		t.Fatalf("cache admission truncated or changed answer: %v/%v %v/%v", first, second, u, v)
	}
	g.lifetimeScanning = true
	initial, unknown := g.resolve(src, true, map[callerResolveKey]bool{})
	g.lifetimeScanning = false
	if unknown || len(initial) != 2 {
		t.Fatal("shared memo budget truncated initial provenance")
	}
	if g.work.ResolveRejected == 0 || g.work.ResolveEvaluations <= before || len(g.resolveMemo)+len(g.initialResolveMemo) > 1 || g.resolveWeight+g.initialResolveWeight > 1 {
		t.Fatalf("cache budget did not recompute: %+v", g.work)
	}
	t.Logf("WORK %+v", g.work)
}

func TestCallerIdentityExactUnionKeepsProvenance(t *testing.T) {
	src := valueSrc{expr: ast.NewIdent("source"), tuple: -1}
	element := src
	element.elem = true
	ranged := src
	ranged.rangeVal = true
	owner := src
	owner.fk = fkey{lit: &ast.FuncLit{}}
	refs := callerDistinctSources([]valueSrc{src, src, element, ranged, owner, element})
	if len(refs) != 4 {
		t.Fatalf("distinct provenance lost: %+v", refs)
	}
	a := callerOrigin{source: src}
	b := callerOrigin{source: element}
	c := callerOrigin{source: src, foreign: true}
	d := callerOrigin{source: src, nilValue: true}
	values := callerDistinctOrigins([]callerOrigin{a, a, b, c, d, b})
	if len(values) != 4 || values[0] != a || values[1] != b || values[2] != c || values[3] != d {
		t.Fatalf("origin union changed identity: %+v", values)
	}
	if callerResolveKeyFor(src, true) == callerResolveKeyFor(element, true) || callerResolveKeyFor(src, true) == callerResolveKeyFor(owner, true) {
		t.Fatal("memo key discarded provenance")
	}
}

func TestCallerIdentityAddressTakenPreservesInstantiatedFieldAndOrigin(t *testing.T) {
	p := callerSoundnessProgram(t, `type Generic[T any] struct{taken,untouched T}`, `box:=Generic[func()]{};_=&box.taken;_=box.untouched`, `&Handler{}`)
	g := newCallerGraph(p)
	fields := map[string]*types.Var{}
	sources := map[string]valueSrc{}
	for expr, sel := range p.root.info.Selections {
		if sel.Kind() != types.FieldVal || expr.Sel.Name != "taken" && expr.Sel.Name != "untouched" {
			continue
		}
		v, ok := sel.Obj().(*types.Var)
		if !ok || v == v.Origin() {
			t.Fatal("проверка требует отдельного объекта инстанцированного generic-поля")
		}
		fields[expr.Sel.Name] = v
		sources[expr.Sel.Name] = valueSrc{pkg: p.root, expr: expr, tuple: -1}
	}
	if len(fields) != 2 {
		t.Fatalf("не найдены оба инстанцированных поля: %v", fields)
	}
	taken, untouched := fields["taken"], fields["untouched"]
	if !g.index.addrTaken[taken] || !g.index.addrTaken[taken.Origin()] || g.index.addrTaken[untouched] || g.index.addrTaken[untouched.Origin()] {
		t.Fatal("адресуемость должна сохранять исходный объект и Origin только адресованного поля")
	}
	// Старый resolver читает исходный объект поля, а не его Origin.
	r := newStrResolver(&surfaceFlow{prog: p, idx: g.index})
	hasAddressLeaf := func(v *types.Var) bool {
		for reason := range r.field(v).leaves {
			if strings.Contains(reason, "адрес отдан наружу") {
				return true
			}
		}
		return false
	}
	if !hasAddressLeaf(taken) || hasAddressLeaf(untouched) {
		t.Fatal("старый resolver потерял адресуемость инстанцированного поля или приписал её соседнему")
	}
	// При вложенном доказательстве адресованное поле обязано дойти до барьера
	// начального режима. Неадресованная функция законно обходит этот барьер.
	g.lifetimeScanning = true
	cuts, skips := g.resolveCuts, g.initialSkips
	if g.callerVariableLifetimeUnknown(sources["untouched"], untouched) || g.resolveCuts != cuts || g.initialSkips != skips {
		t.Fatal("неадресованное поле потеряло доказательство стабильности значения функции")
	}
	if g.callerVariableLifetimeUnknown(sources["taken"], taken) || g.resolveCuts != cuts+1 || g.initialSkips != skips+1 {
		t.Fatal("caller analyzer потерял обязательный барьер времени жизни через Origin")
	}
}
