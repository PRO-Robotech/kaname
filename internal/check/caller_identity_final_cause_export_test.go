// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"strings"
	"weak"
)

var finalCauseSites = [...]struct {
	file         string
	line, column int
	method       string
}{
	{"internal/admission/admission.go", 94, 16, "PersonMarks"},
}

func newFinalCauseProbe(p *surfaceProgram) *finalCauseProbe {
	d := &finalCauseProbe{index: make(map[ast.Expr]int), memo: make(map[finalMemoKey]finalSaved), records: make(map[weak.Pointer[callerOriginRecord]]finalSaved)}
	for _, sp := range p.pkgs {
		for _, f := range sp.files {
			filename := p.fset.Position(f.Pos()).Filename
			if filename == "internal/apps/kaname/modulecatalog/rows.go" {
				ast.Inspect(f, func(n ast.Node) bool {
					read, ok := n.(*ast.SelectorExpr)
					if ok {
						pos := p.fset.PositionFor(read.Pos(), false)
						if pos.Line == 109 && pos.Column == 26 && read.Sel.Name == "Module" {
							d.read = read
						}
					}
					return true
				})
			}
			for i, want := range finalCauseSites {
				if filename != want.file {
					continue
				}
				ast.Inspect(f, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					sel, ok := call.Fun.(*ast.SelectorExpr)
					if !ok || sel.Sel.Name != want.method {
						return true
					}
					pos := p.fset.Position(call.Pos())
					if pos.Line != want.line || pos.Column != want.column {
						return true
					}
					selection := sp.info.Selections[sel]
					if selection == nil || selection.Kind() != types.MethodVal {
						return true
					}
					_, ok = selection.Obj().(*types.Func)
					if !ok {
						return true
					}
					d.sites[i] = finalSite{Root: sel}
					d.index[sel] = i
					return true
				})
			}
		}
	}
	return d
}

func (d *finalCauseProbe) print(p *surfaceProgram, findings []string, rpc string, declared bool) {
	location := func(pos token.Pos) string {
		if !pos.IsValid() {
			return ""
		}
		q := p.fset.Position(pos)
		if len(q.Filename) > 190 || strings.Contains(q.Filename, "..") || !(strings.HasPrefix(q.Filename, "internal/") || strings.HasPrefix(q.Filename, "cmd/") || strings.HasPrefix(q.Filename, "pkg/")) {
			return "<dependency>"
		}
		return q.String()
	}
	for i, r := range d.rows {
		w := finalCauseSites[i]
		site := fmt.Sprintf("%s:%d:%d", w.file, w.line, w.column)
		inReport := false
		for _, f := range findings {
			if f == rpc+": неразрешённый вызов "+site {
				inReport = true
				break
			}
		}
		layer := r.CompletedBy
		if r.Seen && layer == "" {
			layer = "raw"
		}
		row := struct {
			Site, Reason, ReasonAt, Evidence, Field, Terminal, TerminalAt, Resolution     string
			Round                                                                         int
			RuntimeNarrowing, SiteFound, ReadFound, Visited, Reported, ResolverUnresolved bool
			DuringObservedResolutions, InReturnedLifetime                                 copiedFieldObservation
		}{site, r.Cause.Kind, location(r.Cause.Source), location(r.Cause.Evidence), location(r.Cause.Field), r.Cause.Nested, location(r.Cause.NestedAt), layer, d.round, declared, len(d.index) == 1, d.read != nil, r.Seen, inReport, r.Unresolved, d.observed, r.Cause.Copied}
		data, _ := json.Marshal(row)
		fmt.Printf("CHECK_ONE_SITE %s\n", data)
	}
}
