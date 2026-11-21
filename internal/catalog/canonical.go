// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package catalog

import (
	"cmp"
	"encoding/json"
	"fmt"
	"slices"
)

// CanonicalJSON закрепляет значение строк, а не случайный порядок ответа SQL.
// Порядок внутри manifest-массивов сохраняется: его различает SameForm.
// Повтор ключа ресурса/глагола отвергается, чтобы один digest не обозначал
// разные результаты прежнего last-wins чтения. Admission остаётся у NewFacts.
// Результат не разделяет с вызывающим изменяемые срезы.
func CanonicalJSON(h Halves) ([]byte, error) {
	live, err := canonicalRows(h.Live)
	if err != nil {
		return nil, fmt.Errorf("live catalog: %w", err)
	}
	retired, err := canonicalRows(h.Retired)
	if err != nil {
		return nil, fmt.Errorf("retired catalog: %w", err)
	}
	return json.Marshal(Halves{Live: live, Retired: retired})
}

func canonicalRows(in Rows) (Rows, error) {
	// append к nil одновременно нормализует пустой и nil перечни.
	out := Rows{
		Modules:   append([]string(nil), in.Modules...),
		Resources: append([]ResourceRow(nil), in.Resources...),
		Verbs:     append([]VerbRow(nil), in.Verbs...),
	}
	slices.Sort(out.Modules)
	out.Modules = slices.Compact(out.Modules)
	for i := range out.Resources {
		r := &out.Resources[i]
		r.ParentTypes = append([]string(nil), r.ParentTypes...)
		r.ParentNames = append([]string(nil), r.ParentNames...)
		r.Writes = append([]string(nil), r.Writes...)
	}
	slices.SortFunc(out.Resources, func(a, b ResourceRow) int {
		if c := cmp.Compare(a.Module, b.Module); c != 0 {
			return c
		}
		return cmp.Compare(a.Resource, b.Resource)
	})
	for i := 1; i < len(out.Resources); i++ {
		a, b := out.Resources[i-1], out.Resources[i]
		if a.Module == b.Module && a.Resource == b.Resource {
			return Rows{}, fmt.Errorf("duplicate resource %q.%q", a.Module, a.Resource)
		}
	}
	slices.SortFunc(out.Verbs, func(a, b VerbRow) int {
		if c := cmp.Compare(a.Module, b.Module); c != 0 {
			return c
		}
		if c := cmp.Compare(a.Resource, b.Resource); c != 0 {
			return c
		}
		return cmp.Compare(a.Verb, b.Verb)
	})
	for i := 1; i < len(out.Verbs); i++ {
		a, b := out.Verbs[i-1], out.Verbs[i]
		if a.Module == b.Module && a.Resource == b.Resource && a.Verb == b.Verb {
			return Rows{}, fmt.Errorf("duplicate verb %q.%q.%q", a.Module, a.Resource, a.Verb)
		}
	}
	return out, nil
}
