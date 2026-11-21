// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package granteffect

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/grantcoverage"
)

func TestUnionBuilderBoundsCompiledSourcesAndInvalidatesResult(t *testing.T) {
	c := compiler(t)
	direct := Direct{SourceID: "source", ObjectType: "strange_box", ObjectID: "box", Relation: "viewer", Recipient: domain.Subject{Type: domain.SubjectTypeUser, ID: "actor"}}
	small := c.CompileDirect(direct)
	if !small.Complete() || len(small.effects) == 0 {
		t.Fatalf("нет контрольного эффекта: %+v", small.Obligations())
	}
	direct.SourceID = strings.Repeat("x", 1<<16)
	large := c.CompileDirect(direct)
	if !large.Complete() || large.outputBytes == 0 {
		t.Fatalf("нет объёмного контрольного эффекта: %+v", large.Obligations())
	}
	direct.Relation = "unknown"
	empty := c.CompileDirect(direct)
	if len(empty.effects) != 0 {
		t.Fatal("неизвестное отношение породило эффект")
	}
	for _, tc := range []struct {
		name  string
		set   Set
		count int
	}{
		{"aggregate", small, min(MaxEffects/len(small.effects), MaxInputBytes/small.outputBytes)},
		{"bytes", large, MaxInputBytes / large.outputBytes},
		{"sources", empty, MaxEffects},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var b UnionBuilder
			for i := 0; i < tc.count; i++ {
				if err := b.Add(tc.set); err != nil {
					t.Fatalf("ранний отказ %d: %v", i, err)
				}
			}
			before := b.Build()
			if tc.set.Complete() && !before.Complete() {
				t.Fatal("допустимая сумма потеряла полноту")
			}
			if err := b.Add(tc.set); !errors.Is(err, ErrUnionLimit) {
				t.Fatalf("превышение принято: %v", err)
			}
			if err := b.Add(small); !errors.Is(err, ErrUnionLimit) {
				t.Fatalf("отказ сброшен: %v", err)
			}
			after := b.Build()
			if after.Complete() || len(after.Effects()) != 0 || len(after.Obligations()) == 0 {
				t.Fatal("отказ оставил частичный результат")
			}
		})
	}
}

func TestWithObligationsPreservesSnapshotEffectsAndCopiesInputs(t *testing.T) {
	s := compiler(t).Compile(binding(box("get")))
	if !s.Complete() {
		t.Fatal(s.Obligations())
	}
	input := []Obligation{{Code: "first"}}
	first := WithObligations(s, input...)
	input[0].Code = "changed"
	second := WithObligations(first, Obligation{Code: "second"})
	if !s.Complete() || first.Complete() || second.Complete() || first.Obligations()[0].Code != "first" || len(first.Obligations()) != 1 || len(second.Obligations()) != 2 {
		t.Fatal("обязательства изменены или удалены")
	}
	if second.Identity() != s.Identity() || !reflect.DeepEqual(second.Effects(), s.Effects()) {
		t.Fatal("изменены исходные эффекты или снимок")
	}
	if got := Prove(second, second); got.Status != grantcoverage.NotProved || got.Reason != grantcoverage.ReasonIncomplete {
		t.Fatalf("неполный набор доказан: %+v", got)
	}
	if Union(s, second).Complete() {
		t.Fatal("сосед погасил обязательства")
	}
}
