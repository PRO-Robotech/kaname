// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package granteffect

import "errors"

var ErrUnionLimit = errors.New("effect union resource limit exceeded")

// UnionBuilder ограничивает накопление до объединения. Нулевое значение готово
// к работе; после отказа Build не возвращает частично завершённый результат.
type UnionBuilder struct {
	sets        []Set
	effects     int
	outputBytes int
	failed      bool
}

func (b *UnionBuilder) Add(s Set) error {
	if b.failed {
		return ErrUnionLimit
	}
	if len(b.sets) >= MaxEffects || len(s.effects) > MaxEffects-b.effects || s.outputBytes > MaxInputBytes-b.outputBytes {
		b.failed = true
		b.sets = nil
		return ErrUnionLimit
	}
	b.sets = append(b.sets, s)
	b.effects += len(s.effects)
	b.outputBytes += s.outputBytes
	return nil
}

func (b *UnionBuilder) Build() Set {
	if b.failed {
		return Set{obligations: []Obligation{{Code: "structural_limit", Detail: "union accumulation"}}}
	}
	return Union(b.sets...)
}

// WithObligations только добавляет обязательства в независимую копию списка.
// Идентичность снимка, эффекты и существующие обязательства сохраняются.
func WithObligations(s Set, obligations ...Obligation) Set {
	out := s
	out.obligations = make([]Obligation, 0, len(s.obligations)+len(obligations))
	out.obligations = append(out.obligations, s.obligations...)
	out.obligations = append(out.obligations, obligations...)
	return out
}
