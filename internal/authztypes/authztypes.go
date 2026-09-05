// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package authztypes holds the NEUTRAL authorization value types shared across
// the Clean-Architecture boundary between the use-case layer (internal/service)
// and whatever answers relation questions — today the decision door
// (internal/authzcascade) over the relational form, before it an adapter to an
// external engine.
//
// Why a dedicated leaf package: the service-layer port interfaces (Authorizer,
// RelationWriter) speak in these types, and the answering side produces
// them. If the types lived in internal/clients (the adapter), the service ports
// would be pinned to an adapter DTO — a dependency-rule inversion (use-case →
// adapter). Hoisting them into this stdlib-only leaf package lets BOTH the
// service ports and the adapter reference a neutral type: the port is a real
// abstraction (substitutable by any relation backend), and the adapter depends
// inward on this package rather than the port depending outward on the adapter.
//
// This package imports ONLY the standard library.
package authztypes

// ExpandTree — ОСНОВАНИЯ права на объекте, развёрнутые в набор субъектов.
//
// Имя оставлено историческим, форма — нет. Дерева произвольной глубины здесь не
// бывает: источник реляционный, основание — плоская запись (факт · выдача ·
// членство), и рёбра «вычисленного набора» и «набора через кортеж» производил
// внешний движок, которого больше нет. Поля под них сняты, чтобы структура не
// обещала глубины, которой неоткуда взяться.
type ExpandTree struct {
	Leaves []string
	// Truncated — ответ не поместился в предел. Остаётся честным полем: перечень
	// оснований конечен, но не обязан быть коротким.
	Truncated bool
}

// ConditionalTuple — a relation tuple optionally tagged with a Condition
// reference + per-tuple context. Conditional tuples evaluate the named
// condition's CEL expression at Check time using `Context` ∪ `request.Context`.
type ConditionalTuple struct {
	User      string
	Relation  string
	Object    string
	Condition *TupleConditionRef
}

// TupleConditionRef — points to a Condition either by built-in name
// (`mfa_fresh`, `non_expired`, …) or by Condition resource id (`cnd_…`). Either
// Name or the resource id must be set; per-tuple context ships inline as
// `Context`.
type TupleConditionRef struct {
	// Name — built-in condition name OR Condition resource id (`cnd_…`).
	Name string
	// Context — per-tuple CEL-context (e.g. `{"allowed_cidrs":[...]}` for
	// source_ip_in_range). Empty for builtin conditions taking only
	// request-time context.
	Context map[string]any
}
