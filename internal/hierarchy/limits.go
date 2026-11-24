// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package hierarchy задаёт независимые конечные границы иерархии.
package hierarchy

const (
	// MaxPointerHops включает путь tag→item→box→project→account→cluster.
	// Более глубокий путь не допускается как частично известный.
	MaxPointerHops = 5
	// MaxStoredParentLinks — позиции сохранённой parentChain без неявного cluster.
	// Совпадает с ограничением resource_parent_edge.depth; схема не расширяется.
	MaxStoredParentLinks = 4
	// MaxImmediateParents — полный набор родителей одного шага SQL-обхода.
	// Это отдельная граница: увеличение глубины не увеличивает fanout.
	MaxImmediateParents = 4
)
