// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package context намеренно совпадает со stdlib по имени, но не import path.
package context

import (
	stdcontext "context"
	"time"
)

type backgroundCtx struct {
	stdcontext.Context
	onCall func()
}

// New возвращает настоящий concrete spoof; каждый метод обнаруживает вызов.
func New(onCall func()) stdcontext.Context {
	return backgroundCtx{stdcontext.Background(), onCall}
}

func (c backgroundCtx) Deadline() (time.Time, bool) { c.onCall(); return c.Context.Deadline() }
func (c backgroundCtx) Done() <-chan struct{}       { c.onCall(); return c.Context.Done() }
func (c backgroundCtx) Err() error                  { c.onCall(); return c.Context.Err() }
func (c backgroundCtx) Value(key any) any           { c.onCall(); return c.Context.Value(key) }
