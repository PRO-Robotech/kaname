// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package registration

import (
	"context"
	"time"
)

// PreparedStore владеет всей попыткой, включая Commit и ограниченный повтор.
type PreparedStore interface {
	RunRegistrationWrite(context.Context, func(context.Context, Writer) error) error
}

func runRegistrationWrite(ctx context.Context, store Store, body func(context.Context, Writer) error) (err error) {
	if prepared, ok := store.(PreparedStore); ok {
		return prepared.RunRegistrationWrite(ctx, body)
	}
	w, err := store.Writer(ctx)
	if err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = w.Rollback(cleanup)
	}()
	if err = body(ctx, w); err != nil {
		return err
	}
	return w.Commit(ctx)
}
