// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package kaname

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// kaname#1034: закрытые mutation intents; scope выводит repository до старых locks.
type GroupMutation string

const (
	GroupCreate GroupMutation = "create"
	GroupUpdate GroupMutation = "update"
	GroupDelete GroupMutation = "delete"
)

type GroupLifecycleWriterFactory interface {
	GroupLifecycleWriter(context.Context, GroupMutation, domain.Group) (Writer, error)
}
