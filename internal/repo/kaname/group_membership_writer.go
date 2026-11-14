// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package kaname

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// GroupMembershipWriterFactory получает полный scope из текущих sources,
// заново проверяет его после fences и только потом открывает primitive writer.
// kaname#1034: участие в protocol не является доказательством D1/D2/D3.
type GroupMembershipWriterFactory interface {
	GroupMembershipWriter(context.Context, domain.GroupMember) (Writer, error)
}
