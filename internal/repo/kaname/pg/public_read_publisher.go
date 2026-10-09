// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/public_read"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// PublicReadPublisher — адаптер порта публикации для анонимного чтения над
// транзакцией вызывающего. Сравнение версий и строка журнала — в public_read.ApplyTx;
// здесь только перевод транзакции порта в транзакцию драйвера.
type PublicReadPublisher struct{}

// NewPublicReadPublisher — конструктор.
func NewPublicReadPublisher() *PublicReadPublisher {
	return &PublicReadPublisher{}
}

// ApplyTx — см. service.PublicReadPublisher.
func (p *PublicReadPublisher) ApplyTx(ctx context.Context, tx service.Tx, in service.PublicReadIntent) (bool, error) {
	out, err := public_read.ApplyTx(ctx, txAsPgx(tx), public_read.Publication{
		ObjectType:       in.ObjectType,
		ObjectID:         in.ObjectID,
		HeadType:         in.HeadType,
		Published:        in.Published,
		Version:          in.Version,
		ObjectGeneration: in.ObjectGeneration,
	})
	return out.Applied, err
}

// WithdrawTx — см. service.PublicReadPublisher.
func (p *PublicReadPublisher) WithdrawTx(ctx context.Context, tx service.Tx, objectType, objectID string) error {
	return public_read.WithdrawTx(ctx, txAsPgx(tx), objectType, objectID)
}

// DropStaleIncarnationTx — см. service.PublicReadPublisher.
func (p *PublicReadPublisher) DropStaleIncarnationTx(ctx context.Context, tx service.Tx, objectType, objectID, headType string) error {
	return public_read.DropStaleIncarnationTx(ctx, txAsPgx(tx), objectType, objectID, headType)
}

var _ service.PublicReadPublisher = (*PublicReadPublisher)(nil)
