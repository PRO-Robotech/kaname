// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"time"

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
func (p *PublicReadPublisher) ApplyTx(ctx context.Context, tx service.Tx, objectType, objectID string, published bool, version time.Time) (bool, error) {
	out, err := public_read.ApplyTx(ctx, txAsPgx(tx), public_read.Publication{
		ObjectType: objectType,
		ObjectID:   objectID,
		Published:  published,
		Version:    version,
	})
	return out.Applied, err
}

var _ service.PublicReadPublisher = (*PublicReadPublisher)(nil)
