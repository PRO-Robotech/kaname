// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"errors"
	"time"

	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/jackc/pgx/v5"
)

// Lifetime связывает RR-свидетельства с единственным RC writer этой попытки.
// Совпадения физического соединения недостаточно: pool повторно использует его.
// Эта структура не удостоверяет SQL preflight и не выдаёт разрешений.
type resourceAttemptLifetime struct {
	conn     *pgx.Conn
	bundle   *granteffect.Bundle
	writer   *authorityWriteTx
	prepared *authorityWriteTx
	at       time.Time
	ended    bool
}

func newResourceAttemptLifetime(conn *pgx.Conn, bundle *granteffect.Bundle) (*resourceAttemptLifetime, error) {
	if conn == nil || bundle == nil {
		return nil, kaname.ErrSourceUnconfirmed
	}
	if err := bundle.Validate(); err != nil {
		return nil, err
	}
	return &resourceAttemptLifetime{conn: conn, bundle: bundle}, nil
}

// До recheck runner закрепляет единственный RC writer. Это ещё не final
// clock: source capture нельзя перенести на следующую TX того же соединения.
func (l *resourceAttemptLifetime) prepare(w *authorityWriteTx) error {
	if l == nil || l.ended || l.prepared != nil || l.writer != nil || w == nil || w.closed || w.writeTx == nil || w.tx == nil || w.tx.Conn() != l.conn {
		return kaname.ErrSourceUnconfirmed
	}
	l.prepared = w
	return nil
}
func (l *resourceAttemptLifetime) beforeDecision(w *authorityWriteTx) bool {
	return l != nil && !l.ended && l.writer == nil && l.prepared == w && w != nil && !w.closed && w.writeTx != nil && w.tx != nil && w.tx.Conn() == l.conn
}

// Привязка однократна и выполняется runner после закрытого SQL preflight.
// Время сохраняется, чтобы позднее обновление fence не продлевало старое решение.
func (l *resourceAttemptLifetime) bind(w *authorityWriteTx) error {
	if l == nil || l.ended || l.writer != nil || l.conn == nil || l.bundle == nil ||
		(l.prepared != nil && l.prepared != w) || w == nil || w.closed || w.writeTx == nil || w.tx == nil || w.tx.Conn() != l.conn || w.fence.decisionAt.IsZero() {
		return kaname.ErrSourceUnconfirmed
	}
	l.writer, l.at = w, w.fence.decisionAt
	return nil
}

func (l *resourceAttemptLifetime) valid(w *authorityWriteTx, bundle *granteffect.Bundle) bool {
	return l != nil && !l.ended && l.writer != nil && l.writer == w && l.bundle == bundle &&
		w != nil && !w.closed && w.writeTx != nil && w.tx != nil && l.conn != nil && w.tx.Conn() == l.conn &&
		!l.at.IsZero() && l.at.Equal(w.fence.decisionAt)
}

func (l *resourceAttemptLifetime) close() {
	if l != nil {
		l.ended = true
	}
}

// Закрытие свидетельств предшествует любой ветви Commit, включая ошибочную.
// Владелец сохраняет canonical SQLSTATE→sentinel перевод вместе с raw cause:
// подтверждённый abort остаётся распознаваемым, неоднозначная доставка — нет.
type resourceDecisionTx struct {
	pgx.Tx
	lifetime         *resourceAttemptLifetime
	owner            *authorityWriteTx
	registrationBody *resourceRegistrationPreparation
}

func (t *resourceDecisionTx) Commit(ctx context.Context) error {
	if t == nil {
		return kaname.ErrSourceUnconfirmed
	}
	valid := t.lifetime != nil && t.lifetime.valid(t.owner, t.lifetime.bundle)
	t.lifetime.close()
	if !valid {
		return kaname.ErrSourceUnconfirmed
	}
	t.owner.closed = true
	w := t.owner.writeTx
	cause := w.tx.Commit(ctx)
	if cause == nil {
		return nil
	}
	// Общий mapErr намеренно скрывает SQL detail. Только этому private runner
	// нужен исходный SQLSTATE для confirmed-abort retry после bounded cleanup.
	if w.membershipHint != "" {
		return errors.Join(mapErr(cause, "Membership.Remove", w.membershipHint), cause)
	}
	return errors.Join(mapErr(cause, "", w.ownerFKHint), cause)
}

func (t *resourceDecisionTx) Rollback(ctx context.Context) error {
	if t == nil {
		return kaname.ErrSourceUnconfirmed
	}
	t.lifetime.close()
	if t.owner == nil || t.owner.writeTx == nil || t.owner.tx == nil {
		return kaname.ErrSourceUnconfirmed
	}
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	return t.owner.Rollback(cleanup)
}

var _ pgx.Tx = (*resourceDecisionTx)(nil)
