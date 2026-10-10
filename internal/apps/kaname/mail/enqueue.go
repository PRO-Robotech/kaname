// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package mail

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/corelib/notify/feed"
)

// Enqueuer — порт use-case (З1): ставит письмо в транзакции события tx —
// транзакции глагола либо строки аудита. Лента пишет строку ленты и строку
// журнала подписки kaname в ту же tx (З17): откат tx уносит обе.
type Enqueuer interface {
	Enqueue(ctx context.Context, tx pgx.Tx, l Letter) (Result, error)
}

// Result — исход Enqueue и id строки ленты, записанной в tx (у Queued).
type Result struct {
	outcome Outcome
	feedID  string
}

// Outcome — исход постановки; рядом с ошибкой — OutcomeUnset.
func (r Result) Outcome() Outcome { return r.outcome }

// FeedID — id строки ленты, записанной в транзакции события, и признак, что
// она записана (только у OutcomeQueued). Строка видна после коммита tx.
func (r Result) FeedID() (string, bool) { return r.feedID, r.outcome == OutcomeQueued }

// feedEnqueuer — Enqueuer над лентой corelib: письмо ставит порождённый Send*
// шаблона, источник ленты берётся из контекста (feed.Source.Bind корня).
type feedEnqueuer struct {
	enabled Enabled
}

// NewEnqueuer — Enqueuer с флагом почты e, разобранным корнем (З2). Нулевой
// Enabled — отказ.
func NewEnqueuer(e Enabled) (Enqueuer, error) {
	if !e.Set() {
		return nil, errors.New("mail: флаг почты не разобран EnabledFrom — " + EnabledKey + " не прочитан корнем")
	}
	return feedEnqueuer{enabled: e}, nil
}

// Enqueue — решение «ставить строку или нет» и постановка:
//
//   - письмо мимо конструктора — ErrLetterUnbuilt при любом флаге;
//   - флаг выключен — OutcomeDisabled, не записано ничего (З2, NTF-1 Р9);
//   - строка записана — OutcomeQueued с id строки;
//   - лимит шаблона ленты исчерпан — OutcomeCapped; транзакция пригодна к
//     коммиту (feed З7);
//   - иной сторож ленты и ошибка хранилища — ошибка с именем шаблона:
//     транзакция события откатывается (З1, О6);
//   - флаг включён, а строки нет — ErrFlagMismatch.
func (q feedEnqueuer) Enqueue(ctx context.Context, tx pgx.Tx, l Letter) (Result, error) {
	if l.put == nil {
		return Result{}, ErrLetterUnbuilt
	}
	if !q.enabled.On() {
		return Result{outcome: OutcomeDisabled}, nil
	}
	id, queued, err := l.put(ctx, tx)
	switch {
	case errors.Is(err, feed.ErrLimitExhausted):
		return Result{outcome: OutcomeCapped}, nil
	case err != nil:
		return Result{}, fmt.Errorf("mail: шаблон %s: %w", l.template, err)
	case !queued:
		return Result{}, fmt.Errorf("%w: шаблон %s", ErrFlagMismatch, l.template)
	}
	return Result{outcome: OutcomeQueued, feedID: id}, nil
}
