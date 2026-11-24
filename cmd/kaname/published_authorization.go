// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/PRO-Robotech/kaname/internal/authzsnapshot"
)

// preparePublishedAuthorization возвращает только первоначально подтверждённый
// снимок. Вызывающий задаёт окно явно и отдельно запускает работника в lifecycle
// службы; конструктор не оставляет фоновой работы после ошибки запуска.
func preparePublishedAuthorization(ctx context.Context, source authzsnapshot.Source, pollInterval, staleAfter time.Duration) (*authzsnapshot.Store, error) {
	if pollInterval <= 0 || staleAfter <= pollInterval {
		return nil, errors.New("published authorization: требуется 0 < poll interval < stale window")
	}
	store, err := authzsnapshot.NewStore(source, staleAfter)
	if err != nil {
		return nil, err
	}
	if err := refreshPublishedAuthorization(ctx, store, pollInterval); err != nil {
		return nil, fmt.Errorf("первоначальное подтверждение опубликованной модели: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if _, err := store.Pin(ctx); err != nil {
		return nil, fmt.Errorf("закрепить первоначальную опубликованную модель: %w", err)
	}
	return store, nil
}

// runPublishedAuthorization блокируется до отмены lifecycle. pollInterval должен
// совпадать с интервалом preparePublishedAuthorization. Ошибка чтения не продлевает
// подтверждение: Store сам закрывает запросы по исходному сроку актуальности.
// Работник продолжает опрос, чтобы восстановиться после недоступности источника.
func runPublishedAuthorization(ctx context.Context, store *authzsnapshot.Store, pollInterval time.Duration, logger *slog.Logger) error {
	if store == nil || logger == nil || pollInterval <= 0 {
		return errors.New("published authorization: требуются Store, logger и положительный poll interval")
	}
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return nil
		}
		if err := refreshPublishedAuthorization(ctx, store, pollInterval); err != nil && ctx.Err() == nil {
			logger.WarnContext(ctx, "не подтверждена головная редакция модели", slog.Any("error", err))
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func refreshPublishedAuthorization(ctx context.Context, store *authzsnapshot.Store, timeout time.Duration) error {
	refreshCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := store.Refresh(refreshCtx); err != nil {
		return err
	}
	return refreshCtx.Err()
}
