// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
)

// superviseStartupTask связывает фатальный отказ стартового досева с общей
// ручкой гашения. Обычный errgroup.Group сам не отменяет долгоживущие задачи:
// вернуть ошибку без triggerShutdown означало бы навсегда задержать Wait.
//
// Только ошибка самой прерванной работы означает штатную отмену. Поздняя
// отмена контекста не превращает уже полученный структурный отказ в успех.
func superviseStartupTask(ctx context.Context, triggerShutdown func(), run func(context.Context) error) error {
	err := run(ctx)
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) && errors.Is(ctx.Err(), context.Canceled) {
		return nil
	}
	triggerShutdown()
	return err
}
