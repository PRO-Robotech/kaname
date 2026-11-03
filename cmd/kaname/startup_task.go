// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import "context"

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
	if ctx.Err() == context.Canceled && onlyStartupCancellation(err) {
		return nil
	}
	triggerShutdown()
	return err
}

// onlyStartupCancellation принимает только дерево, у которого каждый лист —
// context.Canceled. errors.Is отвечает лишь о наличии одной причины и потому
// не отличает штатную отмену от её объединения с настоящим отказом.
func onlyStartupCancellation(err error) bool {
	if err == context.Canceled {
		return true
	}
	switch wrapped := err.(type) {
	case interface{ Unwrap() []error }:
		causes := wrapped.Unwrap()
		seen := false
		for _, cause := range causes {
			if cause == nil {
				continue
			}
			if !onlyStartupCancellation(cause) {
				return false
			}
			seen = true
		}
		return seen
	case interface{ Unwrap() error }:
		return onlyStartupCancellation(wrapped.Unwrap())
	default:
		return false
	}
}
