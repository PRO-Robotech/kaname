// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// env.go — env-driven helper used by the composition root.
//
// Здесь стоял выбор поставщика решения о доступе, сборка клиента внешнего движка
// отношений, его сроки на операцию и перевод исходов его попыток в наблюдаемое.
// Ничего из этого нет: поставщик один и он не внешний — решение вычисляет
// реляционная форма в собственной базе службы, и «выбор адаптера» перестал быть
// вопросом, а не сменил умолчание.
package main

import (
	"net/url"
	"os"
	"strconv"
	"time"
)

// maskDSN отдает DSN с замаскированным паролем — для безопасного логирования
// slave-URL. Возвращает оригинальную строку, если она не парсится как URL.
func maskDSN(dsn string) string {
	if dsn == "" {
		return ""
	}
	u, err := url.Parse(dsn)
	if err != nil || u.User == nil {
		return dsn
	}
	if _, hasPwd := u.User.Password(); !hasPwd {
		return dsn
	}
	u.User = url.UserPassword(u.User.Username(), "***")
	return u.String()
}

// envDurationMS reads an integer-millisecond env var, returning def when unset
// or invalid (non-numeric / non-positive).
func envDurationMS(key string, def time.Duration) time.Duration {
	raw := os.Getenv(key)
	if raw == "" {
		return def
	}
	ms, err := strconv.Atoi(raw)
	if err != nil || ms <= 0 {
		return def
	}
	return time.Duration(ms) * time.Millisecond
}
