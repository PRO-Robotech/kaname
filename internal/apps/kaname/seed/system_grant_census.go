// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package seed

// system_grant_census.go — ПЕРЕПИСЬ ВСТРОЕННОГО ДОСТУПА ПРИ СТАРТЕ.
//
// # Предмет
//
// Встроенный доступ платформы (права служебных учёток, публичное чтение
// глобального справочника) выражен СИСТЕМНЫМИ ВЫДАЧАМИ. Пока их не было,
// «выдано в обход» и «ничего не выдано» выглядели одинаково — ровно из-за этого
// задача и заведена.
//
// Обратная сторона того же свойства появляется вместе с выдачами: их можно
// ОТОЗВАТЬ, и это штатная операция. Отзыв последней системной выдачи публичного
// чтения закрывает справочник для всех арендаторов сразу, и со стороны это
// выглядит как «продукт сломался», а не как «администратор так решил».
//
// Перепись при старте делает состояние ЗАМЕТНЫМ: сколько системных выдач
// действует и сколько оснований доступа они держат. Ноль — не отказ старта
// (администратор вправе закрыть публичность), но и не рутина: он говорится
// предупреждением, потому что «ноль системных выдач» обязано быть отличимо от
// «никто не смотрел».
//
// # Чем это НЕ является
//
// Не гейтом. Гейт свежей базы («оснований доступа помимо поверхности выдач —
// ноль») живёт пробой рядом с миграциями и роняет прогон; здесь — наблюдаемость
// живого стенда, у которой другой предмет: что администратор сделал с выдачами
// ПОСЛЕ развёртывания.

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
)

// SystemGrantCensus — что перепись увидела.
type SystemGrantCensus struct {
	// Active — действующих системных выдач.
	Active int
	// Revoked — отозванных: отличать «их никогда не заводили» от «их сняли»
	// обязательно, иначе обе картины читаются как одна.
	Revoked int
	// AuthenticatedClass — из действующих: выданных системному классу
	// `authenticated` («любой вошедший»). Публичное чтение справочника держится
	// ими. Прежде поле считало подстановку `user:*` и после переезда на классы
	// показывало бы ноль при исправном доступе (kaname#829, разбор CE-09).
	AuthenticatedClass int
	// ClusterAnchored — из действующих: с якорем на кластере.
	ClusterAnchored int
}

// CensusOfSystemGrants читает перепись одним запросом.
func CensusOfSystemGrants(ctx context.Context, pool *pgxpool.Pool) (SystemGrantCensus, error) {
	var c SystemGrantCensus
	err := pool.QueryRow(ctx, `
		SELECT
		  count(*) FILTER (WHERE status = 'ACTIVE' AND revoked_at IS NULL),
		  count(*) FILTER (WHERE status = 'REVOKED' OR revoked_at IS NOT NULL),
		  count(*) FILTER (WHERE status = 'ACTIVE' AND revoked_at IS NULL
		                     AND subject_type = 'system_class' AND subject_id = 'authenticated'),
		  count(*) FILTER (WHERE status = 'ACTIVE' AND revoked_at IS NULL
		                     AND resource_type = 'cluster')
		  FROM kaname.access_bindings
		 WHERE is_system`).
		Scan(&c.Active, &c.Revoked, &c.AuthenticatedClass, &c.ClusterAnchored)
	if err != nil {
		return SystemGrantCensus{}, fmt.Errorf("seed: перепись системных выдач: %w", err)
	}
	return c, nil
}

// LogSystemGrantCensus печатает перепись при старте.
//
// Отдельной функцией, а не строкой в композиционном корне: решение «ноль — это
// предупреждение, а не рутина» принадлежит предмету, а не месту вызова, и
// повторять его во втором вызывающем значило бы завести два места об одном.
func LogSystemGrantCensus(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger) {
	if logger == nil || pool == nil {
		return
	}
	c, err := CensusOfSystemGrants(ctx, pool)
	if err != nil {
		// Не фатально: перепись — наблюдаемость, а не предусловие работы. Но и не
		// молча: непрочитанная перепись обязана быть отличима от прочитанной с
		// нулём.
		logger.Warn("перепись системных выдач не прочитана — состояние встроенного доступа неизвестно",
			slog.Any("err", err))
		return
	}
	attrs := []any{
		slog.Int("active", c.Active),
		slog.Int("revoked", c.Revoked),
		slog.Int("authenticated_class", c.AuthenticatedClass),
		slog.Int("cluster_anchored", c.ClusterAnchored),
	}
	if c.Active == 0 {
		logger.Warn("системных выдач НЕТ: встроенный доступ платформы не выдан ни одной строкой. "+
			"Если это не решение администратора — служебные учётки и публичное чтение "+
			"глобального справочника закрыты", attrs...)
		return
	}
	if c.AuthenticatedClass == 0 {
		logger.Warn("системной выдачи классу «вошедшие» НЕТ: публичное чтение глобального "+
			"справочника закрыто каждому вошедшему. Если это не решение администратора — "+
			"встроенная выдача снята или не переехала на системный класс", attrs...)
		return
	}
	logger.Info("перепись системных выдач (встроенный доступ платформы)", attrs...)
}
