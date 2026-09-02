// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"fmt"
	"log/slog"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/config"
	"github.com/PRO-Robotech/kacho/services/iam/internal/manifest"
)

// module_manifests.go — манифесты модулей ЧИТАЮТСЯ НА СТАРТЕ (задача #1875).
//
// # Зачем это здесь
//
// Ручка, объявленная и никем не читаемая, есть МЁРТВЫЙ СТРАЖ: служба
// поднимается, называя себя настроенной, и отделывается одним предупреждением
// (`00-kacho-core` ban #16, класс `AuthMode`). Отличать надо не «поле есть» от
// «поля нет», а «значение меняет исход старта» от «не меняет» — поэтому каталог
// доставки читается здесь, до приёма трафика, и его состояние решает, поднимется
// ли служба.
//
// # Что этот путь НЕ делает
//
// Он не применяет манифест и ничего не пишет: применение — предмет `#1034`,
// запись манифестов — `#1091`. Здесь только ЧТЕНИЕ доставленного и отказ на
// сорванной доставке.
//
// # Порядок относительно стража паритета
//
// Чтение стоит ПЕРЕД стражем паритета каталога намеренно: манифест и есть та
// опорная сторона, на которую страж переезжает (`#1861`). Сорванная доставка
// обязана называться своим именем ДО того, как о расхождении заговорит страж, —
// иначе оператор прочтёт отказ доставки как расхождение каталога и пойдёт чинить
// не то.

// loadDeliveredManifests читает каталог доставки и печатает перепись
// осмотренного — ВСЕГДА, независимо от исхода.
//
// Перепись без исхода и исход без переписи одинаково негодны: первая не говорит,
// пускать ли, второй не отличает «прочитано ноль» от «находок ноль».
func loadDeliveredManifests(logger *slog.Logger, cfg config.ManifestsConfig) error {
	if cfg.Dir == "" {
		// Молчать об этом нельзя: доставка, не объявленная посадкой, снаружи
		// неотличима от доставки, объявленной и сорванной. Страж старта уже
		// отверг бы сочетание «опираемся и не назвали каталог», поэтому сюда
		// доходит только осознанное «доставки нет».
		logger.Info("доставка манифестов модулей не объявлена посадкой",
			slog.Bool("required", cfg.Required),
			slog.String("knob", "manifests.dir"))
		return nil
	}

	report, err := manifest.LoadDelivered(cfg.Dir)
	logger.Info("перепись доставки манифестов модулей",
		slog.String("dir", cfg.Dir),
		slog.Bool("required", cfg.Required),
		slog.Int("paths_seen", report.PathsSeen),
		slog.Int("dirs_skipped", report.DirsSkipped),
		slog.Int("manifests_read", report.ManifestsRead),
		slog.Int("findings", len(report.Findings)),
		slog.Any("modules", report.Modules()))
	if err != nil {
		return fmt.Errorf("доставка манифестов модулей: %w", err)
	}
	return nil
}
