// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// retention_test.go — величины уборки объявлены и проверяются при СТАРТЕ
// (приёмка `retention-sweep-has-a-caller.md` §3.3).
//
// # Почему объявлены, а не вшиты
//
// Величина, уезжающая в SQL мимо объявления, невидима оператору: он не может ни
// прочитать её, ни изменить, а по поведению стенда отличить «партия мала» от
// «уборка не идёт» нельзя. Порогов среди них НЕТ намеренно — они вычисляются из
// `pkg/tokenpolicy`, и настраиваемый порог был бы ручкой, которой его молча
// разводят с предикатом читателя.
//
// # Почему предикат ОДИН
//
// Страж старта зовёт `retention.Config.Validate` — тот же, что зовёт
// построитель уборщика. Две проверки об одном предмете разошлись бы молча, и
// разошлись бы там, где расхождение не видно: обе отвечают «годно» на годном.
package config_test

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// TestRetentionDefaultsAreDeclared — умолчания величин уборки объявлены.
func TestRetentionDefaultsAreDeclared(t *testing.T) {
	cfg, err := config.Load("")
	require.NoError(t, err)

	require.Equal(t, 5*time.Minute, cfg.Retention.Interval)
	require.Equal(t, 1000, cfg.Retention.Batch)
	require.Positive(t, cfg.Retention.MaxBatchesPerPass,
		"потолок партий за проход обязан быть положительным: ноль означал бы петлю, "+
			"которая исполняется и не убирает ничего")
	require.NoError(t, cfg.Retention.Validate(), "объявленные умолчания обязаны проходить своего же стража")
}

// TestDocumentedEnvName_RetentionBatch — ручка партии действительно ручка.
//
// Значение не-дефолтное намеренно: совпадение с умолчанием сделало бы
// утверждение тождественно истинным.
func TestDocumentedEnvName_RetentionBatch(t *testing.T) {
	t.Setenv("KANAME_RETENTION__BATCH", "137")

	cfg, err := config.Load("")
	require.NoError(t, err)
	require.Equal(t, 137, cfg.Retention.Batch)
}

// TestFlatEnvName_RetentionBatch_IsNotAKnob — положительный контроль отрицания:
// плоская форма имени ручкой НЕ является, и значение выразимо ровно одним
// способом.
func TestFlatEnvName_RetentionBatch_IsNotAKnob(t *testing.T) {
	t.Setenv("KANAME_RETENTION_BATCH", "138")

	cfg, err := config.Load("")
	require.NoError(t, err)
	require.Equal(t, 1000, cfg.Retention.Batch)
}

// TestRetentionBootGuardRefusesUnworkableValues — страж старта отказывает на
// величинах, при которых уборка исполняется и не убирает ничего.
//
// Обе стороны обязательны: без положительного контроля проба зеленела бы на
// страже, отвергающем ВСЁ.
func TestRetentionBootGuardRefusesUnworkableValues(t *testing.T) {
	base, err := config.Load("")
	require.NoError(t, err)

	// Положительный контроль сужен до СВОЕЙ секции намеренно: страж целой
	// конфигурации отвергает умолчания по другим причинам (незаданный адресат
	// докерной полосы, посадка производственного режима), и требовать от него
	// «без отказов» значило бы утверждать не о том. Здесь утверждается ровно
	// то, что нужно: на годных величинах уборки страж о ней МОЛЧИТ. Без этой
	// половины проба зеленела бы на страже, отвергающем всё.
	t.Run("годные величины страж не поминает", func(t *testing.T) {
		require.NoError(t, base.Retention.Validate())
		if err := base.Validate(); err != nil {
			require.NotContains(t, err.Error(), "retention.",
				"страж поминает секцию уборки при годных величинах")
		}
	})

	for _, tc := range []struct {
		name  string
		mut   func(*config.RetentionConfig)
		names string
	}{
		{"нулевой интервал", func(r *config.RetentionConfig) { r.Interval = 0 }, "retention.interval"},
		{"нулевая партия", func(r *config.RetentionConfig) { r.Batch = 0 }, "retention.batch"},
		{"партия сверх потолка", func(r *config.RetentionConfig) { r.Batch = 10_000_000 }, "retention.batch"},
		{"нулевой потолок партий", func(r *config.RetentionConfig) { r.MaxBatchesPerPass = 0 }, "retention.max-batches-per-pass"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := base
			tc.mut(&bad.Retention)
			err := bad.Validate()
			require.Error(t, err, "негодная величина уборки принята стражем старта")
			require.True(t, strings.Contains(err.Error(), tc.names),
				"отказ обязан называть РУЧКУ, иначе оператору нечего чинить; получено: %s", err.Error())
		})
	}
}
