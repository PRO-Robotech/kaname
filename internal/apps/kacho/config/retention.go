// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// retention.go — секция `retention`: величины фоновой уборки таблиц, чей рост
// задаёт внешний (задача #1292).
package config

import (
	"time"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/retention"
)

// RetentionConfig — величины уборки.
//
// Порогов здесь НЕТ, и это решение, а не пропуск: порог есть функция предиката
// читателя таблицы и вычисляется из `pkg/tokenpolicy` реестром уборки.
// Настраиваемый порог был бы ручкой, которой его молча разводят с предикатом
// читателя, — то есть ручкой заведения того самого дефекта, ради которого
// уборка и заводится.
type RetentionConfig struct {
	// Interval — как часто идёт проход по реестру.
	//
	// Величина НЕ определяющая: верхняя граница числа строк равна
	// «темп × (срок строки + интервал)», и при сроке до часа пять минут
	// добавляют к границе около восьми процентов. Выбрана поэтому по стоимости
	// прогона, а не по точности.
	Interval time.Duration `mapstructure:"interval"`
	// Batch — сколько строк снимает один оператор.
	Batch int `mapstructure:"batch"`
	// MaxBatchesPerPass — потолок числа партий за проход.
	MaxBatchesPerPass int `mapstructure:"max-batches-per-pass"`
}

// Sweep — величины в форме, которую принимает уборщик.
//
// Перевод, а не копия предиката: годность решает `retention.Config.Validate`, и
// зовут его обе стороны — страж старта и построитель уборщика.
func (c RetentionConfig) Sweep() retention.Config {
	return retention.Config{
		Interval:          c.Interval,
		Batch:             c.Batch,
		MaxBatchesPerPass: c.MaxBatchesPerPass,
	}
}

// Validate — страж старта секции.
//
// Действует в ЛЮБОМ режиме, а не только в производственном: уборка, собранная с
// нулевой партией, исполняется и не убирает ничего на всяком поднятом стенде, а
// «зелёный dev» именно это и маскирует.
func (c RetentionConfig) Validate() error { return c.Sweep().Validate() }
