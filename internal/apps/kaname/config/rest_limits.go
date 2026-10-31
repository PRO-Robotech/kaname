// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

// rest_limits.go — потолки размера тела и одновременности собственного
// ПУБЛИЧНОГО REST-фронта (kaname#990). Механизм и его доводы — в шапке
// `internal/restfront/limits.go`; здесь — величины посадки и их страж.
//
// # Умолчания — потолки, а не их отсутствие
//
// Молчание посадки даёт безопасные величины ниже; снятие потолка требует слов
// (значение 0) и допустимо только вне боевой посадки. Обратное умолчание —
// «не объявлено, значит без потолка» — дало бы опубликованную наружу
// поверхность без границы памяти на каждой установке, где профиль промолчал.
//
// # Почему указатель
//
// Отсутствие представимо отдельно от значения: незаданное поле берёт
// умолчание, а 0 — ОБЪЯВЛЕННОЕ снятие, которое страж судит. На простом числе
// «не задано» и «снято» неотличимы, и страж либо отвергал бы молчание, либо
// пропускал бы снятие.
//
// # Откуда числа
//
// Тело — 1 МиБ. Самое длинное тело публичного контракта на сегодня — пакетная
// проверка доступа: до ста вопросов по нескольку сотен байт, то есть десятки
// килобайт. Мебибайт оставляет запас на порядок и больше, а цена его названа
// числом ниже.
//
// Одновременность — 256 запросов на процесс: это шестнадцать вызывающих,
// каждый из которых упёрся в свой потолок допуска на слушателе (пол платформы —
// 16 одновременных на арендатора). Граница памяти тел в работе — произведение
// двух величин: 256 × 1 МиБ = 256 МиБ на процесс в худшем случае. Поднимая одну
// величину, оператор поднимает и это произведение — оно названо в тексте
// ручки, чтобы решение принималось с ним перед глазами.

import (
	"fmt"

	"go.uber.org/multierr"
)

// Умолчания потолков публичного REST-фронта. Читаются и `defaults.go` (ключи
// настройки), и [RESTLimitsConfig.Effective] (поле, не прошедшее загрузчик), —
// одно число в одном месте.
const (
	DefaultRESTMaxBodyBytes int64 = 1 << 20
	DefaultRESTMaxInFlight  int   = 256
)

// Ключи и переменные — координаты, которые называет отказ стража.
const (
	restLimitsBodyKey     = "api-server.rest-limits.max-body-bytes"
	restLimitsBodyEnv     = "KANAME_API_SERVER__REST_LIMITS__MAX_BODY_BYTES"
	restLimitsInFlightKey = "api-server.rest-limits.max-in-flight"
	restLimitsInFlightEnv = "KANAME_API_SERVER__REST_LIMITS__MAX_IN_FLIGHT"
)

// RESTLimitsConfig — потолки публичного REST-фронта в объявлении посадки.
type RESTLimitsConfig struct {
	// MaxBodyBytes — наибольший размер тела запроса, байт. Не задано —
	// [DefaultRESTMaxBodyBytes]; 0 — потолок снят (только вне боевой посадки).
	MaxBodyBytes *int64 `mapstructure:"max-body-bytes"`
	// MaxInFlight — наибольшее число запросов в работе на процесс. Не задано —
	// [DefaultRESTMaxInFlight]; 0 — потолок снят (только вне боевой посадки).
	MaxInFlight *int `mapstructure:"max-in-flight"`
}

// RESTLimits — действующие потолки: то, что уходит во фронт.
type RESTLimits struct {
	MaxBodyBytes int64
	MaxInFlight  int
}

// Effective — действующие потолки: объявленное значение либо умолчание.
func (r RESTLimitsConfig) Effective() RESTLimits {
	out := RESTLimits{MaxBodyBytes: DefaultRESTMaxBodyBytes, MaxInFlight: DefaultRESTMaxInFlight}
	if r.MaxBodyBytes != nil {
		out.MaxBodyBytes = *r.MaxBodyBytes
	}
	if r.MaxInFlight != nil {
		out.MaxInFlight = *r.MaxInFlight
	}
	return out
}

// Validate — страж потолков: отрицательное отвергается в любой посадке,
// снятие (0) — в боевой.
//
// Отказ по обеим осям сразу (multierr): оператор, узнающий перечень по одной
// ручке за перезапуск, платит перекатом за каждую.
func (r RESTLimitsConfig) Validate(production bool) error {
	eff := r.Effective()
	var errs error
	errs = multierr.Append(errs, judgeRESTCeiling(eff.MaxBodyBytes, production,
		restLimitsBodyKey, restLimitsBodyEnv,
		"тело любого размера читалось бы в память процесса целиком"))
	errs = multierr.Append(errs, judgeRESTCeiling(int64(eff.MaxInFlight), production,
		restLimitsInFlightKey, restLimitsInFlightEnv,
		"число запросов в работе ограничивали бы только соединения вызывающего"))
	return errs
}

func judgeRESTCeiling(v int64, production bool, key, env, without string) error {
	switch {
	case v < 0:
		return fmt.Errorf("%s = %d (%s): потолок публичного REST-фронта обязан быть "+
			"неотрицательным; отрицательное значение не означает «без потолка» и похоже "+
			"на опечатку; refusing to start", key, v, env)
	case v == 0 && production:
		return fmt.Errorf("%s = 0 (%s): потолок публичного REST-фронта снят в боевой "+
			"посадке — %s. Края, который держал бы потолок, у отдельно поставленной службы "+
			"нет; задайте положительное значение или уберите ручку (умолчание безопасно); "+
			"refusing to start", key, env, without)
	default:
		return nil
	}
}
