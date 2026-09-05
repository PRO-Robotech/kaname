// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// token_signing.go — настройка СВОЕЙ чеканки токенов и её страж старта
// (задача #897).
//
// # Почему каждая величина здесь обязательна, а не «по умолчанию»
//
// Незаданное ожидание означает «не сужаем», а не «взять разумное». Пустой
// перечень допустимых алгоритмов означает «принимаем любой»; незаданный
// издатель — «любой»; отсутствующий путь набора превращает страж записи
// источника в тождественно истинную проверку. Каждая из этих трёх величин
// невидима на положительном пути: токен выпускается, проверяется, запрос
// проходит — и защиты при этом нет.
//
// # Асимметрия цены
//
// Слишком строгая настройка даёт отказ В СТАРТЕ — видимый сразу, с именем
// настройки в тексте. Слишком слабая даёт принимаемый чужой токен, не видимый
// никогда. Поэтому на каждой развилке здесь выбрано отвергать.
package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/PRO-Robotech/kacho/pkg/tokenpolicy"
	"go.uber.org/multierr"
)

// dayDuration — сутки. Отдельная величина, чтобы срок ключа читался в тех
// единицах, в которых о нём думают.
const dayDuration = 24 * time.Hour

// defaultKeySetPath — путь НАШЕЙ записи публикуемого набора.
//
// Собственный, а не канонический well-known: по каноническому пути тот же
// слушатель отдаёт зеркало прежнего издателя, и оно остаётся там до тех пор,
// пока прежний издатель принимается. Перенос зеркала сменил бы адрес у каждого
// существующего потребителя разом — цена, которой эта фаза не предусматривала.
const defaultKeySetPath = "/.well-known/kacho/jwks.json"

// TokenSigningConfig — своя чеканка токенов.
type TokenSigningConfig struct {
	// Enabled — включена ли своя чеканка. Пока выключена, её настройки не
	// требуются: страж, требующий того, чем не пользуются, — отказ в старте
	// без предмета.
	Enabled bool `mapstructure:"enabled"`
	// Issuer — НАШ издатель. Попадает в каждый выпущенный токен и в привязку
	// «издатель → источник набора» на приёмной стороне.
	Issuer string `mapstructure:"issuer"`
	// Algorithm — алгоритм подписи, закрепляемый за порождаемым ключом.
	Algorithm string `mapstructure:"algorithm"`
	// AllowedAlgorithms — перечень допустимых алгоритмов приёма, через
	// запятую. Считаются ЭЛЕМЕНТЫ, а не длина строки.
	AllowedAlgorithms string `mapstructure:"allowed-algorithms"`
	// KeySetPath — путь нашей записи публикуемого набора. ОБЪЯВЛЯЕТСЯ, а не
	// выводится из издателя.
	KeySetPath string `mapstructure:"key-set-path"`
	// KeyLifetime — срок ключа.
	KeyLifetime time.Duration `mapstructure:"key-lifetime"`
}

// ParseCommaList читает перечень через запятую, считая ЭЛЕМЕНТЫ.
//
// Один предикат для стража и для вызывающего: два места об одном предмете
// разошлись бы ровно на вырожденном значении — одинокая запятая даёт длину 1 и
// ноль элементов, и страж, меряющий длину, объявил бы перечень непустым.
//
// Предикат общий на все перечни настройки, а не свой у каждого: семантика у них
// одна, а вторая копия разошлась бы именно там, где расхождение не видно.
func ParseCommaList(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		if v := strings.TrimSpace(part); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// ParseAlgorithmList читает перечень алгоритмов.
func ParseAlgorithmList(raw string) []string { return ParseCommaList(raw) }

// ResolveKeySetPath возвращает путь нашей записи набора.
func (c TokenSigningConfig) ResolveKeySetPath() string {
	if p := strings.TrimSpace(c.KeySetPath); p != "" {
		return p
	}
	return defaultKeySetPath
}

// ResolveKeyLifetime возвращает срок ключа.
func (c TokenSigningConfig) ResolveKeyLifetime() time.Duration {
	if c.KeyLifetime > 0 {
		return c.KeyLifetime
	}
	return 90 * dayDuration
}

// AllowedAlgorithmList возвращает перечень допустимых алгоритмов приёма.
func (c TokenSigningConfig) AllowedAlgorithmList() []string {
	return ParseAlgorithmList(c.AllowedAlgorithms)
}

// Validate — страж старта своей чеканки.
//
// Каждое сообщение называет НАСТРОЙКУ и правило, и ни одно не называет
// значения секрета: текст отказа читает оператор, а не предъявитель.
func (c TokenSigningConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	var errs error

	if strings.TrimSpace(c.Issuer) == "" {
		errs = multierr.Append(errs, fmt.Errorf(
			"authn.token-signing.issuer is empty — an unset issuer means «we do not narrow», "+
				"and every token of every origin would be accepted as ours"))
	}

	if !tokenpolicy.AlgorithmAllowed(c.Algorithm) {
		errs = multierr.Append(errs, fmt.Errorf(
			"authn.token-signing.algorithm %q is not one of %v", c.Algorithm, tokenpolicy.Algorithms()))
	}

	allowed := c.AllowedAlgorithmList()
	if len(allowed) == 0 {
		errs = multierr.Append(errs, fmt.Errorf(
			"authn.token-signing.allowed-algorithms has no elements (got %q) — an empty list means "+
				"«any algorithm», and the header-versus-key check rests on this list", c.AllowedAlgorithms))
	}
	inOwnList := false
	for _, alg := range allowed {
		if !tokenpolicy.AlgorithmAllowed(alg) {
			errs = multierr.Append(errs, fmt.Errorf(
				"authn.token-signing.allowed-algorithms names %q, which is not one of %v",
				alg, tokenpolicy.Algorithms()))
		}
		if alg == c.Algorithm {
			inOwnList = true
		}
	}
	if len(allowed) > 0 && !inOwnList {
		errs = multierr.Append(errs, fmt.Errorf(
			"authn.token-signing.algorithm %q is outside authn.token-signing.allowed-algorithms %q — "+
				"we would mint what we ourselves refuse", c.Algorithm, c.AllowedAlgorithms))
	}

	if !usableKeySetPath(c.KeySetPath) {
		errs = multierr.Append(errs, fmt.Errorf(
			"authn.token-signing.key-set-path %q declares no usable path — refusing to start rather "+
				"than resolving the key set to an address derived from the issuer", c.KeySetPath))
	}

	if c.KeyLifetime < 0 {
		errs = multierr.Append(errs, fmt.Errorf(
			"authn.token-signing.key-lifetime must not be negative (got %s)", c.KeyLifetime))
	}
	return errs
}

// usableKeySetPath отвечает, несёт ли объявленный путь хотя бы один сегмент.
//
// Считает СЕГМЕНТЫ, а не символы: «///» непусто по длине и пусто по существу.
func usableKeySetPath(path string) bool {
	if !strings.HasPrefix(path, "/") {
		return false
	}
	for _, seg := range strings.Split(path, "/") {
		if strings.TrimSpace(seg) != "" {
			return true
		}
	}
	return false
}
