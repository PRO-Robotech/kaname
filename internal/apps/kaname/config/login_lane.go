// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

// login_lane.go — НАСТРОЙКА полосы входа паролем (фаза Ф3, задача
// PRO-Robotech/kacho#1269; решения Р3, Р10, Р11, Р13; сценарии Ф3-06, Ф3-28,
// Ф3-33, Ф3-41, Ф3-42, Ф3-44) и восстановления доступа на той же полосе (фаза
// Ф5, задача PRO-Robotech/kacho#1271; Р1, сценарий Ф5-06).
//
// # Ни одна величина не подставляется молча (Ф1 §7 инв. 4)
//
// Срок сессии, домен печенья, четыре величины частоты, длина пароля, состояние
// и адрес проверки утечек, ручка «что писать», ёмкость и резерв, срок кода
// восстановления — всё объявляет профиль; незаданное — отказ старта с именем
// ручки. Дословный перенос Ф1 §4.1 (24 ч, 8 знаков, 5 минут) живёт в ПРОФИЛЯХ
// чартов, а не здесь: величина в построении невидима читающему и не отказывает
// никогда.
//
// Требования предъявляются ПОСАДКЕ `own` строками таблицы полос: под
// `external` вход человека проверяет поставщик, и полосы у нас нет.
//
// # Домен печенья: имя ИЛИ слово «нет», пропуск — отказ
//
// На адресной посадке ключ `Domain` не печатается вовсе (`kacho#1222`); это
// объявляется словом `none`, а не пропуском, — иначе забытая строка профиля
// молча давала бы host-only печенье на посадке с именем.

import (
	"fmt"
	"strings"
	"time"

	"go.uber.org/multierr"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
)

// LoginLaneConfig — ручки полосы; все под `authn.login.*`.
type LoginLaneConfig struct {
	SessionTTL   time.Duration `mapstructure:"session-ttl"`
	CookieDomain string        `mapstructure:"cookie-domain"`

	AddressAttempts int           `mapstructure:"address-attempts"`
	AddressWindow   time.Duration `mapstructure:"address-window"`
	SourceAttempts  int           `mapstructure:"source-attempts"`
	SourceWindow    time.Duration `mapstructure:"source-window"`

	PasswordMinLength int    `mapstructure:"password-min-length"`
	BreachCheck       string `mapstructure:"breach-check"`
	BreachCheckURL    string `mapstructure:"breach-check-url"`

	HasherFormat      string `mapstructure:"hasher-format"`
	HasherMemory      uint32 `mapstructure:"hasher-memory"`
	HasherIterations  uint32 `mapstructure:"hasher-iterations"`
	HasherParallelism uint32 `mapstructure:"hasher-parallelism"`

	VerifierCapacity   int    `mapstructure:"verifier-capacity"`
	MemoryReserveBytes uint64 `mapstructure:"memory-reserve-bytes"`

	// RecoveryCodeTTL — срок кода восстановления доступа (Ф5 Р1; перенос Ф1
	// §4.1 — 5 минут — объявляется профилем).
	RecoveryCodeTTL time.Duration `mapstructure:"recovery-code-ttl"`

	// Подтверждение адреса (kaname#456, Р7, Р9; Ф6 Р16) — пять ручек, у каждой
	// нет умолчания. Величины профиля продукта — 30m · 5 · 60s · 5 · 24h.
	//
	// VerificationCodeTTL — срок кода подтверждения; своя величина, не равная
	// сроку кода восстановления (Ф6 Р16).
	VerificationCodeTTL time.Duration `mapstructure:"verification-code-ttl"`
	// VerificationCodeAttempts — предел неподошедших предъявлений на код: столько
	// тратит код, и дальше он не подходит и верным значением.
	VerificationCodeAttempts int `mapstructure:"verification-code-attempts"`
	// VerificationResendInterval — наименьший промежуток между двумя письмами
	// одного человека.
	VerificationResendInterval time.Duration `mapstructure:"verification-resend-interval"`
	// VerificationResendLimit — писем одному человеку за скользящее окно; письмо
	// регистрации в счёт.
	VerificationResendLimit int `mapstructure:"verification-resend-limit"`
	// VerificationResendWindow — скользящее окно числа писем.
	VerificationResendWindow time.Duration `mapstructure:"verification-resend-window"`
}

// loginLaneKnob — пара «ключ настройки ↔ переменная среды» одной ручки полосы.
type loginLaneKnob struct {
	Key string
	Env string
}

const loginLaneKeyPrefix = "authn.login."

// LoginLaneKnobs — перечень ручек полосы одним объявлением. Читается `Load`
// (привязка окружения) и стражами (имя в отказе).
var LoginLaneKnobs = []loginLaneKnob{
	{loginLaneKeyPrefix + "session-ttl", "KANAME_AUTHN__LOGIN__SESSION_TTL"},
	{loginLaneKeyPrefix + "cookie-domain", "KANAME_AUTHN__LOGIN__COOKIE_DOMAIN"},
	{loginLaneKeyPrefix + "address-attempts", "KANAME_AUTHN__LOGIN__ADDRESS_ATTEMPTS"},
	{loginLaneKeyPrefix + "address-window", "KANAME_AUTHN__LOGIN__ADDRESS_WINDOW"},
	{loginLaneKeyPrefix + "source-attempts", "KANAME_AUTHN__LOGIN__SOURCE_ATTEMPTS"},
	{loginLaneKeyPrefix + "source-window", "KANAME_AUTHN__LOGIN__SOURCE_WINDOW"},
	{loginLaneKeyPrefix + "password-min-length", "KANAME_AUTHN__LOGIN__PASSWORD_MIN_LENGTH"},
	{loginLaneKeyPrefix + "breach-check", "KANAME_AUTHN__LOGIN__BREACH_CHECK"},
	{loginLaneKeyPrefix + "breach-check-url", "KANAME_AUTHN__LOGIN__BREACH_CHECK_URL"},
	{loginLaneKeyPrefix + "hasher-format", "KANAME_AUTHN__LOGIN__HASHER_FORMAT"},
	{loginLaneKeyPrefix + "hasher-memory", "KANAME_AUTHN__LOGIN__HASHER_MEMORY"},
	{loginLaneKeyPrefix + "hasher-iterations", "KANAME_AUTHN__LOGIN__HASHER_ITERATIONS"},
	{loginLaneKeyPrefix + "hasher-parallelism", "KANAME_AUTHN__LOGIN__HASHER_PARALLELISM"},
	{loginLaneKeyPrefix + "verifier-capacity", "KANAME_AUTHN__LOGIN__VERIFIER_CAPACITY"},
	{loginLaneKeyPrefix + "memory-reserve-bytes", "KANAME_AUTHN__LOGIN__MEMORY_RESERVE_BYTES"},
	{loginLaneKeyPrefix + "recovery-code-ttl", "KANAME_AUTHN__LOGIN__RECOVERY_CODE_TTL"},
	{loginLaneKeyPrefix + "verification-code-ttl", "KANAME_AUTHN__LOGIN__VERIFICATION_CODE_TTL"},
	{loginLaneKeyPrefix + "verification-code-attempts", "KANAME_AUTHN__LOGIN__VERIFICATION_CODE_ATTEMPTS"},
	{loginLaneKeyPrefix + "verification-resend-interval", "KANAME_AUTHN__LOGIN__VERIFICATION_RESEND_INTERVAL"},
	{loginLaneKeyPrefix + "verification-resend-limit", "KANAME_AUTHN__LOGIN__VERIFICATION_RESEND_LIMIT"},
	{loginLaneKeyPrefix + "verification-resend-window", "KANAME_AUTHN__LOGIN__VERIFICATION_RESEND_WINDOW"},
}

func loginLaneEnv(key string) string {
	for _, k := range LoginLaneKnobs {
		if k.Key == key {
			return k.Env
		}
	}
	return ""
}

func loginLaneMissing(key, why string) error {
	return fmt.Errorf("%s не задан (%s): %s", key, loginLaneEnv(key), why)
}

// Состояния проверки по базе утечек (Ф1 Р2, Ф3-33): включена · выключена
// СЛОВОМ · не объявлена — отказ.
const (
	BreachCheckEnabled  = "enabled"
	BreachCheckDisabled = "disabled"
	// CookieDomainNone — слово, которым адресная посадка объявляет, что ключа
	// `Domain` у печенья нет.
	CookieDomainNone = "none"
)

// ValidateSessionAndCookie — срок и домен печенья (Ф3-06, Ф3-07).
func (l LoginLaneConfig) ValidateSessionAndCookie() error {
	var errs error
	if l.SessionTTL <= 0 {
		errs = multierr.Append(errs, loginLaneMissing(loginLaneKeyPrefix+"session-ttl",
			"срок сессии — величина посадки без умолчания в коде; перенос Ф1 (24h) объявляется профилем"))
	}
	switch strings.TrimSpace(l.CookieDomain) {
	case "":
		errs = multierr.Append(errs, loginLaneMissing(loginLaneKeyPrefix+"cookie-domain",
			"домен печенья — имя origin консоли либо слово «"+CookieDomainNone+"» на адресной посадке; "+
				"пропуск и «нет» обязаны различаться"))
	case CookieDomainNone:
	default:
		if strings.ContainsAny(l.CookieDomain, " /:") {
			errs = multierr.Append(errs, fmt.Errorf("%s = %q (%s): не доменное имя",
				loginLaneKeyPrefix+"cookie-domain", l.CookieDomain, loginLaneEnv(loginLaneKeyPrefix+"cookie-domain")))
		}
	}
	return errs
}

// ResolvedCookieDomain — значение для `Set-Cookie`: пусто на адресной посадке.
func (l LoginLaneConfig) ResolvedCookieDomain() string {
	d := strings.TrimSpace(l.CookieDomain)
	if d == CookieDomainNone {
		return ""
	}
	return d
}

// ValidateRateLimits — четыре величины частоты (Ф3-28).
func (l LoginLaneConfig) ValidateRateLimits() error {
	var errs error
	for _, k := range []struct {
		key string
		ok  bool
	}{
		{loginLaneKeyPrefix + "address-attempts", l.AddressAttempts > 0},
		{loginLaneKeyPrefix + "address-window", l.AddressWindow > 0},
		{loginLaneKeyPrefix + "source-attempts", l.SourceAttempts > 0},
		{loginLaneKeyPrefix + "source-window", l.SourceWindow > 0},
	} {
		if !k.ok {
			errs = multierr.Append(errs, loginLaneMissing(k.key,
				"предел неверных предъявлений — положительное число и окно; без него полоса открыта перебору"))
		}
	}
	return errs
}

// ValidatePasswordPolicy — длина, состояние и адрес проверки утечек (Ф3-33).
func (l LoginLaneConfig) ValidatePasswordPolicy() error {
	var errs error
	if l.PasswordMinLength <= 0 {
		errs = multierr.Append(errs, loginLaneMissing(loginLaneKeyPrefix+"password-min-length",
			"минимальная длина пароля — величина профиля; перенос Ф1 (8) объявляется профилем"))
	}
	switch strings.TrimSpace(l.BreachCheck) {
	case BreachCheckEnabled:
		if strings.TrimSpace(l.BreachCheckURL) == "" {
			errs = multierr.Append(errs, loginLaneMissing(loginLaneKeyPrefix+"breach-check-url",
				"проверка по базе утечек включена, а адрес авторитета не задан — адрес не выводится из чужого"))
		}
	case BreachCheckDisabled:
	case "":
		errs = multierr.Append(errs, loginLaneMissing(loginLaneKeyPrefix+"breach-check",
			"состояние проверки по базе утечек объявляется словом: «"+BreachCheckEnabled+"» с адресом либо «"+
				BreachCheckDisabled+"»; необъявленное — отказ (Ф1-37)"))
	default:
		errs = multierr.Append(errs, fmt.Errorf("%s = %q (%s): ожидается «%s» либо «%s»",
			loginLaneKeyPrefix+"breach-check", l.BreachCheck, loginLaneEnv(loginLaneKeyPrefix+"breach-check"),
			BreachCheckEnabled, BreachCheckDisabled))
	}
	return errs
}

// BreachCheckOn — включена ли проверка по базе утечек.
func (l LoginLaneConfig) BreachCheckOn() bool {
	return strings.TrimSpace(l.BreachCheck) == BreachCheckEnabled
}

// Declared — ручка «что писать» (ID-PW-1 PWV-16) в форме объявления хешера.
func (l LoginLaneConfig) Declared() passwordverify.Declared {
	format := domain.PasswordHashFormat(strings.TrimSpace(l.HasherFormat))
	params := map[domain.PasswordHashCostParam]uint32{}
	switch format {
	case domain.PasswordHashFormatArgon2id:
		if l.HasherMemory > 0 {
			params[domain.CostParamArgon2Memory] = l.HasherMemory
		}
		if l.HasherIterations > 0 {
			params[domain.CostParamArgon2Iterations] = l.HasherIterations
		}
		if l.HasherParallelism > 0 {
			params[domain.CostParamArgon2Parallelism] = l.HasherParallelism
		}
	case domain.PasswordHashFormatBcrypt:
		if l.HasherIterations > 0 {
			params[domain.CostParamBcryptCost] = l.HasherIterations
		}
	}
	return passwordverify.Declared{Format: format, Params: params}
}

// ValidateHasher — ручка «что писать» и её страж (Ф3-41): формат из перечня,
// записываемый, параметры между полом и потолком; незаданное — отказ, и каждая
// незаданная величина названа своей ручкой.
func (l LoginLaneConfig) ValidateHasher() error {
	var errs error
	format := strings.TrimSpace(l.HasherFormat)
	if format == "" {
		errs = multierr.Append(errs, loginLaneMissing(loginLaneKeyPrefix+"hasher-format",
			"формат вновь заводимых значений пароля объявляет профиль (перечень: "+
				strings.Join(domain.PasswordHashFormatMarkers(), ", ")+")"))
	}
	// Параметры стоимости — по ручке на каждый; отсутствие называется своей
	// ручкой, а не общим отказом объявления.
	if format == "" || format == string(domain.PasswordHashFormatArgon2id) {
		for _, p := range []struct {
			short string
			set   bool
			why   string
		}{
			{"hasher-memory", l.HasherMemory > 0, "память argon2id, КиБ — между полом и потолком перечня"},
			{"hasher-iterations", l.HasherIterations > 0, "проходы argon2id — между полом и потолком перечня"},
			{"hasher-parallelism", l.HasherParallelism > 0, "параллелизм argon2id — между полом и потолком перечня"},
		} {
			if !p.set {
				errs = multierr.Append(errs, loginLaneMissing(loginLaneKeyPrefix+p.short, p.why))
			}
		}
	}
	if errs != nil {
		return errs
	}
	if err := l.Declared().Validate(); err != nil {
		return fmt.Errorf("%s (%s): %w", loginLaneKeyPrefix+"hasher-*", loginLaneEnv(loginLaneKeyPrefix+"hasher-format"), err)
	}
	return nil
}

// ValidateCapacity — ёмкость и резерв заданы и положительны (Ф3-42 в).
func (l LoginLaneConfig) ValidateCapacity() error {
	var errs error
	if l.VerifierCapacity <= 0 {
		errs = multierr.Append(errs, loginLaneMissing(loginLaneKeyPrefix+"verifier-capacity",
			"ёмкость проверяющего — положительное число одновременных проверок (ID-PW-1 PWV-15)"))
	}
	if l.MemoryReserveBytes == 0 {
		errs = multierr.Append(errs, loginLaneMissing(loginLaneKeyPrefix+"memory-reserve-bytes",
			"резерв памяти процесса сверх проверок — положительное число байт (ID-PW-1 PWV-15.7)"))
	}
	return errs
}

// MemoryPerVerificationAtCeilingBytes — память ОДНОЙ проверки на потолке
// записи по самому дорогому формату перечня: проверяющий читает любой формат,
// и бюджет считается по худшему.
func MemoryPerVerificationAtCeilingBytes() uint64 {
	var worst uint64
	for _, r := range domain.PasswordHashFormats() {
		if m := r.MemoryPerVerificationAtCeilingBytes(); m > worst {
			worst = m
		}
	}
	return worst
}

// ValidateMemoryBudget — арифметика стража (Ф3-42): ёмкость × память на
// потолке + резерв ≤ предел среды; предел средой не наложен — отказ.
// Предел приносит композиционный корень (порт стража — чтение cgroup).
func (l LoginLaneConfig) ValidateMemoryBudget(limitBytes uint64, limited bool) error {
	if err := l.ValidateCapacity(); err != nil {
		return err
	}
	perCheck := MemoryPerVerificationAtCeilingBytes()
	// Ёмкость уже проверена положительной (`ValidateCapacity`), поэтому
	// преобразование знака не теряет: отрицательное сюда не доходит.
	need := uint64(l.VerifierCapacity)*perCheck + l.MemoryReserveBytes // #nosec G115 -- см. строку выше
	if !limited {
		return fmt.Errorf("%s: предел памяти средой не наложен — ёмкость %d × %d байт на проверку + резерв %d = %d байт "+
			"сверять не с чем; задайте предел памяти контейнеру (ID-PW-1 PWV-15.8)",
			loginLaneKeyPrefix+"verifier-capacity", l.VerifierCapacity, perCheck, l.MemoryReserveBytes, need)
	}
	if need > limitBytes {
		return fmt.Errorf("%s = %d (%s): ёмкость %d × %d байт на проверку + резерв %d = %d байт превышает предел среды %d байт — "+
			"под нагрузкой процесс выйдет за предел; уменьшите ёмкость либо поднимите предел (ID-PW-1 PWV-15.7)",
			loginLaneKeyPrefix+"verifier-capacity", l.VerifierCapacity, loginLaneEnv(loginLaneKeyPrefix+"verifier-capacity"),
			l.VerifierCapacity, perCheck, l.MemoryReserveBytes, need, limitBytes)
	}
	return nil
}

// ValidateRecovery — срок кода восстановления (Ф5-06): незаданный — отказ с
// именем ручки; положительный близнец Ф5-07 — объявленный срок поднимает
// процесс.
func (l LoginLaneConfig) ValidateRecovery() error {
	if l.RecoveryCodeTTL <= 0 {
		return loginLaneMissing(loginLaneKeyPrefix+"recovery-code-ttl",
			"срок кода восстановления — величина посадки без умолчания в коде; перенос Ф1 §4.1 (5m) объявляется профилем")
	}
	return nil
}

// Границы величин подтверждения адреса (kaname#456, условие аудита
// поверхности): величина за границей — отказ старта с именем ключа. Без границ
// профиль мог бы молча выключить защиту от подбора кода (миллион попыток,
// бессрочный код, письма без промежутка) — а ручки, выключающей рубеж, у
// полосы нет. Граница — не умолчание: величину называет профиль, граница
// только отвергает выключающую.
const (
	// VerificationCodeAttemptsCeiling — предел попыток на код не выше.
	VerificationCodeAttemptsCeiling = 10
	// VerificationCodeTTLCeiling — срок кода не дольше.
	VerificationCodeTTLCeiling = 24 * time.Hour
	// VerificationResendIntervalFloor — промежуток между письмами не короче.
	VerificationResendIntervalFloor = 30 * time.Second
	// VerificationResendLimitCeiling — писем за окно не больше.
	VerificationResendLimitCeiling = 20
)

// ValidateVerification — пять ручек подтверждения адреса (kaname#456, Р9,
// EV-90): незаданная — отказ старта с именем ключа и переменной. Промежуток
// между письмами короче окна: иначе предел числа писем за окно не исполнялся
// бы никогда, и ручка объявляла бы свойство, которого у полосы нет. Величина за
// границей — тоже отказ старта (см. границы выше).
func (l LoginLaneConfig) ValidateVerification() error {
	var errs error
	beyond := func(short string, value any, bound string) {
		key := loginLaneKeyPrefix + short
		errs = multierr.Append(errs, fmt.Errorf("%s (%s) = %v за границей %s: такая величина выключала бы защиту от подбора кода",
			key, loginLaneEnv(key), value, bound))
	}
	if l.VerificationCodeAttempts > VerificationCodeAttemptsCeiling {
		beyond("verification-code-attempts", l.VerificationCodeAttempts, fmt.Sprintf("«не больше %d»", VerificationCodeAttemptsCeiling))
	}
	if l.VerificationCodeTTL > VerificationCodeTTLCeiling {
		beyond("verification-code-ttl", l.VerificationCodeTTL, "«не дольше "+VerificationCodeTTLCeiling.String()+"»")
	}
	if l.VerificationResendInterval > 0 && l.VerificationResendInterval < VerificationResendIntervalFloor {
		beyond("verification-resend-interval", l.VerificationResendInterval, "«не короче "+VerificationResendIntervalFloor.String()+"»")
	}
	if l.VerificationResendLimit > VerificationResendLimitCeiling {
		beyond("verification-resend-limit", l.VerificationResendLimit, fmt.Sprintf("«не больше %d»", VerificationResendLimitCeiling))
	}
	if l.VerificationCodeTTL <= 0 {
		errs = multierr.Append(errs, loginLaneMissing(loginLaneKeyPrefix+"verification-code-ttl",
			"срок кода подтверждения адреса — своя величина посадки без умолчания в коде (Ф6 Р16); величина профиля продукта — 30m"))
	}
	if l.VerificationCodeAttempts <= 0 {
		errs = multierr.Append(errs, loginLaneMissing(loginLaneKeyPrefix+"verification-code-attempts",
			"предел неподошедших предъявлений на код подтверждения; величина профиля продукта — 5"))
	}
	if l.VerificationResendInterval <= 0 {
		errs = multierr.Append(errs, loginLaneMissing(loginLaneKeyPrefix+"verification-resend-interval",
			"наименьший промежуток между письмами подтверждения одному человеку; величина профиля продукта — 60s"))
	}
	if l.VerificationResendLimit <= 0 {
		errs = multierr.Append(errs, loginLaneMissing(loginLaneKeyPrefix+"verification-resend-limit",
			"писем подтверждения одному человеку за окно, письмо регистрации в счёт; величина профиля продукта — 5"))
	}
	if l.VerificationResendWindow <= 0 {
		errs = multierr.Append(errs, loginLaneMissing(loginLaneKeyPrefix+"verification-resend-window",
			"скользящее окно числа писем подтверждения; величина профиля продукта — 24h"))
	}
	if l.VerificationResendInterval > 0 && l.VerificationResendWindow > 0 && l.VerificationResendInterval >= l.VerificationResendWindow {
		errs = multierr.Append(errs, fmt.Errorf("%s (%s) = %s не короче %s (%s) = %s: предел числа писем за окно не исполнялся бы никогда",
			loginLaneKeyPrefix+"verification-resend-interval", loginLaneEnv(loginLaneKeyPrefix+"verification-resend-interval"),
			l.VerificationResendInterval, loginLaneKeyPrefix+"verification-resend-window",
			loginLaneEnv(loginLaneKeyPrefix+"verification-resend-window"), l.VerificationResendWindow))
	}
	return errs
}

// ValidateAll — все стражи настройки полосы разом (страж старта посадки `own`).
func (l LoginLaneConfig) ValidateAll() error {
	return multierr.Combine(
		l.ValidateSessionAndCookie(),
		l.ValidateRateLimits(),
		l.ValidatePasswordPolicy(),
		l.ValidateHasher(),
		l.ValidateCapacity(),
		l.ValidateRecovery(),
		l.ValidateVerification(),
	)
}
