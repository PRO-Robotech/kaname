// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

// mail_bounds.go — ТАБЛИЦА ГРАНИЦ почтовых ручек kaname (приёмка NTF-2 Р8,
// NTF2-50, NTF2-71; замысел NTF-2 З2, З5, З18, З23, З26).
//
// ─────────────────────────────────────────────────────────────────────────────
// ОДНА ТАБЛИЦА — ЧЕТЫРЕ ЧИТАТЕЛЯ
//
// Строка таблицы — единственное место, где ручка объявлена. Её читают:
//
//	Load              — привязка ключа к окружению (`BindEnv`): у ручки нет
//	                    умолчания, и без привязки переменная не доехала бы до
//	                    поля вовсе;
//	страж старта      — ValidateMailBounds: наличие, границы, порядок;
//	перечень величин  — RequiredSettings и порождённый из него документ
//	                    установки;
//	срок хранения     — MailRetention (З26): верхняя граница окна, а не
//	                    настроенное значение.
//
// Второго перечня нет: ключ, внесённый в таблицу, получает и привязку, и
// суждение стража, и строку документа, и вход срока хранения.
//
// ─────────────────────────────────────────────────────────────────────────────
// ВИДЫ СТРОК
//
//	счёт          целое; границы включительны; окно счёта задано ИМЕНЕМ ручки
//	              («в час», «в сутки») либо соседней ручкой окна;
//	длительность  срок или окно; границы включительны;
//	объявление    обязательна, без границ: флаг почты и пути файлов ключей.
//
// Строк вида «счёт» и «длительность» — 32, ровно ключи kaname таблицы Р8
// приёмки (окна адресата 15, сроки кода 3, перебор 3, письмо о торможении 1,
// приглашения 8, доверенное устройство 2). Строк «объявление» — 3.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕГО ТАБЛИЦА НЕ СУДИТ
//
// Верхнюю границу `invite.recipient-per-day-all ≤ 50`: это лимит шаблона
// `invite`, и страж обязан читать её из сгенерированного описания шаблона, а
// не держать вторым местом о том же числе (Р8; NTF2-71 (щ)). Описания шаблонов
// в дереве ещё нет — его заводит полоса шаблонов (F4), и граница входит в
// стража вместе с ним. До того строка судится нижней границей и порядком
// `recipient-per-day ≤ recipient-per-day-all`.

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	"go.uber.org/multierr"
)

// MailBoundKind — вид строки таблицы границ.
type MailBoundKind int

const (
	// MailBoundCount — целое с включительными границами.
	MailBoundCount MailBoundKind = iota
	// MailBoundDuration — длительность с включительными границами.
	MailBoundDuration
	// MailBoundDeclared — обязательна, границ нет.
	MailBoundDeclared
)

// String — имя вида для текстов отказа и переписи.
func (k MailBoundKind) String() string {
	switch k {
	case MailBoundCount:
		return "счёт"
	case MailBoundDuration:
		return "длительность"
	case MailBoundDeclared:
		return "объявление"
	default:
		return "неизвестный вид"
	}
}

// day — сутки; в таблице Р8 сроки названы сутками.
const day = 24 * time.Hour

// MailBound — одна ручка таблицы.
type MailBound struct {
	// Key — путь ключа целиком; его называет отказ.
	Key string
	// Kind — вид строки.
	Kind MailBoundKind
	// Min — нижняя граница включительно: число у счёта, наносекунды у
	// длительности.
	Min int64
	// Max — верхняя граница включительно; HasMax == false — сверху не
	// ограничена таблицей Р8.
	Max    int64
	HasMax bool
	// Window — окно счёта, заданное ИМЕНЕМ ручки («в час» — 1 ч, «в сутки» —
	// 24 ч). Ноль — у счёта окно задаёт соседняя ручка либо окна нет.
	Window time.Duration
	// Sample — величина базового профиля (ориентир Р8): ею строка подаётся в
	// пробе полноты перечня и печатается примером в документе установки.
	Sample string
	// Why — что ручка задаёт, словами оператора.
	Why string
}

// MailBoundOrder — порядок двух ручек: Lesser ≤ Greater.
type MailBoundOrder struct {
	Lesser, Greater string
}

// mailWindowPurposes — назначения окна адресата (Р8).
var mailWindowPurposes = []string{"recovery", "verification", "registration"}

const (
	mailWindowPrefix = loginLaneKeyPrefix + "mail-window."
	invitePrefix     = "invite."
)

func countBound(key string, lo, hi int64, hasMax bool, window time.Duration, sample, why string) MailBound {
	return MailBound{Key: key, Kind: MailBoundCount, Min: lo, Max: hi, HasMax: hasMax, Window: window, Sample: sample, Why: why}
}

func durationBound(key string, lo, hi time.Duration, sample, why string) MailBound {
	return MailBound{Key: key, Kind: MailBoundDuration, Min: int64(lo), Max: int64(hi), HasMax: true, Sample: sample, Why: why}
}

func declared(key, sample, why string) MailBound {
	return MailBound{Key: key, Kind: MailBoundDeclared, Sample: sample, Why: why}
}

// NotificationsEnabledKey — ключ флага почты (З2, NTF2-50).
const NotificationsEnabledKey = "notifications.enabled"

// MailBounds — таблица границ. Порядок строк — порядок документа установки.
var MailBounds = func() []MailBound {
	var out []MailBound
	out = append(out,
		declared(NotificationsEnabledKey, "true",
			"включена ли почта службы: `true` либо `false`; `false` законно — действия, которым нужна почта, "+
				"получают явный отказ, прочие исполняются"),
		declared("authn.secrets.mail-window-key-file", "/etc/kaname/secrets/mail-window.key",
			"путь к файлу ключа k_window (свёртка ключа окна адресата и адресов ожидающих регистраций), не короче 32 байт; "+
				"смена ключа начинает окна адресатов и ожидающие регистрации заново"),
		declared("authn.secrets.device-label-key-file", "/etc/kaname/secrets/device-label.key",
			"путь к файлу ключа k_device (подпись метки доверенного устройства), не короче 32 байт; "+
				"смена ключа делает недействительными все метки"),
	)
	for _, p := range mailWindowPurposes {
		k := mailWindowPrefix + p + "."
		out = append(out,
			durationBound(k+"first-pause", 30*time.Second, time.Hour, "60s",
				"пауза перед вторым письмом назначения `"+p+"` одному адресату"),
			durationBound(k+"second-pause", 30*time.Second, time.Hour, "5m",
				"пауза перед третьим и следующими письмами назначения `"+p+"`"),
			countBound(k+"per-hour", 1, 20, true, time.Hour, "3",
				"писем назначения `"+p+"` одному адресату в час"),
			countBound(k+"per-day", 1, 20, true, day, "5",
				"писем назначения `"+p+"` одному адресату в сутки"),
			durationBound(k+"floor-interval", time.Hour, day, "6h",
				"пол: одно письмо назначения `"+p+"` за этот промежуток проходит сверх потолков"),
		)
	}
	out = append(out,
		durationBound(loginLaneKeyPrefix+"recovery-code-ttl", 5*time.Minute, day, "15m",
			"срок кода восстановления доступа; не короче первой паузы окна `recovery`"),
		durationBound(loginLaneKeyPrefix+"verification-code-ttl", 5*time.Minute, day, "60m",
			"срок кода подтверждения адреса; не короче первой паузы окна `verification`"),
		durationBound(loginLaneKeyPrefix+"registration-code-ttl", 5*time.Minute, day, "60m",
			"срок кода регистрации; не короче первой паузы окна `registration`"),
		countBound(loginLaneKeyPrefix+"attempts.address-source-per-window", 1, 0, false, 0, "5",
			"неверных предъявлений кода с пары (адрес, источник) за окно перебора"),
		MailBound{Key: loginLaneKeyPrefix + "attempts.window", Kind: MailBoundDuration, Min: int64(time.Nanosecond), Max: int64(time.Hour), HasMax: true,
			Sample: "15m", Why: "окно счёта перебора кода; положительное, не длиннее часа"},
		countBound(loginLaneKeyPrefix+"attempts.address-failure-ceiling", 1, 0, false, 0, "100",
			"потолок неверных предъявлений на адрес за окно перебора"),
		durationBound(loginLaneKeyPrefix+"mail-throttled-interval", day, 30*day, "168h",
			"не чаще одного письма о торможении адресату за этот промежуток"),
		countBound(invitePrefix+"account-per-day", 0, 0, false, day, "200",
			"приглашений одного аккаунта в сутки"),
		countBound(invitePrefix+"young-account-per-day", 0, 0, false, day, "50",
			"приглашений молодого аккаунта в сутки; не больше потолка зрелого"),
		MailBound{Key: invitePrefix + "young-account-age", Kind: MailBoundDuration, Min: 0,
			Sample: "720h", Why: "возраст, до которого аккаунт считается молодым"},
		countBound(invitePrefix+"pending-max", 1, 0, false, 0, "200",
			"висящих приглашений одного аккаунта"),
		countBound(invitePrefix+"recipient-per-hour", 0, 0, false, time.Hour, "3",
			"писем приглашения одному адресату от одного аккаунта в час"),
		countBound(invitePrefix+"recipient-per-day", 0, 0, false, day, "5",
			"писем приглашения одному адресату от одного аккаунта в сутки"),
		countBound(invitePrefix+"recipient-per-day-all", 0, 0, false, day, "10",
			"писем приглашения одному адресату в сутки поперёк аккаунтов"),
		durationBound(invitePrefix+"ttl", day, 30*day, "168h",
			"срок строки приглашения: после него активация отвергается"),
		durationBound(loginLaneKeyPrefix+"trusted-device.ttl", day, 365*day, "2160h",
			"срок метки доверенного устройства от её выдачи"),
		countBound(loginLaneKeyPrefix+"trusted-device.recovery-per-day", 1, 5, true, day, "2",
			"писем восстановления в сутки по паре (окно адресата, метка устройства)"),
	)
	return out
}()

// MailBoundOrders — порядки между ручками таблицы (Р8).
var MailBoundOrders = func() []MailBoundOrder {
	var out []MailBoundOrder
	codeTTL := map[string]string{
		"recovery":     loginLaneKeyPrefix + "recovery-code-ttl",
		"verification": loginLaneKeyPrefix + "verification-code-ttl",
		"registration": loginLaneKeyPrefix + "registration-code-ttl",
	}
	for _, p := range mailWindowPurposes {
		k := mailWindowPrefix + p + "."
		out = append(out,
			MailBoundOrder{k + "first-pause", k + "second-pause"},
			MailBoundOrder{k + "per-hour", k + "per-day"},
			MailBoundOrder{k + "first-pause", codeTTL[p]},
		)
	}
	out = append(out,
		MailBoundOrder{invitePrefix + "young-account-per-day", invitePrefix + "account-per-day"},
		MailBoundOrder{invitePrefix + "recipient-per-hour", invitePrefix + "recipient-per-day"},
		MailBoundOrder{invitePrefix + "recipient-per-day", invitePrefix + "recipient-per-day-all"},
	)
	return out
}()

// ValidateMailBounds — страж старта таблицы границ (NTF2-50, NTF2-71).
//
// Действует в ЛЮБОМ режиме и на любой посадке: ручки лимитов почты нужны
// службе всегда, а величина, подставленная построением, предметом стража быть
// не может. Отказ называет ключ и переменную; у незаданной — её отсутствие, у
// величины вне границ — значение и границу, у нарушенного порядка — обе ручки
// и порядок. Порядок судится только между объявленными и годными ручками:
// незаданная ручка уже названа своим отказом, и второй текст о ней только
// спутал бы оператора.
func (c Config) ValidateMailBounds() error {
	root := reflect.ValueOf(c)
	var errs error
	values := make(map[string]int64, len(MailBounds))
	for _, b := range MailBounds {
		v, ok, err := mailBoundValue(root, b)
		switch {
		case err != nil:
			errs = multierr.Append(errs, err)
		case !ok:
			errs = multierr.Append(errs, fmt.Errorf("%s must be declared (%s): %s",
				b.Key, EnvNameOfKey(b.Key), b.Why))
		case b.Kind == MailBoundDeclared:
		case v < b.Min || (b.HasMax && v > b.Max):
			errs = multierr.Append(errs, fmt.Errorf("%s = %s (%s) is outside its bound %s",
				b.Key, b.format(v), EnvNameOfKey(b.Key), b.bound()))
		default:
			values[b.Key] = v
		}
	}
	byKey := mailBoundsByKey()
	for _, o := range MailBoundOrders {
		lo, okLo := values[o.Lesser]
		hi, okHi := values[o.Greater]
		if !okLo || !okHi || lo <= hi {
			continue
		}
		errs = multierr.Append(errs, fmt.Errorf("%s = %s exceeds %s = %s: the bound is %s ≤ %s",
			o.Lesser, byKey[o.Lesser].format(lo), o.Greater, byKey[o.Greater].format(hi), o.Lesser, o.Greater))
	}
	return errs
}

func mailBoundsByKey() map[string]MailBound {
	out := make(map[string]MailBound, len(MailBounds))
	for _, b := range MailBounds {
		out[b.Key] = b
	}
	return out
}

// format — величина строки словами её вида.
func (b MailBound) format(v int64) string {
	if b.Kind == MailBoundDuration {
		return time.Duration(v).String()
	}
	return strconv.FormatInt(v, 10)
}

// bound — граница строки словами: «lo ≤ x ≤ hi», «lo ≤ x», «0 < x ≤ hi».
func (b MailBound) bound() string {
	lo := b.format(b.Min) + " ≤ x"
	if b.Kind == MailBoundDuration && b.Min == int64(time.Nanosecond) {
		lo = "0 < x"
	}
	if b.HasMax {
		return lo + " ≤ " + b.format(b.Max)
	}
	return lo
}

// mailBoundValue — величина строки в разобранной настройке: поле находится
// по пути ключа ТЕМ ЖЕ правилом тегов `mapstructure`, каким его заполняет
// декодер, поэтому ключ таблицы и поле разойтись не могут — ключ без поля
// даёт ошибку, а не молчаливое «не объявлено». ok == false — не объявлена:
// указатель nil либо пустая строка.
func mailBoundValue(root reflect.Value, b MailBound) (int64, bool, error) {
	f, found := fieldByKey(root, b.Key)
	if !found {
		return 0, false, fmt.Errorf("%s: строка таблицы границ не находит поля настройки — таблица и структура Config разошлись", b.Key)
	}
	if f.Kind() == reflect.Pointer {
		if f.IsNil() {
			return 0, false, nil
		}
		f = f.Elem()
	}
	switch f.Kind() {
	case reflect.Bool:
		return 0, true, nil
	case reflect.String:
		return 0, strings.TrimSpace(f.String()) != "", nil
	case reflect.Int, reflect.Int64:
		return f.Int(), true, nil
	default:
		return 0, false, fmt.Errorf("%s: поле вида %s таблица границ не судит", b.Key, f.Kind())
	}
}

// fieldByKey — поле структуры по пути ключа, по тегам `mapstructure` (правило
// обхода — walkDecoderKeys в strict_env.go).
func fieldByKey(v reflect.Value, key string) (reflect.Value, bool) {
	segs := strings.Split(key, ".")
	cur := v
	for _, seg := range segs {
		for cur.Kind() == reflect.Pointer {
			if cur.IsNil() {
				return reflect.Value{}, false
			}
			cur = cur.Elem()
		}
		if cur.Kind() != reflect.Struct {
			return reflect.Value{}, false
		}
		next, ok := structFieldByTag(cur, seg)
		if !ok {
			return reflect.Value{}, false
		}
		cur = next
	}
	return cur, true
}

func structFieldByTag(v reflect.Value, seg string) (reflect.Value, bool) {
	tp := v.Type()
	for i := 0; i < tp.NumField(); i++ {
		f := tp.Field(i)
		if !f.IsExported() {
			continue
		}
		name, opts, _ := strings.Cut(f.Tag.Get("mapstructure"), ",")
		if name == "" && hasTagOption(opts, "squash") {
			if got, ok := structFieldByTag(v.Field(i), seg); ok {
				return got, true
			}
			continue
		}
		if name == "" {
			name = strings.ToLower(f.Name)
		}
		if name == seg {
			return v.Field(i), true
		}
	}
	return reflect.Value{}, false
}

// Declared — значение ручки таблицы границ для читателя в композиционном
// корне. nil — страж старта не исполнялся либо ручку не объявили: читатель
// получает отказ с именем ключа, а не нулевое значение, которое у сроков и
// потолков читалось бы как «без ограничения».
func Declared[T any](p *T, key string) (T, error) {
	if p == nil {
		var zero T
		return zero, fmt.Errorf("%s must be declared (%s)", key, EnvNameOfKey(key))
	}
	return *p, nil
}

// MailMomentKind — вид таблицы моментов, чей срок хранения выводится из
// верхних границ окон, которые её читают (З26).
type MailMomentKind string

// Виды таблиц моментов (замысел NTF-2 З26, таблица «Сроки на границах Р8»).
const (
	MailMomentThrottled     MailMomentKind = "mail_window_letters.throttled"
	MailMomentProgression   MailMomentKind = "mail_window_letters.progression"
	MailMomentFloor         MailMomentKind = "mail_window_letters.floor"
	MailMomentTrustedDevice MailMomentKind = "mail_window_letters.trusted_device"
	MailMomentInviteActs    MailMomentKind = "invite_acts"
	MailMomentTrustedLabels MailMomentKind = "trusted_devices"
)

// MailMomentReaders — какие окна читают каждый вид: ключи таблицы границ.
// Окно ручки — её верхняя граница у длительности и окно, заданное именем, у
// счёта.
var MailMomentReaders = func() map[MailMomentKind][]string {
	var windows []string
	for _, p := range mailWindowPurposes {
		k := mailWindowPrefix + p + "."
		windows = append(windows, k+"first-pause", k+"second-pause", k+"per-hour", k+"per-day", k+"floor-interval")
	}
	invites := []string{
		invitePrefix + "account-per-day", invitePrefix + "young-account-per-day",
		invitePrefix + "recipient-per-hour", invitePrefix + "recipient-per-day", invitePrefix + "recipient-per-day-all",
	}
	return map[MailMomentKind][]string{
		MailMomentThrottled:     {loginLaneKeyPrefix + "mail-throttled-interval"},
		MailMomentProgression:   windows,
		MailMomentFloor:         windows,
		MailMomentTrustedDevice: {loginLaneKeyPrefix + "trusted-device.recovery-per-day"},
		MailMomentInviteActs:    invites,
		MailMomentTrustedLabels: {loginLaneKeyPrefix + "trusted-device.ttl"},
	}
}()

// mailRetentionMargin — запас сверх верхней границы окна: покрывает шаг уборки.
const mailRetentionMargin = time.Hour

// MailRetention — срок хранения вида (З26): наибольшая ВЕРХНЯЯ ГРАНИЦА окон,
// читающих вид, плюс запас. Граница берётся из таблицы, а не из настроенного
// значения: поднятие ручки в пределах границы не делает прежние моменты
// невидимыми окну. Вид без читателей либо читатель без верхней границы — ноль:
// такой вид срока не выводит, и проба срока хранения называет его находкой.
func MailRetention(kind MailMomentKind) time.Duration {
	byKey := mailBoundsByKey()
	var longest time.Duration
	for _, key := range MailMomentReaders[kind] {
		b, ok := byKey[key]
		if !ok {
			return 0
		}
		w, ok := b.upperWindow()
		if !ok {
			return 0
		}
		if w > longest {
			longest = w
		}
	}
	if longest == 0 {
		return 0
	}
	return longest + mailRetentionMargin
}

// upperWindow — верхняя граница окна ручки: у длительности — её граница, у
// счёта — окно, заданное именем.
func (b MailBound) upperWindow() (time.Duration, bool) {
	switch b.Kind {
	case MailBoundDuration:
		return time.Duration(b.Max), b.HasMax
	case MailBoundCount:
		return b.Window, b.Window > 0
	default:
		return 0, false
	}
}

// bindMailBounds — привязка ключей таблицы к окружению. У ручек нет
// умолчания, а AutomaticEnv резолвит переменную только для ключа, который
// viper уже знает; привязка регистрирует ключ, НЕ давая ему значения.
func bindMailBounds(bind func(input ...string) error) error {
	for _, b := range MailBounds {
		if err := bind(b.Key, EnvNameOfKey(b.Key)); err != nil {
			return fmt.Errorf("bind %s env: %w", b.Key, err)
		}
	}
	return nil
}
