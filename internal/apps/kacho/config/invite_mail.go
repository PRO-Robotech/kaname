// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// invite_mail.go — величины НАШЕГО отправителя письма приглашения.
//
// Основание: приёмка sub-phase-ID-MAIL-1-mail-delivery-acceptance.md, Р23 (у
// письма приглашения производитель — наш код) и Р25 (отправка идёт через очередь
// в нашей базе). Объём §10 п. 20.
//
// # ВЕЛИЧИН ДВЕ, И ОНИ РАЗНЫЕ
//
// Предел времени на ПОПЫТКУ (`attempt-timeout`) и число ПОВТОРОВ
// (`max-attempts`) — разные величины с разными предметами, и круг 6 приёмки
// назвал это явно (§4.1, замечание В1). «Ограниченный повтор» без первой
// ограничивает ЧИСЛО попыток, каждая из которых вправе висеть вечно, — а это
// `architecture.md` §«Per-call deadline на КАЖДОМ внешнем вызове» в чистом виде.
//
// # ВСТРОЕННЫХ УМОЛЧАНИЙ У УЗЛА, ОТПРАВИТЕЛЯ И УДОСТОВЕРЕНИЯ НЕТ (Р3)
//
// Пустое значение означает «не задано», а не «разумное значение»: величина,
// которую построение подставляет молча, предметом стража быть не может — он
// зелен при любом входе, потому что незаданной она не бывает. Умолчания есть
// РОВНО у двух величин — предела попытки и числа повторов, — и у обеих по одной
// причине: незаданный предел означал бы БЕСКОНЕЧНОЕ ожидание, то есть ровно тот
// дефект, который предел и снимает. Это не то же, что умолчание адреса: пустой
// адрес даёт наблюдаемый отказ, пустой предел — тишину.
//
// # ПОЛОСА ШИФРОВАНА, И ВЫБРАТЬ ИНОЕ ОПЕРАТОР НЕ МОЖЕТ
//
// `ParseMailTLSMode` принимает два имени, и незащищённой полосы среди них нет
// (ban #16: dev-insecure posture запрещена на любом поднятом стенде). Это
// построение, а не соглашение: значения, которого разбор не производит, оператор
// выбрать не может, как бы он ни написал настройку.
package config

import (
	"fmt"
	"strings"
	"time"
)

// Умолчания ДВУХ величин отправителя. У остальных умолчаний нет (Р3).
const (
	// defaultInviteMailAttemptTimeout — предел времени на ОДНУ попытку отправки:
	// весь разговор с почтовым узлом, от соединения до принятого письма.
	//
	// ВЕЛИЧИНА НАЗВАНА РЕШЕНИЕМ, А НЕ ВЫБРАНА НАУГАД, и вот его основание.
	// Разговор SMTP — это семь оборотов до узла (приветствие, EHLO, STARTTLS,
	// повторный EHLO, AUTH, MAIL/RCPT, DATA), поэтому предел обязан быть кратно
	// больше одного оборота, иначе исправная отправка через нагруженный
	// ретранслятор станет «временным отказом» и уйдёт в повтор. Двадцать секунд
	// дают около трёх секунд на оборот при семи оборотах — с запасом к
	// наблюдаемой задержке публичных ретрансляторов и заметно меньше, чем
	// терпение дренажа (`ApplyTimeout`), который обязан пережить эту попытку
	// целиком, а не оборвать её раньше.
	//
	// ПРЕДИКАТ ПЕРЕСМОТРА: доля клетки `transient` счётчика исходов при живом
	// узле. Систематический временный отказ на узле, который отвечает, означает,
	// что предел мал; ноль повторов при заведомо медленном узле — что велик.
	defaultInviteMailAttemptTimeout = 20 * time.Second

	// defaultInviteMailMaxAttempts — число ПОВТОРОВ дренажа, после которого
	// строка объявляется отравленной и перестаёт ретраиться.
	//
	// ВЕЛИЧИНА НАЗВАНА РЕШЕНИЕМ. Десять попыток при возрастающей паузе от
	// секунды до тридцати покрывают порядка четырёх минут недоступности узла —
	// то есть переживают перекат ретранслятора, но не переживают неверную
	// настройку. Отравленная строка НЕ теряется: она остаётся в очереди видимой
	// и поднимается обратно возвратом (`outbox/reconciler`), когда настройку
	// починят.
	//
	// ПРЕДИКАТ ПЕРЕСМОТРА: число отравленных строк очереди при исправной
	// настройке. Систематическое отравление означает, что окно мало.
	defaultInviteMailMaxAttempts = 10
)

// InviteMailConfig — секция `invite-mail`.
//
//	Relay          — `host:port` почтового узла. Пусто ⇒ полоса не настроена.
//	From           — адрес отправителя, ОДИН на установку (Р16).
//	FromName       — отображаемое имя отправителя; необязательно.
//	UsernameEnv    — ИМЯ переменной окружения с логином удостоверения.
//	PasswordEnv    — ИМЯ переменной окружения с паролем удостоверения.
//	TLSMode        — `starttls` (умолчание) либо `implicit`.
//	CABundleFile   — якорь доверия для проверки сертификата узла.
//	LoginURL       — адрес страницы входа, который несёт письмо.
//	AttemptTimeout — предел времени на ОДНУ попытку.
//	MaxAttempts    — число повторов дренажа.
//
// УДОСТОВЕРЕНИЕ ПРИЕЗЖАЕТ ИЗ СЕКРЕТА, А НЕ ИЗ КАРТЫ НАСТРОЕК (Р6), поэтому здесь
// объявлены ИМЕНА переменных окружения, а не сами значения: карта настроек
// читается шире секрета, и величина, положенная в неё, доступна каждому, кто
// вправе её прочитать. Форма перенята у уже существующей ручки чеканки
// (`authn.bootstrap-mint.signing-key-env`), а не изобретена.
type InviteMailConfig struct {
	Relay          string        `mapstructure:"relay"`
	From           string        `mapstructure:"from"`
	FromName       string        `mapstructure:"from-name"`
	UsernameEnv    string        `mapstructure:"username-env"`
	PasswordEnv    string        `mapstructure:"password-env"`
	TLSMode        string        `mapstructure:"tls-mode"`
	CABundleFile   string        `mapstructure:"ca-bundle-file"`
	LoginURL       string        `mapstructure:"login-url"`
	AttemptTimeout time.Duration `mapstructure:"attempt-timeout"`
	MaxAttempts    int           `mapstructure:"max-attempts"`
}

// AttemptTimeoutOrDefault — предел времени на одну попытку.
//
// Непозитивное значение читается как незаданное и заменяется умолчанием: попытка
// без предела не ограничена ничем, и «не задано» здесь означало бы бесконечное
// ожидание. Это ОТДЕЛЬНАЯ величина от числа повторов, и подменять одну другой
// нельзя ни в какую сторону.
func (c InviteMailConfig) AttemptTimeoutOrDefault() time.Duration {
	if c.AttemptTimeout <= 0 {
		return defaultInviteMailAttemptTimeout
	}
	return c.AttemptTimeout
}

// MaxAttemptsOrDefault — число повторов дренажа.
func (c InviteMailConfig) MaxAttemptsOrDefault() int {
	if c.MaxAttempts <= 0 {
		return defaultInviteMailMaxAttempts
	}
	return c.MaxAttempts
}

// RelayConfigured говорит, объявлена ли почтовая полоса ВООБЩЕ.
//
// Предикат ОДИН на стража и на потребителя, и это требование Р4, а не стиль:
// разойдясь, они разойдутся ровно там, где расхождение опасно — на вырожденном
// значении, которое для одного «непусто», а для другого пусто.
func (c InviteMailConfig) RelayConfigured() bool {
	return !degenerate(c.Relay)
}

// Validate — страж величин ОТПРАВИТЕЛЯ.
//
// # ЧТО ОН СУДИТ И ЧЕГО НЕ СУДИТ — СКАЗАНО ПРЯМО
//
// Он судит СОГЛАСОВАННОСТЬ объявленных величин между собой: половину пары
// удостоверения, отправителя без узла, непонятную посадку полосы, непозитивные
// величины. Он НЕ требует, чтобы полоса была объявлена: «объявлена ли она
// вообще» — предмет стража рендера профиля и шага подстановки (Р4а, места С1 и
// С2), у которых есть то, чего нет здесь, — доступ к объявлениям профиля и к
// фактической величине из секрета. Страж, судящий величину, которой не видит,
// был бы зелен при любом входе.
//
// # ПОЛОВИНА ПАРЫ ХУЖЕ ОТСУТСТВИЯ ОБЕИХ
//
// Она выглядит настроенной. Поэтому объявленный логин без пароля (и зеркально)
// — отказ, а не предупреждение.
func (c InviteMailConfig) Validate() error {
	if degenerate(c.Relay) {
		// Полоса не объявлена. Согласовывать нечего; отсутствие судит не здесь.
		// Но объявленные ПОЛОВИНЫ при необъявленной полосе — уже расхождение:
		// они выглядят настройкой, которой не соответствует ни один узел.
		if !degenerate(c.From) || !degenerate(c.UsernameEnv) || !degenerate(c.PasswordEnv) {
			return fmt.Errorf(
				"invite-mail: relay is not declared, yet sender/credential knobs are " +
					"(invite-mail.relay is empty while invite-mail.from/username-env/password-env " +
					"are set) — a half-declared lane looks configured and delivers nothing")
		}
		return nil
	}
	if degenerate(c.From) {
		return fmt.Errorf(
			"invite-mail: relay %q is declared without a sender address "+
				"(invite-mail.from) — there is no built-in default for it", c.Relay)
	}
	userSet := !degenerate(c.UsernameEnv)
	passSet := !degenerate(c.PasswordEnv)
	if userSet != passSet {
		return fmt.Errorf(
			"invite-mail: credentials are half-declared (invite-mail.username-env set: %t, "+
				"invite-mail.password-env set: %t) — half a configuration is worse than none, "+
				"because it looks configured", userSet, passSet)
	}
	if _, err := parseTLSModeName(c.TLSMode); err != nil {
		return fmt.Errorf("invite-mail: %w", err)
	}
	if c.AttemptTimeout < 0 {
		return fmt.Errorf(
			"invite-mail.attempt-timeout must not be negative (got %s) — it is the deadline of "+
				"ONE delivery attempt, a different value from invite-mail.max-attempts",
			c.AttemptTimeout)
	}
	if c.MaxAttempts < 0 {
		return fmt.Errorf(
			"invite-mail.max-attempts must not be negative (got %d) — it is the retry bound, "+
				"a different value from invite-mail.attempt-timeout", c.MaxAttempts)
	}
	return nil
}

// parseTLSModeName принимает РОВНО два имени посадки полосы.
//
// Незащищённой полосы среди них нет намеренно (ban #16): значение, которого
// разбор не производит, оператор выбрать не может. Разбор живёт здесь, а
// применение — у отправителя; имена совпадают дословно, и совпадение держит
// проба, а не соглашение.
func parseTLSModeName(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "starttls":
		return "starttls", nil
	case "implicit", "tls":
		return "implicit", nil
	default:
		return "", fmt.Errorf(
			"unknown invite-mail.tls-mode %q (allowed: starttls|implicit); the lane to the mail "+
				"relay is encrypted on every stand, so there is no plaintext mode to choose", s)
	}
}

// TLSModeName — нормализованное имя посадки полосы.
func (c InviteMailConfig) TLSModeName() string {
	name, err := parseTLSModeName(c.TLSMode)
	if err != nil {
		// Негодное имя отвергает Validate; здесь возвращаем шифрованную посадку,
		// чтобы ошибка разбора не превращалась в открытую полосу.
		return "starttls"
	}
	return name
}

// degenerate — ОДИН предикат «значение не задано» на стража и на потребителя.
//
// Пустая строка, пробел и табуляция считаются НЕЗАДАННЫМИ, а не «непустыми»
// (Р4). Канонический вход для расхождения — значение из одних пробелов: его
// длина ненулевая, а содержания нет.
func degenerate(s string) bool { return strings.TrimSpace(s) == "" }
