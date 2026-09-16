// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// invite_mail.go — величины НАШЕГО отправителя письма приглашения.
//
// Основание: приёмка доставки писем ID-MAIL-1, Р23 (у
// письма приглашения производитель — наш код) и Р25 (отправка идёт через очередь
// в нашей базе). Объём §10 п. 20.
//
// # ВЕЛИЧИН ДВЕ, И ОНИ РАЗНЫЕ
//
// Предел времени на ПОПЫТКУ (`attempt-timeout`) и число ПОВТОРОВ
// (`max-attempts`) — разные величины с разными предметами, и круг 6 приёмки
// назвал это явно (§4.1, замечание В1). «Ограниченный повтор» без первой
// ограничивает ЧИСЛО попыток, каждая из которых вправе висеть вечно, — а это
// §«Per-call deadline на КАЖДОМ внешнем вызове» в чистом виде.
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
//
// # АДРЕС УЗЛА — В ТОЙ ФОРМЕ, КОТОРУЮ ЧИТАЕТ ВТОРОЙ ОТПРАВИТЕЛЬ
//
// Писем у продукта три вида, отправителя два (Р23): приглашение шлёт наш код,
// подтверждение и восстановление — почтовый процесс поставщика личности. Узел,
// адрес отправителя и удостоверение объявляются ОДНАЖДЫ, и оба берут их оттуда
// (§10 п. 19, MAIL-48). Единственное объявление несёт адрес в форме URI —
// `smtp://[имя@]узел:порт/` либо `smtps://…`, — потому что это форма второго
// читателя. Значит `relay` обязан понимать ту же строку ТАК ЖЕ: схема — посадка
// полосы (`smtp` — STARTTLS, `smtps` — неявный TLS), часть до «@» — имя
// пользователя. Всё, что второй читатель исполнил бы, а наш нет (параметры
// адреса, путь, адрес без порта), отвергается при старте: принять и не
// исполнить значит прочитать одну величину двумя разными смыслами.
//
// Прежде форма ПРИНИМАЛАСЬ и частью ВЫБРАСЫВАЛАСЬ: транспорт срезал схему молча,
// `smtps://` уходил в STARTTLS, имя пользователя становилось частью имени узла,
// а завершающий `/` — частью порта. И страж судил другим предикатом, чем
// транспорт: `smtp://` для одного был объявленной полосой, для другого — нет.
// Разбор теперь ОДИН (`RelayCoordinate`), и транспорт получает `узел:порт`.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
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
//	Relay          — адрес почтового узла: `host:port` либо
//	                 `smtp[s]://[имя@]host:port/` (RelayCoordinate). Пусто ⇒
//	                 полоса не настроена.
//	From           — адрес отправителя, ОДИН на установку (Р16).
//	FromName       — отображаемое имя отправителя; необязательно.
//	UsernameEnv    — ИМЯ переменной окружения с логином удостоверения; у
//	                 адреса формы URI логин — часть до «@», и второго
//	                 источника у него нет.
//	PasswordEnv    — ИМЯ переменной окружения с паролем удостоверения.
//	TLSMode        — `starttls` (умолчание) либо `implicit`; у адреса формы
//	                 URI посадку называет схема, и ручка обязана совпасть.
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
	coord, err := c.RelayCoordinate()
	if err != nil {
		return fmt.Errorf("invite-mail: %w", err)
	}
	if degenerate(c.From) {
		return fmt.Errorf(
			"invite-mail: relay %q is declared without a sender address "+
				"(invite-mail.from) — there is no built-in default for it", redactRelay(c.Relay))
	}
	// ИМЯ ПОЛЬЗОВАТЕЛЯ — ОДИН ИСТОЧНИК. Адрес формы URI несёт его частью до
	// «@», окружение — по имени переменной; оба сразу — два источника одной
	// величины, и какой победит, решал бы порядок, а не решение.
	userInAddress := coord.Username != ""
	userInEnv := !degenerate(c.UsernameEnv)
	if userInAddress && userInEnv {
		return fmt.Errorf(
			"invite-mail: the user name is declared twice — inside invite-mail.relay and by " +
				"invite-mail.username-env; one value, one source: keep the one the other sender " +
				"of the same lane reads, the address")
	}
	userSet := userInAddress || userInEnv
	passSet := !degenerate(c.PasswordEnv)
	if userSet != passSet {
		return fmt.Errorf(
			"invite-mail: credentials are half-declared (user name set: %t — in invite-mail.relay: "+
				"%t, invite-mail.username-env: %t; invite-mail.password-env set: %t) — half a "+
				"configuration is worse than none, because it looks configured",
			userSet, userInAddress, userInEnv, passSet)
	}
	knob, err := parseTLSModeName(c.TLSMode)
	if err != nil {
		return fmt.Errorf("invite-mail: %w", err)
	}
	// ПОСАДКА — ОДИН ИСТОЧНИК. Схема адреса называет её сама; ручка, названная
	// рядом, обязана совпасть, иначе один узел объявлен двумя посадками.
	if coord.TLSMode != "" && !degenerate(c.TLSMode) && knob != coord.TLSMode {
		return fmt.Errorf(
			"invite-mail: invite-mail.relay names the lane %q by its scheme while "+
				"invite-mail.tls-mode names %q — one relay, two landings; drop the knob, the "+
				"address already says it", coord.TLSMode, knob)
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

// MailRelayCoordinate — разобранный адрес почтового узла.
//
// Разбор ОДИН на стража старта и на сборку отправителя: разойдясь, они
// разошлись бы ровно там, где расхождение опасно, — так и было, пока транспорт
// срезал схему сам.
type MailRelayCoordinate struct {
	// HostPort — `узел:порт`, который набирает транспорт.
	HostPort string
	// TLSMode — посадка, названная СХЕМОЙ адреса (`starttls`/`implicit`).
	// Пусто у голой формы: её посадку называет ручка `tls-mode`.
	TLSMode string
	// Username — имя пользователя из адреса формы URI, раскодированное. Пусто,
	// если адрес его не несёт.
	Username string
}

// defaultRelayPort — порт ГОЛОЙ формы, когда он не назван (порт отправки
// почты). У формы URI умолчания порта нет — см. parseRelayURI.
const defaultRelayPort = "587"

// RelayCoordinate разбирает `invite-mail.relay`.
//
// Две формы, и у каждой свой смысл:
//
//	узел[:порт]                    — посадку называет tls-mode, имя — username-env;
//	smtp[s]://[имя@]узел:порт[/]   — посадку называет схема, имя — часть до «@»;
//	                                 это форма второго отправителя той же полосы.
//
// Незаданная полоса (пусто, пробелы) — не адрес: вызывающий обязан спросить
// RelayConfigured раньше.
func (c InviteMailConfig) RelayCoordinate() (MailRelayCoordinate, error) {
	s := strings.TrimSpace(c.Relay)
	if s == "" {
		return MailRelayCoordinate{}, errors.New("invite-mail.relay is not declared")
	}
	if strings.Contains(s, "://") {
		return parseRelayURI(s)
	}
	return parseRelayBare(s)
}

// parseRelayURI — форма второго отправителя: `smtp[s]://[имя@]узел:порт[/]`.
func parseRelayURI(s string) (MailRelayCoordinate, error) {
	shown := redactRelay(s)
	u, err := url.Parse(s)
	if err != nil {
		// Текст ошибки разбора несёт адрес ЦЕЛИКОМ, а в нём может стоять
		// удостоверение: наружу идёт только причина.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return MailRelayCoordinate{}, fmt.Errorf("invite-mail.relay %q does not parse as an address: %v", shown, err)
	}
	var coord MailRelayCoordinate
	switch strings.ToLower(u.Scheme) {
	case "smtp":
		coord.TLSMode = "starttls"
	case "smtps":
		coord.TLSMode = "implicit"
	default:
		return MailRelayCoordinate{}, fmt.Errorf(
			"invite-mail.relay %q: scheme %q is not a mail lane (allowed: smtp:// — STARTTLS, "+
				"smtps:// — implicit TLS); there is no plaintext lane to choose", shown, u.Scheme)
	}
	if u.User != nil {
		if _, hasPassword := u.User.Password(); hasPassword {
			return MailRelayCoordinate{}, fmt.Errorf(
				"invite-mail.relay %q carries a password inside the address — the credential "+
					"comes from the secret by invite-mail.password-env, never from the address: "+
					"the address is rendered into the config map, which is read wider than a secret", shown)
		}
		coord.Username = u.User.Username()
		if strings.TrimSpace(coord.Username) == "" {
			return MailRelayCoordinate{}, fmt.Errorf(
				"invite-mail.relay %q names an empty user before «@» — either name the user or "+
					"drop the «@»", shown)
		}
	}
	if u.RawQuery != "" || u.ForceQuery {
		return MailRelayCoordinate{}, fmt.Errorf(
			"invite-mail.relay %q carries address parameters (%q) — the invite sender implements "+
				"none of them, and accepting one it does not honour would make the same value mean "+
				"two different lanes to the two senders", shown, u.RawQuery)
	}
	if u.Fragment != "" || strings.Contains(s, "#") {
		return MailRelayCoordinate{}, fmt.Errorf("invite-mail.relay %q carries a fragment — a relay address has none", shown)
	}
	if u.Opaque != "" || (u.Path != "" && u.Path != "/") {
		return MailRelayCoordinate{}, fmt.Errorf(
			"invite-mail.relay %q carries a path — a relay address is scheme, user, host and port", shown)
	}
	host, port := u.Hostname(), u.Port()
	if strings.TrimSpace(host) == "" {
		return MailRelayCoordinate{}, fmt.Errorf("invite-mail.relay %q names no host", shown)
	}
	if port == "" {
		return MailRelayCoordinate{}, fmt.Errorf(
			"invite-mail.relay %q names no port — in this form the port is part of the value "+
				"the other sender of the same lane reads, and it has no default for it: a "+
				"port-less address would mean two different relays to the two senders", shown)
	}
	if err := validRelayPort(port); err != nil {
		return MailRelayCoordinate{}, fmt.Errorf("invite-mail.relay %q: %w", shown, err)
	}
	coord.HostPort = net.JoinHostPort(host, port)
	return coord, nil
}

// parseRelayBare — прежняя форма `узел[:порт]`.
func parseRelayBare(s string) (MailRelayCoordinate, error) {
	if strings.Contains(s, "@") {
		return MailRelayCoordinate{}, fmt.Errorf(
			"invite-mail.relay %q carries «@» — a user name lives only in the smtp:// form "+
				"(or in invite-mail.username-env), a bare address is host[:port]", redactRelay(s))
	}
	if strings.ContainsAny(s, "/?#") {
		return MailRelayCoordinate{}, fmt.Errorf(
			"invite-mail.relay %q is not host[:port] — a path or parameters belong to no bare address", s)
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		// Порт не назван — узел назван: это законно, порт подставляется. Но
		// двоеточие без разбираемой пары — не узел.
		if strings.Contains(s, ":") {
			return MailRelayCoordinate{}, fmt.Errorf("invite-mail.relay %q is not host[:port]", s)
		}
		host, port = s, defaultRelayPort
	}
	host, port = strings.TrimSpace(host), strings.TrimSpace(port)
	if host == "" {
		return MailRelayCoordinate{}, fmt.Errorf("invite-mail.relay %q names no host", s)
	}
	if err := validRelayPort(port); err != nil {
		return MailRelayCoordinate{}, fmt.Errorf("invite-mail.relay %q: %w", s, err)
	}
	return MailRelayCoordinate{HostPort: net.JoinHostPort(host, port)}, nil
}

// validRelayPort — порт есть число 1…65535.
func validRelayPort(port string) error {
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("port %q is not a TCP port", port)
	}
	return nil
}

// relayUserinfo — часть адреса до «@» в форме URI.
var relayUserinfo = regexp.MustCompile(`://[^@/?#]*@`)

// redactRelay — адрес для текста отказа: часть до «@» вырезана. Отказ,
// печатающий адрес целиком, вынес бы удостоверение, если его туда положили, в
// журнал — дверь шире секрета (Р6).
func redactRelay(s string) string {
	return relayUserinfo.ReplaceAllString(s, "://***@")
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

// TLSModeName — посадка полосы, которую применит отправитель.
//
// Адрес формы URI называет её схемой, и тогда она берётся ИЗ АДРЕСА — это
// единственный источник, который читает и второй отправитель той же полосы.
// Голый адрес посадки не называет: её называет ручка, умолчание — STARTTLS.
func (c InviteMailConfig) TLSModeName() string {
	if !degenerate(c.Relay) {
		if coord, err := c.RelayCoordinate(); err == nil && coord.TLSMode != "" {
			return coord.TLSMode
		}
	}
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
