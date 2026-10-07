// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// invite_mail.go — НАШ отправитель писем: приглашение, восстановление доступа и
// подтверждение адреса.
//
// # Почему отправитель здесь, а не у поставщика личности
//
// Писем в продукте три вида. Приглашение отправляем МЫ (приёмка ID-MAIL-1,
// Р23): его предмет — наша строка в нашей базе, и о ней поставщик не знает
// ничего. Восстановление доступа с фазы Ф5 (`kacho#1271`, приёмка
// `recovery-of-access.md`, Р3, Д5) — тоже наше: код чеканим мы, поток
// поставщика истёк вместе с поставщиком, и у письма не осталось бы ни одного
// отправителя. Подтверждение адреса — тоже наше (kaname#456, приёмка
// `access-beyond-login-needs-a-verified-address.md`, Р8): код чеканим мы, и без
// подтверждения человеку не открывается ничего дальше экрана подтверждения.
//
// Второй вид живёт в ТОЙ ЖЕ полосе, а не во второй (Р3): отправитель,
// настройка, закрытый набор клеток исхода, ограниченный повтор и предел времени
// на попытку — общие; различается только тело письма, выбираемое по виду
// события. Две стороны словаря видов — ограничение схемы и ветви применителя —
// сверяет гейт `TestEveryMailKindHasExactlyOneSender`. Имя полосы, очереди и
// клеток осталось от приглашения: переименование не меняет ни одного
// предмета, а разошлось бы с историей.
//
// # Что здесь лежит — три части одной цепочки
//
//   - InviteMailSender — транспорт: один разговор с почтовым узлом, СВОИМ
//     пределом времени ограниченный; тело письма выбирает по виду события;
//   - DecodeMailEvent — Decoder[T] для общего дренажа;
//   - NewInviteMailApplier — Applier[T]: ветвится на ВИДЕ события, зовёт
//     транспорт и раскладывает исход по ЗАКРЫТОМУ набору клеток счётчика.
//
// # Две величины, и они РАЗНЫЕ
//
// Предел времени на ПОПЫТКУ (`MailRelay.AttemptTimeout`) и число ПОВТОРОВ
// (`drainer.Config.MaxAttempts`, композиционный корень) — разные величины с
// разными предметами. «Ограниченный повтор» без первой ограничивает ЧИСЛО
// попыток, каждая из которых вправе висеть вечно, — а это
// §«Per-call deadline на КАЖДОМ внешнем вызове» в чистом виде.
// Наблюдаема первая только на узле, который ПРИНИМАЕТ соединение и молчит: на
// отказе в соединении обрыв даёт ядро, а не наша величина.
//
// # Настройка отделена от сбоя — собственной клеткой
//
// Недоступность узла лечится временем; ответ не по протоколу почты по
// объявленному адресу не лечится никогда. Схлопнуть их в один ряд значит сделать
// постоянную неверную настройку штатным режимом — §Hardening п. 8.
// Поэтому клеток три, набор ЗАКРЫТ и приходит из констант, а не из ответа узла:
// иначе кардинальность росла бы с трафиком.
package clients

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/smtp"
	"net/textproto"
	"net/url"
	"strings"
	"time"

	"github.com/PRO-Robotech/corelib/outbox/drainer"
)

const (
	// InviteMailTable — полное имя очереди писем приглашения. ШЕСТАЯ очередь
	// сервиса; форма не изобретается — она в дереве пятикратна.
	InviteMailTable = "kaname.invite_mail_outbox"
	// InviteMailChannel — LISTEN-канал (триггер миграции).
	InviteMailChannel = "kaname_invite_mail_outbox"
	// EventInviteMailSend — вид события приглашения. Словарь закрыт CHECK'ом
	// миграции: расширение требует и кода, и миграции.
	EventInviteMailSend = "mail.invite.send"
	// EventRecoveryMailSend — вид события письма восстановления доступа (Ф5 Р3);
	// заведён миграцией `20260917015400_recovery_code_is_our_record`.
	EventRecoveryMailSend = "mail.recovery.send"
	// EventVerificationMailSend — вид события письма подтверждения адреса
	// (kaname#456, Р8); заведён миграцией
	// `20260927190000_address_verification_is_our_verb`.
	EventVerificationMailSend = "mail.verification.send"
)

// VerificationScreenPath — путь экрана подтверждения адреса в консоли. Адрес
// экрана — происхождение консоли, объявленное той же настройкой, что адрес
// входа в письмах службы, и этот путь, без параметров и фрагмента.
const VerificationScreenPath = "/verification"

// Клетки счётчика исходов отправки. Набор ЗАКРЫТ (Р25): форма взята у зеркала
// набора ключей вместе с обоснованием — успехи считаются НАРАВНЕ с отказами,
// иначе ноль отказов неотличим от «сюда никто не приходил», а настройка стоит
// СВОЕЙ клеткой, потому что временем не лечится.
const (
	// InviteMailOutcomeSent — письмо СДАНО почтовому узлу.
	//
	// КЛЕТКА НАЗЫВАЕТСЯ «sent», А НЕ «delivered», И ЭТО НЕ ПРИДИРКА К СЛОВУ.
	// Дальше ретранслятора наш вердикт не идёт (Р15): продукт видит сдачу, а не
	// получение адресатом. Ряд с именем «delivered» читался бы дежурным в три
	// часа ночи как «письма доходят» — то есть утверждал бы ровно то, чего
	// продукт не знает, и делал бы это на поверхности, где комментария нет.
	// Имя ряда и есть утверждение; комментарий, поясняющий, что имя означает не
	// то, что говорит, — второе место об одном предмете, и верным было бы одно.
	InviteMailOutcomeSent = "sent"
	// InviteMailOutcomeTransient — узел не принял письмо по причине, которая
	// лечится временем: не поднят, не ответил, ответил временным отказом.
	InviteMailOutcomeTransient = "transient"
	// InviteMailOutcomeMisconfigured — по объявленному адресу не почтовый узел,
	// величина не задана либо задана вырожденно, удостоверение отвергнуто.
	// Временем НЕ лечится.
	InviteMailOutcomeMisconfigured = "misconfigured"
)

// InviteMailOutcomes — закрытый набор клеток семейства.
var InviteMailOutcomes = []string{
	InviteMailOutcomeSent,
	InviteMailOutcomeTransient,
	InviteMailOutcomeMisconfigured,
}

// Сигнальные ошибки классификации. КАЖДАЯ ветка возврата транспорта заворачивает
// свой отказ ровно в одну из них — корзины «прочее» у отправителя нет by
// construction.
var (
	// ErrMailMisconfigured — отказ, который повтор не вылечит.
	ErrMailMisconfigured = errors.New("invite mail: relay is misconfigured")
	// ErrMailTransient — отказ, который лечится временем.
	ErrMailTransient = errors.New("invite mail: relay is temporarily unavailable")
)

// MailTLSMode — посадка полосы до почтового узла.
type MailTLSMode int

const (
	// MailTLSStartTLS — открытая полоса, поднимаемая до шифрованной командой
	// STARTTLS, с проверкой сертификата по объявленному якорю. Посадка по
	// умолчанию: Р5 требует шифрования И на стенде тоже.
	MailTLSStartTLS MailTLSMode = iota
	// MailTLSImplicit — шифрование с первого байта (submissions, 465).
	MailTLSImplicit
	// MailTLSDisabledForTest — НЕЗАЩИЩЁННАЯ полоса, допустимая ТОЛЬКО в
	// in-process фикстурах (ban #16: dev-insecure posture запрещена на любом
	// поднятом стенде).
	//
	// РАЗБОР КОНФИГУРАЦИИ ЭТО ЗНАЧЕНИЕ НЕ ПРОИЗВОДИТ НИ ПРИ КАКОМ ВХОДЕ, и это
	// не соглашение, а построение: `ParseMailTLSMode` принимает два имени и
	// отвергает всё прочее, поэтому оператор не может выбрать незащищённую
	// полосу, как бы он ни написал значение. Свойство закреплено пробой
	// `Test_ParseMailTLSMode_NeverYieldsThePlaintextMode`.
	MailTLSDisabledForTest
)

// ParseMailTLSMode переводит объявление профиля в посадку полосы.
//
// Принимаются РОВНО два имени. Незащищённой полосы среди них нет: значение,
// которого разбор не производит, оператор выбрать не может (ban #16).
func ParseMailTLSMode(s string) (MailTLSMode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "starttls":
		return MailTLSStartTLS, nil
	case "implicit", "tls":
		return MailTLSImplicit, nil
	default:
		return MailTLSStartTLS, fmt.Errorf(
			"%w: unknown mail tls mode %q (allowed: starttls|implicit)", ErrMailMisconfigured, s)
	}
}

// MailRelay — величины НАШЕГО исходящего соединения к почтовому узлу.
//
// Встроенных умолчаний у узла, отправителя и удостоверения НЕТ (Р3): пустое
// значение означает «не задано» и даёт отказ по настройке, а не «разумное
// значение». Величина, которую построение подставляет молча, предметом стража
// быть не может — он зелен при любом входе.
type MailRelay struct {
	// Addr — `host:port` почтового узла.
	Addr string
	// From — адрес отправителя, ОДИН на установку (Р16).
	From string
	// FromName — отображаемое имя отправителя; необязательно.
	FromName string
	// Username/Password — удостоверение. Приезжает из СЕКРЕТА, не из карты
	// настроек (Р6). ПАРА: половина настройки хуже отсутствия обеих, потому что
	// выглядит настроенной (Р4).
	Username string
	Password string
	// AttemptTimeout — СОБСТВЕННЫЙ предел времени на ОДНУ попытку: весь разговор
	// с узлом, от соединения до принятого письма. Отдельная величина от числа
	// повторов, и наблюдаема она на узле, который принимает соединение и молчит.
	AttemptTimeout time.Duration
	// TLSMode — посадка полосы. Р5: шифрование обязательно и на стенде тоже.
	TLSMode MailTLSMode
	// RootCAs — якорь доверия для проверки сертификата узла. nil означает
	// системный набор, а НЕ отключённую проверку: проверка не отключается ничем.
	RootCAs *x509.CertPool
	// ServerName — имя, по которому сверяется сертификат узла. Пусто → берётся
	// из Addr.
	ServerName string
	// LoginURL — адрес страницы входа, который несёт письмо. Ссылки-предъявителя
	// приглашение НЕ несёт (Р24): обладание письмом доступа не даёт.
	LoginURL string
}

// MailEvent — расшифрованная нагрузка одной строки очереди: письмо любого из
// двух видов. Вид в нагрузке НЕ хранится — он в колонке события; применитель
// проставляет его в `Kind` перед сдачей транспорту.
//
// Приглашение предъявителя НЕ несёт (Р24): письмо несёт призыв и адрес страницы
// входа, а доступ даёт владение почтовым ящиком. Письмо восстановления
// предъявителя НЕСЁТ — код — потому что предъявитель и есть его предмет (Ф5 Р1);
// в строке очереди он лежит открытым до сдачи письма узлу, и сданную строку
// снимает уборка.
type MailEvent struct {
	// To — адрес получателя. Единственная координата, без которой письмо
	// отправить некому.
	To string `json:"to"`
	// AccountID — аккаунт. Атрибуция и тело письма приглашения.
	AccountID string `json:"account_id"`
	// UserID — строка человека. Атрибуция; отправка от неё не зависит.
	UserID string `json:"user_id"`
	// LoginURL — адрес страницы входа. Пусто → берётся из настройки установки.
	LoginURL string `json:"login_url,omitempty"`
	// Code — код в форме для человека; у видов восстановления и подтверждения.
	// Строка этих видов без кода нерастолковываема.
	Code string `json:"code,omitempty"`
	// CodeValidMinutes — срок кода в минутах, как его называет письмо (Ф1-25:
	// «код с объявленным сроком»). У видов восстановления и подтверждения.
	CodeValidMinutes int `json:"code_valid_minutes,omitempty"`
	// Kind — вид события строки; проставляется применителем, в нагрузке не
	// хранится.
	Kind string `json:"-"`
}

// InviteMailObserver — писатель счётчика исходов отправки.
//
// Нужен, чтобы «ноль писем за всю жизнь очереди» было ЗАМЕТНО: без него мёртвый
// отправитель и здоровое облако, куда никто не приходил, выглядят одинаково —
// тихо (класс мёртвой очереди регистраций).
type InviteMailObserver interface {
	// IncInviteMailOutcome — исход одной попытки отправки; outcome — клетка из
	// InviteMailOutcomes.
	IncInviteMailOutcome(outcome string)
}

// InviteMailTransport — порт: то, что умеет сдать письмо почтовому узлу.
// Реализуется InviteMailSender; в пробах — подставным транспортом, который
// снисходительнее настоящего быть не вправе. Вид письма приходит в `ev.Kind`.
type InviteMailTransport interface {
	Send(ctx context.Context, ev MailEvent) error
}

// InviteMailSender — транспорт поверх SMTP.
type InviteMailSender struct {
	relay MailRelay
	// now — часы отправителя: ими ставится `Date` письма (kaname#630). Одно
	// поле на отправителя, как `Now` у остальных обработчиков службы, — а не
	// обращение к стене процесса из сборки письма.
	now func() time.Time
}

// NewInviteMailSender конструирует транспорт. Величины НЕ проверяются здесь:
// вырожденная настройка обязана дать наблюдаемый исход `misconfigured` на
// попытке, а не тихий отказ конструирования, который никто не считает.
//
// Часы по умолчанию — `time.Now`, тем же правилом, что у остальных
// обработчиков службы (`Deps.Now == nil → time.Now`); подменяются WithClock.
func NewInviteMailSender(relay MailRelay) *InviteMailSender {
	return &InviteMailSender{relay: relay, now: time.Now}
}

// WithClock ставит часы отправителя — ими датируется каждое письмо. nil
// оставляет часы по умолчанию: «часов нет» у отправителя непредставимо.
func (s *InviteMailSender) WithClock(now func() time.Time) *InviteMailSender {
	if now != nil {
		s.now = now
	}
	return s
}

// defaultAttemptTimeout — предел попытки, применяемый, когда вызывающий его не
// назвал.
//
// ЭТО НЕ УМОЛЧАНИЕ ВЕЛИЧИНЫ ПРОФИЛЯ (Р3 запрещает такие у узла, отправителя и
// удостоверения), а нижняя граница ЗДРАВОГО СМЫСЛА у транспорта: попытка без
// предела не ограничена ничем, и «величина не задана» здесь означало бы
// бесконечное ожидание — то есть ровно тот дефект, который предел и снимает.
// Профиль величину переопределяет; страж старта требует её положительной.
const defaultAttemptTimeout = 20 * time.Second

// Send — один разговор с почтовым узлом, ограниченный СВОИМ пределом времени.
//
// Предел ставится дважды и намеренно: контекстом (он обрывает установление
// соединения) и абсолютным сроком на самом соединении (он обрывает узел, который
// СОЕДИНЕНИЕ ПРИНЯЛ и молчит). Одного контекста мало: после того как соединение
// установлено, чтения и записи по нему контекст уже не сторожит.
func (s *InviteMailSender) Send(ctx context.Context, ev MailEvent) error {
	relay := s.relay

	addr, ok := normalizedHostPort(relay.Addr)
	if !ok {
		if strings.Contains(relay.Addr, "://") {
			// Адрес доехал НЕРАЗОБРАННЫМ. Его разбирает страж старта
			// (`invite-mail.relay`), и сборка обязана отдать сюда `узел:порт`.
			// Сам адрес не печатается: в нём может стоять удостоверение.
			return fmt.Errorf("%w: mail relay address reached the transport as a URI — it is "+
				"parsed once, by the start guard of invite-mail.relay, and must arrive here as "+
				"host:port", ErrMailMisconfigured)
		}
		return fmt.Errorf("%w: mail relay address is not set (got %q)", ErrMailMisconfigured, relay.Addr)
	}
	if strings.TrimSpace(relay.From) == "" {
		return fmt.Errorf("%w: mail sender address is not set", ErrMailMisconfigured)
	}
	if strings.TrimSpace(ev.To) == "" {
		// Нерастолковываемая строка сюда не доезжает (её отвергает декодер), но
		// путь закрыт и здесь: отправка «никому» — форма отправки без предмета.
		return fmt.Errorf("%w: invite mail names no recipient", drainer.ErrPermanent)
	}
	// Штамп письма (`Date`, `Message-ID`) ставится ДО разговора с узлом: письмо,
	// которому его не поставить, не уходит ни при каком входе, и узел о нём не
	// узнаёт. Собирается письмо здесь же, один раз на попытку.
	stamp, err := s.stamp()
	if err != nil {
		return err
	}
	letter := renderMail(relay, ev, stamp)
	// ПАРА удостоверения: половина настройки хуже отсутствия обеих, потому что
	// выглядит настроенной (Р4). Проверяется ОДНИМ предикатом с тем, что читает
	// транспорт, — иначе страж и потребитель разойдутся ровно там, где
	// расхождение опасно.
	userSet := strings.TrimSpace(relay.Username) != ""
	passSet := relay.Password != ""
	if userSet != passSet {
		return fmt.Errorf(
			"%w: mail relay credentials are half-declared (username set: %t, password set: %t)",
			ErrMailMisconfigured, userSet, passSet)
	}

	attempt := relay.AttemptTimeout
	if attempt <= 0 {
		attempt = defaultAttemptTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, attempt)
	defer cancel()
	deadline, _ := ctx.Deadline()

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return classifyDialErr(addr, err)
	}
	defer func() { _ = conn.Close() }()

	// АБСОЛЮТНЫЙ срок на соединении — то, чем обрывается МОЛЧАЩИЙ узел. Без него
	// «ограниченный повтор» ограничивал бы число попыток, каждая из которых
	// висит вечно.
	if derr := conn.SetDeadline(deadline); derr != nil {
		return fmt.Errorf("%w: set attempt deadline on %s: %w", ErrMailTransient, addr, derr)
	}

	serverName := relay.ServerName
	if serverName == "" {
		if host, _, serr := net.SplitHostPort(addr); serr == nil {
			serverName = host
		}
	}

	if relay.TLSMode == MailTLSImplicit {
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName: serverName,
			RootCAs:    relay.RootCAs,
			MinVersion: tls.VersionTLS12,
		})
		if herr := tlsConn.HandshakeContext(ctx); herr != nil {
			return classifyTLSErr(addr, herr)
		}
		conn = tlsConn
	}

	client, err := smtp.NewClient(conn, serverName)
	if err != nil {
		// Приветствие, которое не разбирается как SMTP, — доказательство того,
		// что по объявленному адресу НЕ ПОЧТОВЫЙ УЗЕЛ. Это настройка, и повтор
		// её не вылечит.
		return classifyProtocolErr(addr, err)
	}
	defer func() { _ = client.Close() }()

	// Представляемся доменом отправителя — тем же, в котором отчеканен штамп.
	if herr := client.Hello(stamp.domain); herr != nil {
		return classifySMTPErr(addr, "EHLO", herr)
	}

	if relay.TLSMode == MailTLSStartTLS {
		ok, _ := client.Extension("STARTTLS")
		if !ok {
			// Полоса обязана быть шифрованной И на стенде тоже (Р5). Узел, не
			// умеющий STARTTLS, — не тот узел, к которому мы собирались идти:
			// это НАСТРОЙКА, а не сбой.
			return fmt.Errorf(
				"%w: mail relay %s offers no STARTTLS — the lane must be encrypted", ErrMailMisconfigured, addr)
		}
		if terr := client.StartTLS(&tls.Config{
			ServerName: serverName,
			RootCAs:    relay.RootCAs,
			MinVersion: tls.VersionTLS12,
		}); terr != nil {
			return classifyTLSErr(addr, terr)
		}
	}

	if userSet {
		auth := smtp.PlainAuth("", relay.Username, relay.Password, serverName)
		if aerr := client.Auth(auth); aerr != nil {
			// Отвергнутое удостоверение временем не лечится.
			return fmt.Errorf("%w: mail relay %s rejected our credentials: %w",
				ErrMailMisconfigured, addr, aerr)
		}
	}

	if merr := client.Mail(addressOnly(relay.From)); merr != nil {
		return classifySMTPErr(addr, "MAIL FROM", merr)
	}
	if rerr := client.Rcpt(addressOnly(ev.To)); rerr != nil {
		return classifySMTPErr(addr, "RCPT TO", rerr)
	}
	w, err := client.Data()
	if err != nil {
		return classifySMTPErr(addr, "DATA", err)
	}
	if _, werr := w.Write(letter); werr != nil {
		return fmt.Errorf("%w: write mail body to %s: %w", ErrMailTransient, addr, werr)
	}
	if cerr := w.Close(); cerr != nil {
		return classifySMTPErr(addr, "end of DATA", cerr)
	}
	// QUIT намеренно не роняет исход: письмо УЖЕ принято узлом, и отказ на
	// прощании означал бы повторную отправку принятого — то есть второе письмо
	// адресату (MAIL-53).
	_ = client.Quit()
	return nil
}

// normalizedHostPort приводит адрес к `host:port` и говорит, годен ли он.
//
// АДРЕС ПРИХОДИТ РАЗОБРАННЫМ. Форму URI (`smtp://…`, `smtps://…`) разбирает ОДИН
// раз страж старта (`config.InviteMailConfig.RelayCoordinate`): схема там —
// посадка полосы, часть до «@» — имя пользователя. Прежде здесь схема срезалась
// молча, то есть транспорт разбирал ту же строку второй раз и С ДРУГИМ СМЫСЛОМ:
// `smtps://` уходил в STARTTLS, имя становилось частью имени узла, `/` — частью
// порта. Поэтому адрес со схемой здесь НЕ годен — это отказ по настройке, а не
// повод угадывать.
//
// Вырожденные значения — пустая строка, пробел, `:` и `:25` — считаются
// НЕЗАДАННЫМИ, а не «непустыми» (Р4).
func normalizedHostPort(raw string) (string, bool) {
	s := strings.TrimSpace(raw)
	if s == "" || strings.Contains(s, "://") {
		return "", false
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		// Порт не назван — узел назван. Это законно: порт подставляем.
		if strings.Contains(s, ":") {
			return "", false
		}
		return net.JoinHostPort(s, "587"), true
	}
	if strings.TrimSpace(host) == "" || strings.TrimSpace(port) == "" {
		return "", false
	}
	return net.JoinHostPort(strings.TrimSpace(host), strings.TrimSpace(port)), true
}

// classifyDialErr — отказ на УСТАНОВЛЕНИИ соединения.
//
// Имя, которого нет в системе имён, — настройка: оно не появится само. Всё
// прочее (узел не поднят, срок истёк, сеть недоступна) — временный отказ.
func classifyDialErr(addr string, err error) error {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return fmt.Errorf("%w: mail relay host %s does not resolve: %w", ErrMailMisconfigured, addr, err)
	}
	return fmt.Errorf("%w: dial mail relay %s: %w", ErrMailTransient, addr, err)
}

// classifyTLSErr — отказ проверки сертификата узла. Временем не лечится:
// сертификат, не сходящийся с объявленным якорем, не сойдётся и завтра.
func classifyTLSErr(addr string, err error) error {
	var certErr *tls.CertificateVerificationError
	var unknownAuthority x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	if errors.As(err, &certErr) || errors.As(err, &unknownAuthority) || errors.As(err, &hostErr) {
		return fmt.Errorf("%w: mail relay %s presented a certificate we do not trust: %w",
			ErrMailMisconfigured, addr, err)
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return fmt.Errorf("%w: TLS handshake with mail relay %s did not finish in time: %w",
			ErrMailTransient, addr, err)
	}
	// Узел, не говорящий по TLS там, где мы его об этом просим, — настройка.
	return fmt.Errorf("%w: TLS with mail relay %s failed: %w", ErrMailMisconfigured, addr, err)
}

// classifyProtocolErr — ответ по объявленному адресу НЕ РАЗБИРАЕТСЯ как SMTP.
//
// Это доказательство того, что по адресу не тот эндпоинт, — то есть настройка, а
// не сбой (§Hardening п. 8, дословно: «ответ, доказывающий, что по
// адресу не тот эндпоинт, — это настройка»). Отдельно оговорено: срок истёк —
// это МОЛЧАНИЕ узла, и оно временно.
func classifyProtocolErr(addr string, err error) error {
	if isTimeout(err) {
		return fmt.Errorf("%w: mail relay %s accepted the connection and said nothing within the attempt deadline: %w",
			ErrMailTransient, addr, err)
	}
	var protoErr textproto.ProtocolError
	if errors.As(err, &protoErr) {
		return fmt.Errorf("%w: the address %s does not speak SMTP: %w", ErrMailMisconfigured, addr, err)
	}
	return classifySMTPErr(addr, "greeting", err)
}

// classifySMTPErr — отказ, названный самим узлом.
//
// Постоянный отказ узла (5xx) временем не лечится — это настройка. Временный
// (4xx) лечится. Молчание — временное. Корзины «прочее» нет: неназванный отказ
// считается временным ОСОЗНАННО, потому что повтор безопаснее отравления, и это
// решение, а не умолчание.
func classifySMTPErr(addr, stage string, err error) error {
	if isTimeout(err) {
		return fmt.Errorf("%w: mail relay %s went silent at %s within the attempt deadline: %w",
			ErrMailTransient, addr, stage, err)
	}
	var protoErr textproto.ProtocolError
	if errors.As(err, &protoErr) {
		return fmt.Errorf("%w: the address %s does not speak SMTP (at %s): %w",
			ErrMailMisconfigured, addr, stage, err)
	}
	var tpErr *textproto.Error
	if errors.As(err, &tpErr) {
		if tpErr.Code >= 500 && tpErr.Code < 600 {
			return fmt.Errorf("%w: mail relay %s permanently refused at %s: %w",
				ErrMailMisconfigured, addr, stage, err)
		}
		return fmt.Errorf("%w: mail relay %s temporarily refused at %s: %w",
			ErrMailTransient, addr, stage, err)
	}
	return fmt.Errorf("%w: mail relay %s failed at %s: %w", ErrMailTransient, addr, stage, err)
}

// isTimeout — истёк ли срок ПОПЫТКИ, чем бы он ни был выражен: контекстом или
// абсолютным сроком на соединении.
func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return errors.Is(err, net.ErrClosed)
}

// ClassifyInviteMailOutcome раскладывает исход одной попытки по ЗАКРЫТОМУ набору
// клеток.
//
// nil — сдано. Прочее приходит завёрнутым в одну из двух сигнальных ошибок:
// каждая ветка возврата транспорта заворачивает свой отказ явно, поэтому
// неклассифицированного отказа НАШ отправитель не производит. Неназванный отказ
// (он мог бы прийти от чужого транспорта в пробе) считается ВРЕМЕННЫМ осознанно:
// повтор безопаснее отравления.
func ClassifyInviteMailOutcome(err error) string {
	switch {
	case err == nil:
		return InviteMailOutcomeSent
	case errors.Is(err, ErrMailMisconfigured):
		return InviteMailOutcomeMisconfigured
	default:
		return InviteMailOutcomeTransient
	}
}

// senderDomain — домен адреса отправителя: им представляемся узлу (EHLO) и в
// нём чеканим `Message-ID`. ОДИН предикат на оба места: адрес, который уходит
// в MAIL FROM, и домен штампа письма берутся из одного значения.
//
// Домена нет либо он не годится в правую часть msg-id (RFC 5322 §3.6.4:
// dot-atom без пробелов, скобок и пустых меток) — ok=false. Молчаливого
// `localhost` нет: узел вправе отвергнуть такое приветствие, а `Message-ID` в
// чужом домене отличать письма не обязан, — это настройка, и решает её оператор.
func senderDomain(from string) (string, bool) {
	addr := addressOnly(from)
	at := strings.LastIndex(addr, "@")
	if at < 0 {
		return "", false
	}
	domain := addr[at+1:]
	if domain == "" || strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") ||
		strings.Contains(domain, "..") {
		return "", false
	}
	for i := 0; i < len(domain); i++ {
		if !isDomainByte(domain[i]) {
			return "", false
		}
	}
	return domain, true
}

// isDomainByte — байт, допустимый в dot-atom правой части msg-id: atext
// RFC 5322 §3.2.3, точка и восьмибитные байты UTF-8 (RFC 6532). Управляющих,
// пробелов и `<>@[]` в нём нет — значит, и CRLF в заголовок через домен не
// попадает.
func isDomainByte(c byte) bool {
	switch {
	case c >= 0x80, c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	return strings.IndexByte(".!#$%&'*+-/=?^_`{|}~", c) >= 0
}

// letterStamp — штамп отправки письма (kaname#630): момент и идентификатор.
// RFC 5322 требует `Date` у каждого письма; `Message-ID` — то, по чему адресат и
// промежуточные узлы отличают одно письмо от другого. Ставит его ТОЛЬКО
// отправитель (stamp): момент — от его часов, идентификатор — из
// криптографически стойкого источника, в домене отправителя.
type letterStamp struct {
	date      time.Time
	messageID string
	// domain — домен отправителя, в котором отчеканен messageID; им же
	// отправитель представляется узлу.
	domain string
}

// stamp чеканит штамп одного письма. Отказ — по НАСТРОЙКЕ: без домена
// отправителя `Message-ID` чеканить негде, и письмо без него не уходит.
//
// Левая часть `Message-ID` — 128 случайных бит (`crypto/rand.Text`) и ничего
// сверх: заголовок видят адресат и каждый промежуточный узел, поэтому в нём нет
// ни адреса получателя, ни строки человека, ни аккаунта, ни кода, ни строки
// очереди. Повтор попытки чеканит новый штамп: принятое узлом письмо повторно
// не сдаётся (MAIL-53), так что два письма с одним идентификатором не уходят.
func (s *InviteMailSender) stamp() (letterStamp, error) {
	domain, ok := senderDomain(s.relay.From)
	if !ok {
		return letterStamp{}, fmt.Errorf("%w: mail headers: sender address has no domain "+
			"(invite-mail.from) — Message-ID is minted in the sender domain, "+
			"and there is no built-in default for it", ErrMailMisconfigured)
	}
	return letterStamp{
		date:      s.now(),
		messageID: "<" + rand.Text() + "@" + domain + ">",
		domain:    domain,
	}, nil
}

// addressOnly снимает отображаемое имя: `Kachō <a@b>` → `a@b`.
func addressOnly(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndex(s, "<"); i >= 0 {
		if j := strings.Index(s[i:], ">"); j > 0 {
			return strings.TrimSpace(s[i+1 : i+j])
		}
	}
	return s
}

// RenderMail — письмо целиком по виду события, со штампом отправки, который
// поставил бы отправитель с часами по умолчанию (NewInviteMailSender). Вид
// неизвестный применитель до транспорта не доводит (постоянный отказ), поэтому
// здесь исходов два.
//
// Адрес отправителя без домена — nil: письма без штампа не бывает, и отдавать
// его нельзя даже для осмотра. Отправка судит тот же отказ сама (Send).
func RenderMail(relay MailRelay, ev MailEvent) []byte {
	return renderStamped(relay, ev, renderMail)
}

// renderStamped — сборка письма для осмотра: штамп ставит отправитель по
// умолчанию, отказ штампа — nil.
func renderStamped(relay MailRelay, ev MailEvent, render func(MailRelay, MailEvent, letterStamp) []byte) []byte {
	stamp, err := NewInviteMailSender(relay).stamp()
	if err != nil {
		return nil
	}
	return render(relay, ev, stamp)
}

// renderMail — письмо по виду события с данным штампом.
func renderMail(relay MailRelay, ev MailEvent, stamp letterStamp) []byte {
	switch ev.Kind {
	case EventRecoveryMailSend:
		return renderRecoveryMail(relay, ev, stamp)
	case EventVerificationMailSend:
		return renderVerificationMail(relay, ev, stamp)
	default:
		return renderInviteMail(relay, ev, stamp)
	}
}

// letterAddress — адрес, который несёт письмо любого вида: происхождение и
// путь, БЕЗ параметров и фрагмента (kaname#456). Письмо не несёт
// предъявителя, и адрес не становится местом, куда его можно положить: ни
// значение из очереди, ни ошибка настройки не доведут до письма адрес с `?` или
// `#`. Неразбираемый либо без происхождения — пусто: письмо тогда без адреса,
// а не с адресом, которого установка не объявляла.
func letterAddress(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path}).String()
}

// verificationScreenAddress — адрес экрана подтверждения: происхождение адреса
// входа, объявленного настройкой установки, и путь экрана, — без параметров и
// фрагмента. Адрес входа не объявлен либо не разбирается как адрес с
// происхождением — пусто: письмо тогда несёт код и срок без адреса, а не адрес,
// которого установка не объявляла.
func verificationScreenAddress(loginURL string) string {
	u, err := url.Parse(strings.TrimSpace(loginURL))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: VerificationScreenPath}).String()
}

// RenderVerificationMail собирает тело письма подтверждения адреса (kaname#456,
// Р8).
//
// Письмо несёт КОД, его срок в минутах и адрес экрана подтверждения — и ничего
// сверх. Кода в адресе нет: адрес ведёт на экран, код вводится руками, — так
// устроены и письма восстановления и приглашения, и письмо, действующее одним
// нажатием, приучало бы нажимать на ссылки о своей учётной записи.
//
// Штамп — как у RenderMail; адрес отправителя без домена — nil.
func RenderVerificationMail(relay MailRelay, ev MailEvent) []byte {
	return renderStamped(relay, ev, renderVerificationMail)
}

func renderVerificationMail(relay MailRelay, ev MailEvent, stamp letterStamp) []byte {
	subject := "Код подтверждения адреса"
	if relay.FromName != "" {
		subject = "Код подтверждения адреса — " + relay.FromName
	}
	b := mailHeaders(relay, ev, subject, stamp)
	b.WriteString("Подтвердите адрес почты, чтобы продолжить работу.\r\n")
	b.WriteString("\r\n")
	b.WriteString("Код подтверждения:\r\n")
	b.WriteString("\r\n")
	b.WriteString("    " + ev.Code + "\r\n")
	b.WriteString("\r\n")
	if ev.CodeValidMinutes > 0 {
		fmt.Fprintf(b, "Код действует %d мин. с момента отправки и применяется один раз.\r\n", ev.CodeValidMinutes)
	} else {
		b.WriteString("Код применяется один раз.\r\n")
	}
	if screen := verificationScreenAddress(relay.LoginURL); screen != "" {
		b.WriteString("Введите его на экране подтверждения: " + screen + "\r\n")
	} else {
		b.WriteString("Введите его на экране подтверждения адреса.\r\n")
	}
	b.WriteString("\r\n")
	b.WriteString("Никому не сообщайте этот код. Если вы не регистрировались — не вводите его нигде и не\r\n")
	b.WriteString("отвечайте на это письмо: без кода адрес не подтвердится.\r\n")
	return []byte(b.String())
}

// mailHeaders — общая шапка всех видов: штамп отправки (момент и
// идентификатор, kaname#630), отправитель, получатель, тема, кодировка.
// Заголовки код не несут — он только в теле. Штамп обязателен параметром: шапки
// без `Date` и `Message-ID` эта функция не собирает.
//
// `Date` — в форме RFC 5322 §3.3 (`time.RFC1123Z`) и в UTC: момент письма не
// сообщает часового пояса узла, на котором служба работает.
func mailHeaders(relay MailRelay, ev MailEvent, subject string, stamp letterStamp) *strings.Builder {
	from := addressOnly(relay.From)
	displayFrom := from
	if relay.FromName != "" {
		displayFrom = fmt.Sprintf("%s <%s>", relay.FromName, from)
	}
	var b strings.Builder
	b.WriteString("Date: " + stamp.date.UTC().Format(time.RFC1123Z) + "\r\n")
	b.WriteString("Message-ID: " + stamp.messageID + "\r\n")
	b.WriteString("From: " + displayFrom + "\r\n")
	b.WriteString("To: " + addressOnly(ev.To) + "\r\n")
	b.WriteString("Subject: " + mimeEncodedHeader(subject) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	b.WriteString("Content-Transfer-Encoding: 8bit\r\n")
	b.WriteString("\r\n")
	return &b
}

// RenderRecoveryMail собирает тело письма восстановления доступа (Ф5 Р3).
//
// Письмо несёт КОД и его срок — и ничего сверх: ни ссылки-предъявителя (полоса
// кодовая, Ф5 §1.2), ни утверждения «доставлено» (Р15 ID-MAIL-1 — продукт видит
// сдачу узлу, а не получение). Адрес консоли, если объявлен, стоит отдельной
// строкой и кода не несёт.
//
// Штамп — как у RenderMail; адрес отправителя без домена — nil.
func RenderRecoveryMail(relay MailRelay, ev MailEvent) []byte {
	return renderStamped(relay, ev, renderRecoveryMail)
}

func renderRecoveryMail(relay MailRelay, ev MailEvent, stamp letterStamp) []byte {
	loginURL := ev.LoginURL
	if loginURL == "" {
		loginURL = relay.LoginURL
	}
	loginURL = letterAddress(loginURL)
	subject := "Код восстановления доступа"
	product := "облаку"
	if relay.FromName != "" {
		subject = "Код восстановления доступа — " + relay.FromName
		product = relay.FromName
	}
	b := mailHeaders(relay, ev, subject, stamp)
	b.WriteString("Кто-то — возможно, вы — запросил восстановление доступа к " + product + ".\r\n")
	b.WriteString("\r\n")
	b.WriteString("Код восстановления:\r\n")
	b.WriteString("\r\n")
	b.WriteString("    " + ev.Code + "\r\n")
	b.WriteString("\r\n")
	if ev.CodeValidMinutes > 0 {
		fmt.Fprintf(b, "Код действует %d мин. с момента отправки и применяется один раз.\r\n", ev.CodeValidMinutes)
	} else {
		b.WriteString("Код применяется один раз.\r\n")
	}
	b.WriteString("Введите его вместе с новым паролем на странице восстановления.\r\n")
	if loginURL != "" {
		b.WriteString("\r\n")
		b.WriteString("Страница входа: " + loginURL + "\r\n")
	}
	b.WriteString("\r\n")
	b.WriteString("Если вы не запрашивали восстановление — не вводите код нигде и не отвечайте\r\n")
	b.WriteString("на это письмо: без кода доступ к учётной записи не изменится.\r\n")
	return []byte(b.String())
}

// RenderInviteMail собирает тело письма.
//
// Письмо говорит об ОТПРАВКЕ и НИГДЕ не говорит «доставлено»: продукт видит
// сдачу ретранслятору, а не получение адресатом, и утверждать второе значило бы
// обещать то, чего он не знает (Р15).
//
// Предъявителя письмо НЕ несёт (Р24): в нём призыв и адрес страницы входа, а
// доступ даёт владение почтовым ящиком, доказанное подтверждением адреса.
//
// Штамп — как у RenderMail; адрес отправителя без домена — nil.
func RenderInviteMail(relay MailRelay, ev MailEvent) []byte {
	return renderStamped(relay, ev, renderInviteMail)
}

func renderInviteMail(relay MailRelay, ev MailEvent, stamp letterStamp) []byte {
	loginURL := ev.LoginURL
	if loginURL == "" {
		loginURL = relay.LoginURL
	}
	loginURL = letterAddress(loginURL)
	// ИМЯ ПРИГЛАШАЮЩЕГО — отображаемое имя отправителя, и другого источника у
	// письма нет. Литерал с именем платформы стоял здесь, пока служба была её
	// частью; отдельным продуктом в ЧУЖОМ облаке он сообщает приглашённому имя,
	// которого тот не покупал. Своим именем службы его тоже не заменить:
	// приглашают работать не в управление доступом, а в облако (#2076).
	//
	// Имя не задано — письмо не называет НИКАКОГО продукта: неверное имя хуже,
	// чем никакого, а решение «настоящее письмо или обман» приглашённый
	// принимает именно по узнаваемости отправителя.
	subject := "Приглашение"
	invitedTo := "Вас пригласили работать в облаке."
	if relay.FromName != "" {
		subject = "Приглашение в " + relay.FromName
		invitedTo = "Вас пригласили работать в " + relay.FromName + "."
	}

	b := mailHeaders(relay, ev, subject, stamp)
	b.WriteString(invitedTo + "\r\n")
	b.WriteString("\r\n")
	if loginURL != "" {
		b.WriteString("Войдите по адресу: " + loginURL + "\r\n")
		b.WriteString("\r\n")
	}
	// Почему письмо НЕ несёт ссылки-предъявителя, сказано адресату прямо: иначе
	// отсутствие ссылки читается как неисправность продукта.
	b.WriteString("Вход выполняется по вашему почтовому адресу — этому самому.\r\n")
	b.WriteString("Отдельной ссылки для входа письмо не содержит: доступ даёт\r\n")
	b.WriteString("владение почтовым ящиком, а не обладание этим письмом.\r\n")
	b.WriteString("\r\n")
	b.WriteString("Если вы не ожидали приглашения — просто не отвечайте на него.\r\n")
	// Тело завершается точкой на своей строке средствами транспорта; здесь
	// точку не ставим, иначе разговор оборвётся раньше времени.
	return []byte(b.String())
}

// mimeEncodedHeader кодирует заголовок с не-ASCII по RFC 2047: узлы и почтовые
// клиенты не обязаны принимать восьмибитные заголовки.
func mimeEncodedHeader(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return "=?UTF-8?B?" + base64.StdEncoding.EncodeToString([]byte(s)) + "?="
		}
	}
	return s
}

// DecodeMailEvent — drainer.Decoder, общий для обоих видов.
//
// Строка, не назвавшая адресата, нерастолковываема и повтором таковой не станет
// — это ПОСТОЯННЫЙ отказ, а не вечный ретрай. Условие закрыто и ограничением
// миграции, поэтому записать такую строку НЕЛЬЗЯ; проверка остаётся вторым
// рубежом, а не единственным. Требования ВИДА (код у письма восстановления)
// судит применитель: декодер вида не знает.
func DecodeMailEvent(payload []byte) (MailEvent, error) {
	var ev MailEvent
	if err := json.Unmarshal(payload, &ev); err != nil {
		return MailEvent{}, fmt.Errorf("%w: decode invite mail payload: %w", drainer.ErrPermanent, err)
	}
	if strings.TrimSpace(ev.To) == "" {
		return MailEvent{}, fmt.Errorf(
			"%w: invite mail payload names no recipient (no to)", drainer.ErrPermanent)
	}
	return ev, nil
}

// NewInviteMailApplier — drainer.Applier: сдаёт письмо узлу и раскладывает исход
// по закрытому набору клеток.
//
// ОТКАЗ ПО НАСТРОЙКЕ ВОЗВРАЩАЕТСЯ ПОСТОЯННЫМ (MAIL-33: «без бесконечных
// повторов»): строка отравляется, остаётся в очереди видимой и повторно
// исполнимой, когда настройку починят, — а не крутится вечно, изображая работу.
// Временный отказ ретраится: он лечится временем.
//
// Ни один исход не остаётся тихим: клетка ставится на КАЖДОЙ ветке возврата, и
// отказ по настройке пишется в журнал уровнем ошибки, а не предупреждения
// (§Hardening п. 8: настройка — громко, никогда тихим Warn).
func NewInviteMailApplier(
	transport InviteMailTransport, obs InviteMailObserver, logger *slog.Logger,
) drainer.Applier[MailEvent] {
	return func(ctx context.Context, eventType string, ev MailEvent) error {
		// Развилка по ВИДУ события, а не по «какое поле непусто»: вид — то, что
		// записал автор намерения. Неизвестный вид — постоянный отказ; корзины
		// «прочее» здесь нет. Каждая ветвь — принятый вид; гейт
		// `TestEveryMailKindHasExactlyOneSender` сверяет их со словарём схемы.
		switch eventType {
		case EventInviteMailSend:
		case EventRecoveryMailSend:
			if strings.TrimSpace(ev.Code) == "" {
				// Письмо восстановления без кода не восстанавливает ничего, и
				// повтор этого не изменит: постоянный отказ, транспорт не зовётся.
				return fmt.Errorf("%w: recovery mail row carries no code", drainer.ErrPermanent)
			}
		case EventVerificationMailSend:
			if strings.TrimSpace(ev.Code) == "" {
				// Письмо подтверждения без кода не подтверждает ничего: постоянный
				// отказ, транспорт не зовётся.
				return fmt.Errorf("%w: verification mail row carries no code", drainer.ErrPermanent)
			}
		default:
			return fmt.Errorf("%w: unknown mail event type %q", drainer.ErrPermanent, eventType)
		}
		ev.Kind = eventType

		err := transport.Send(ctx, ev)
		outcome := ClassifyInviteMailOutcome(err)
		if obs != nil {
			obs.IncInviteMailOutcome(outcome)
		}
		if err == nil {
			return nil
		}
		if logger != nil {
			// Настройка — громко и отдельным текстом; сбой — предупреждением.
			// Различие здесь то же, что и в клетке счётчика: недоступность
			// проходит со временем, неверный адрес — никогда.
			if outcome == InviteMailOutcomeMisconfigured {
				logger.Error("mail is not deliverable: the mail lane is misconfigured",
					"err", err, "outcome", outcome, "kind", eventType, "account_id", ev.AccountID)
			} else {
				logger.Warn("mail delivery attempt failed",
					"err", err, "outcome", outcome, "kind", eventType, "account_id", ev.AccountID)
			}
		}
		if outcome == InviteMailOutcomeMisconfigured {
			return fmt.Errorf("%w: %w", drainer.ErrPermanent, err)
		}
		return err
	}
}
