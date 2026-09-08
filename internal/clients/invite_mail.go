// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// invite_mail.go — НАШ отправитель письма приглашения.
//
// # Почему отправитель здесь, а не у поставщика личности
//
// Писем в продукте три вида, и производители у них РАЗНЫЕ (приёмка ID-MAIL-1,
// Р23): подтверждение адреса и восстановление доступа отправляет почтовый
// процесс поставщика — их предъявители принадлежат ему; приглашение отправляем
// МЫ, потому что предмет приглашения — наша строка в нашей базе, и о ней
// поставщик не знает ничего.
//
// # Что здесь лежит — три части одной цепочки
//
//   - InviteMailSender — транспорт: один разговор с почтовым узлом, СВОИМ
//     пределом времени ограниченный;
//   - DecodeInviteMail — Decoder[T] для общего дренажа;
//   - NewInviteMailApplier — Applier[T]: зовёт транспорт и раскладывает исход по
//     ЗАКРЫТОМУ набору клеток счётчика.
//
// # Две величины, и они РАЗНЫЕ
//
// Предел времени на ПОПЫТКУ (`MailRelay.AttemptTimeout`) и число ПОВТОРОВ
// (`drainer.Config.MaxAttempts`, композиционный корень) — разные величины с
// разными предметами. «Ограниченный повтор» без первой ограничивает ЧИСЛО
// попыток, каждая из которых вправе висеть вечно, — а это
// `architecture.md` §«Per-call deadline на КАЖДОМ внешнем вызове» в чистом виде.
// Наблюдаема первая только на узле, который ПРИНИМАЕТ соединение и молчит: на
// отказе в соединении обрыв даёт ядро, а не наша величина.
//
// # Настройка отделена от сбоя — собственной клеткой
//
// Недоступность узла лечится временем; ответ не по протоколу почты по
// объявленному адресу не лечится никогда. Схлопнуть их в один ряд значит сделать
// постоянную неверную настройку штатным режимом — `security.md` §Hardening п. 8.
// Поэтому клеток три, набор ЗАКРЫТ и приходит из констант, а не из ответа узла:
// иначе кардинальность росла бы с трафиком.
package clients

import (
	"context"
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
	"strings"
	"time"

	"github.com/PRO-Robotech/kacho/pkg/outbox/drainer"
)

const (
	// InviteMailTable — полное имя очереди писем приглашения. ШЕСТАЯ очередь
	// сервиса; форма не изобретается — она в дереве пятикратна.
	InviteMailTable = "kaname.invite_mail_outbox"
	// InviteMailChannel — LISTEN-канал (триггер миграции).
	InviteMailChannel = "kaname_invite_mail_outbox"
	// EventInviteMailSend — единственный вид события очереди. Словарь закрыт
	// CHECK'ом миграции: расширение требует и кода, и миграции.
	EventInviteMailSend = "mail.invite.send"
)

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

// InviteMailEvent — расшифрованная нагрузка одной строки очереди.
//
// Предъявителя здесь НЕТ и быть не должно (Р24): письмо приглашения несёт призыв
// и адрес страницы входа, а доступ даёт владение почтовым ящиком, доказанное
// подтверждением адреса у поставщика.
type InviteMailEvent struct {
	// To — адрес приглашённого. Единственная координата, без которой письмо
	// отправить некому.
	To string `json:"to"`
	// AccountID — аккаунт, в который приглашают. Атрибуция и тело письма.
	AccountID string `json:"account_id"`
	// UserID — строка приглашения. Атрибуция; отправка от неё не зависит.
	UserID string `json:"user_id"`
	// LoginURL — адрес страницы входа. Пусто → берётся из настройки установки.
	LoginURL string `json:"login_url,omitempty"`
}

// InviteMailObserver — писатель счётчика исходов отправки.
//
// Нужен, чтобы «ноль писем за всю жизнь очереди» было ЗАМЕТНО: без него мёртвый
// отправитель и здоровое облако, куда никто не приходил, выглядят одинаково —
// тихо (`data-integrity.md`, класс мёртвой очереди регистраций).
type InviteMailObserver interface {
	// IncInviteMailOutcome — исход одной попытки отправки; outcome — клетка из
	// InviteMailOutcomes.
	IncInviteMailOutcome(outcome string)
}

// InviteMailTransport — порт: то, что умеет сдать письмо почтовому узлу.
// Реализуется InviteMailSender; в пробах — подставным транспортом, который
// снисходительнее настоящего быть не вправе.
type InviteMailTransport interface {
	Send(ctx context.Context, ev InviteMailEvent) error
}

// InviteMailSender — транспорт поверх SMTP.
type InviteMailSender struct {
	relay MailRelay
}

// NewInviteMailSender конструирует транспорт. Величины НЕ проверяются здесь:
// вырожденная настройка обязана дать наблюдаемый исход `misconfigured` на
// попытке, а не тихий отказ конструирования, который никто не считает.
func NewInviteMailSender(relay MailRelay) *InviteMailSender {
	return &InviteMailSender{relay: relay}
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
func (s *InviteMailSender) Send(ctx context.Context, ev InviteMailEvent) error {
	relay := s.relay

	addr, ok := normalizedHostPort(relay.Addr)
	if !ok {
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

	if herr := client.Hello(localHelloName(relay.From)); herr != nil {
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
	if _, werr := w.Write(RenderInviteMail(relay, ev)); werr != nil {
		return fmt.Errorf("%w: write invite mail body to %s: %w", ErrMailTransient, addr, werr)
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

// normalizedHostPort приводит объявленный адрес к `host:port` и говорит, задан
// ли он ВООБЩЕ.
//
// Вырожденные значения — пустая строка, пробел, схема без узла, `:` и `:25` —
// считаются НЕЗАДАННЫМИ, а не «непустыми» (Р4). Предикат ОДИН на стража и на
// потребителя: разойдясь, они разойдутся ровно там, где расхождение опасно.
func normalizedHostPort(raw string) (string, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", false
	}
	// Схема, если её написали, снимается: `smtp://relay:587` → `relay:587`.
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		// Порт не назван — узел назван. Это законно: порт подставляем.
		if strings.TrimSpace(s) == "" || strings.Contains(s, ":") {
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
// не сбой (`security.md` §Hardening п. 8, дословно: «ответ, доказывающий, что по
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

// localHelloName — имя, которым мы представляемся узлу. Берётся из домена
// СВОЕГО адреса отправителя: узел вправе сверять его, а `localhost` многие
// ретрансляторы отвергают.
func localHelloName(from string) string {
	at := strings.LastIndex(addressOnly(from), "@")
	if at < 0 || at+1 >= len(addressOnly(from)) {
		return "localhost"
	}
	return addressOnly(from)[at+1:]
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

// RenderInviteMail собирает тело письма.
//
// Письмо говорит об ОТПРАВКЕ и НИГДЕ не говорит «доставлено»: продукт видит
// сдачу ретранслятору, а не получение адресатом, и утверждать второе значило бы
// обещать то, чего он не знает (Р15).
//
// Предъявителя письмо НЕ несёт (Р24): в нём призыв и адрес страницы входа, а
// доступ даёт владение почтовым ящиком, доказанное подтверждением адреса.
func RenderInviteMail(relay MailRelay, ev InviteMailEvent) []byte {
	loginURL := ev.LoginURL
	if loginURL == "" {
		loginURL = relay.LoginURL
	}
	from := addressOnly(relay.From)
	displayFrom := from
	if relay.FromName != "" {
		displayFrom = fmt.Sprintf("%s <%s>", relay.FromName, from)
	}

	var b strings.Builder
	b.WriteString("From: " + displayFrom + "\r\n")
	b.WriteString("To: " + addressOnly(ev.To) + "\r\n")
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

	b.WriteString("Subject: " + mimeEncodedHeader(subject) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	b.WriteString("Content-Transfer-Encoding: 8bit\r\n")
	b.WriteString("\r\n")
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

// DecodeInviteMail — drainer.Decoder.
//
// Строка, не назвавшая адресата, нерастолковываема и повтором таковой не станет
// — это ПОСТОЯННЫЙ отказ, а не вечный ретрай. Условие закрыто и ограничением
// миграции, поэтому записать такую строку НЕЛЬЗЯ; проверка остаётся вторым
// рубежом, а не единственным.
func DecodeInviteMail(payload []byte) (InviteMailEvent, error) {
	var ev InviteMailEvent
	if err := json.Unmarshal(payload, &ev); err != nil {
		return InviteMailEvent{}, fmt.Errorf("%w: decode invite mail payload: %w", drainer.ErrPermanent, err)
	}
	if strings.TrimSpace(ev.To) == "" {
		return InviteMailEvent{}, fmt.Errorf(
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
// (`security.md` §Hardening п. 8: настройка — громко, никогда тихим Warn).
func NewInviteMailApplier(
	transport InviteMailTransport, obs InviteMailObserver, logger *slog.Logger,
) drainer.Applier[InviteMailEvent] {
	return func(ctx context.Context, eventType string, ev InviteMailEvent) error {
		// Развилка по ВИДУ события, а не по «какое поле непусто»: вид — то, что
		// записал автор намерения. Неизвестный вид — постоянный отказ; корзины
		// «прочее» здесь нет.
		if eventType != EventInviteMailSend {
			return fmt.Errorf("%w: unknown invite mail event type %q", drainer.ErrPermanent, eventType)
		}

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
				logger.Error("invite mail is not deliverable: the mail lane is misconfigured",
					"err", err, "outcome", outcome, "account_id", ev.AccountID)
			} else {
				logger.Warn("invite mail delivery attempt failed",
					"err", err, "outcome", outcome, "account_id", ev.AccountID)
			}
		}
		if outcome == InviteMailOutcomeMisconfigured {
			return fmt.Errorf("%w: %w", drainer.ErrPermanent, err)
		}
		return err
	}
}
