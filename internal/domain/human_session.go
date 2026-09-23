// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

// human_session.go — НАША сессия человека и её носитель (фаза Ф3, задача
// PRO-Robotech/kacho#1269; приёмка
// `docs/engineering/acceptance/login-lane-issues-our-session-and-logout-ends-it-server-side.md`,
// решения Р1, Р3, Р4, Р6, Р12).
//
// # Что такое сессия и что такое носитель — это РАЗНЫЕ предметы
//
// Сессия — ЗАПИСЬ с закрытым составом (Р1): субъект, момент аутентификации,
// момент последнего предъявления, срок, уровень уверенности, множество
// предъявленного. Требования сменить пароль в составе НЕТ (kacho#2697,
// kaname#201): восстановление задаёт пароль тем же обращением, что предъявляет
// код, и сессия появляется уже полноправной. Носитель — НЕПРОЗРАЧНОЕ значение
// у клиента: из него не читается ни субъект, ни момент, ни номер записи; он
// указывает на запись, и удостоверение — запись, а не он. Значение, которого
// хранилище не знает, обслуживается как отсутствие сессии.
//
// Единица отзыва — сессия, не носитель (Ф11 Р5): у одной сессии за время жизни
// бывает несколько носителей (перевыпуск при смене пароля), и снятие записи
// гасит все.
//
// # Почему носитель хранится ДАЙДЖЕСТОМ
//
// Хранилище знает не значение, а его свёртку: копия таблицы не даёт ни одного
// годного носителя, а сравнение при предъявлении — точное равенство свёрток,
// без ветвления по содержимому значения.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"time"
)

// HumanSessionID — идентификатор записи сессии. Наружу не выходит: клиент
// держит носитель, край получает субъекта и поля записи; номер записи не
// адресуется ничем внешним.
type HumanSessionID string

// SessionBearerBytes — длина случайной части носителя в байтах: 32 байта = 256
// бит, не меньше 128 требуемых (Ф3 §8 инв. 9). В URL-безопасном base64 без
// дополнения это 43 знака — не короче 22 требуемых (Ф3-08).
const SessionBearerBytes = 32

// sessionBearerRedacted — заглушка на всяком общем пути вывода носителя.
// #nosec G101 -- это ЗАМЕНА носителя в выводе, а не сам носитель: строка стоит
// там, где значение печатать запрещено.
const sessionBearerRedacted = "[redacted session bearer]"

// ErrSessionBearerNotSerializable — носитель не сериализуется ни в JSON, ни в
// текст: значение уходит клиенту одним путём — заголовком `Set-Cookie`, который
// пишет обработчик полосы, — и попасть в журнал либо в ответ иным путём не
// может.
var ErrSessionBearerNotSerializable = fmt.Errorf("session bearer is not serializable")

// SessionBearer — непрозрачное значение носителя (Р1). Тип не печатается и не
// сериализуется, как `LoginVerifier`; значение выходит ровно двумя методами:
// `Digest` (в хранилище) и `CookieValue` (клиенту).
type SessionBearer struct {
	box *sessionBearerBox
}

type sessionBearerBox struct {
	value string
}

// NewSessionBearer — свежий носитель из криптографического источника случайности.
func NewSessionBearer() (SessionBearer, error) {
	var raw [SessionBearerBytes]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return SessionBearer{}, fmt.Errorf("session bearer: random source: %w", err)
	}
	return SessionBearer{box: &sessionBearerBox{value: base64.RawURLEncoding.EncodeToString(raw[:])}}, nil
}

// PresentedSessionBearer — носитель, как его прислал клиент. Значение не
// разбирается: единственное, что с ним делают, — берут дайджест. Пустое —
// отсутствие носителя.
func PresentedSessionBearer(value string) SessionBearer {
	if value == "" {
		return SessionBearer{}
	}
	return SessionBearer{box: &sessionBearerBox{value: value}}
}

// IsZero — носителя нет.
func (b SessionBearer) IsZero() bool { return b.box == nil || b.box.value == "" }

// CookieValue — значение для `Set-Cookie`. Единственный выход к клиенту.
func (b SessionBearer) CookieValue() string {
	if b.box == nil {
		return ""
	}
	return b.box.value
}

// Digest — свёртка носителя, по которой хранилище находит запись. Хранится и
// сравнивается только она.
func (b SessionBearer) Digest() BearerDigest {
	if b.box == nil {
		return ""
	}
	sum := sha256.Sum256([]byte(b.box.value))
	return BearerDigest(hex.EncodeToString(sum[:]))
}

// String — заглушка.
func (b SessionBearer) String() string { return sessionBearerRedacted }

// GoString — заглушка и для `%#v`.
func (b SessionBearer) GoString() string {
	return "domain.SessionBearer{" + sessionBearerRedacted + "}"
}

// Format — заглушка на любом глаголе форматирования.
func (b SessionBearer) Format(f fmt.State, verb rune) {
	if verb == 'v' && f.Flag('#') {
		_, _ = io.WriteString(f, b.GoString())
		return
	}
	_, _ = io.WriteString(f, sessionBearerRedacted)
}

// LogValue — заглушка для журнала.
func (b SessionBearer) LogValue() slog.Value { return slog.StringValue(sessionBearerRedacted) }

// MarshalJSON — отказ.
func (b SessionBearer) MarshalJSON() ([]byte, error) { return nil, ErrSessionBearerNotSerializable }

// MarshalText — отказ.
func (b SessionBearer) MarshalText() ([]byte, error) { return nil, ErrSessionBearerNotSerializable }

// BearerDigest — свёртка носителя в хранилище (шестнадцатеричная запись
// SHA-256). Сама по себе носителем не является: обратно значение не
// восстанавливается.
type BearerDigest string

// assuranceLevelValues — закрытая ось уровня уверенности, как её объявила Ф11
// (`internal/assurance`): «1», «2», «3». Здесь она нужна проверке записи ДО
// базы; производитель значения — правило `assurance.LevelOf`, второго
// вычисления уровня в дереве нет (гейт `assurance_level_sole_writer`).
var assuranceLevelValues = []string{"1", "2", "3"}

// HumanSession — запись сессии (Р1). Состав закрыт: поле без читателя есть
// значение, которое пишут и не читают.
type HumanSession struct {
	ID     HumanSessionID
	UserID UserID
	// AuthenticatedAt — момент аутентификации. Неподвижен всю жизнь записи
	// (Ф11 Р6): край сравнивает его с отсечкой.
	AuthenticatedAt time.Time
	// LastPresentedAt — момент последнего ПРЕДЪЯВЛЕНИЯ СПОСОБА (сверка
	// пароля, кода, ключа), не носителя запросу. Читается внутри службы.
	LastPresentedAt time.Time
	// ExpiresAt — абсолютный срок, ОДИН (F4d-27): окна бездействия нет.
	ExpiresAt time.Time
	// AssuranceLevel — по правилу Ф11 от множества предъявленного.
	AssuranceLevel string
	// PresentedMethods — множество предъявленного (Ф11 Р2), слова словаря
	// `assurance.Methods`. Читается внутри службы правилом уровня.
	PresentedMethods []string
	// CreatedAt назначает запись.
	CreatedAt time.Time
}

// Validate — запись, годная к выдаче. Судится ДО базы то, что база держит
// ограничениями: уровень из оси, непустое множество, срок позже момента,
// последнее предъявление не раньше аутентификации.
func (s HumanSession) Validate() error {
	if s.ID == "" {
		return fmt.Errorf("Illegal argument human_session.id: required")
	}
	if s.UserID == "" {
		return fmt.Errorf("Illegal argument human_session.user_id: required")
	}
	if s.AuthenticatedAt.IsZero() {
		return fmt.Errorf("Illegal argument human_session.authenticated_at: required")
	}
	if s.LastPresentedAt.IsZero() || s.LastPresentedAt.Before(s.AuthenticatedAt) {
		return fmt.Errorf("Illegal argument human_session.last_presented_at: must not precede authenticated_at")
	}
	if !s.ExpiresAt.After(s.AuthenticatedAt) {
		return fmt.Errorf("Illegal argument human_session.expires_at: must follow authenticated_at")
	}
	levelKnown := false
	for _, l := range assuranceLevelValues {
		if s.AssuranceLevel == l {
			levelKnown = true
			break
		}
	}
	if !levelKnown {
		return fmt.Errorf("Illegal argument human_session.assurance_level: must be one of %v", assuranceLevelValues)
	}
	if len(s.PresentedMethods) == 0 {
		return fmt.Errorf("Illegal argument human_session.presented_methods: required")
	}
	for _, m := range s.PresentedMethods {
		if m == "" {
			return fmt.Errorf("Illegal argument human_session.presented_methods: empty method")
		}
	}
	return nil
}

// Expired — истёк ли срок на данный момент. Граница — включающая: в сам момент
// срока сессии уже нет.
func (s HumanSession) Expired(now time.Time) bool { return !now.Before(s.ExpiresAt) }

// Слова причин ДВУХ записей — одним объявлением (Ф3 Р4, Р6, Р9).
//
// Константы ниже служат двум словарям. Закрытый — причина СНЯТИЯ записи
// сессии: ограничение `human_sessions_ended_reason_check`, его перечень в
// домене — HumanSessionEndReasons. Открытый — причина ОТСЕЧКИ
// (`user_token_revocations.reason`, ограничена только длиной). Какой записи
// служит каждая константа, сказано у неё. Слово, которое пишут обе записи,
// объявлено один раз: второе написание разошлось бы с первым молча.
//
// `password-change` — ТО ЖЕ значение, что пишет существующий хук завершения
// восстановления (`internal/apps/kaname/api/user`). `logout` — своё: журнал
// обязан отличать выход от смены пароля (Ф1-63).
const (
	// RevokeReasonLogout — собственный выход человека: причина снятия его
	// записи сессии и причина отсечки.
	RevokeReasonLogout = "logout"
	// RevokeReasonPasswordChange — смена пароля и завершение восстановления:
	// причина снятия прочих записей сессии и причина отсечки.
	RevokeReasonPasswordChange = "password-change"
	// RevokeReasonSecondFactorRemoved — снятие второго фактора самим человеком
	// гасит ПРОЧИЕ его сессии (Ф12 Р9, kacho#1281): журнал отличает это от
	// выхода и от смены пароля. Причина снятия записи сессии.
	RevokeReasonSecondFactorRemoved = "second-factor-removed"
	// RevokeReasonSecondFactorReset — причина отсечки, которую пишет сброс
	// второго фактора распорядителем (Ф12 Р10): все сессии человека покрыты
	// отсечкой `now` существующим писателем принудительного выхода. В словарь
	// снятия сессии НЕ входит: ни одному снимающему методу она не передаётся.
	RevokeReasonSecondFactorReset = "second-factor-reset"
	// RevokeReasonAdminForceLogout — выход, произведённый распорядителем
	// (`InternalIAMService.ForceLogout`; kaname#334, приёмка
	// `forced-exit-has-its-own-session-end-reason.md`, Р1, Р3). Роли у слова
	// ДВЕ, и объявлено оно одно:
	//   - причина снятия НАШИХ записей сессии входа принудительным выходом.
	//     Это слово закрытого словаря, и из запроса оно не берётся (Р2):
	//     свободная причина распорядителя в запись сессии не идёт;
	//   - умолчание СВОБОДНОЙ причины отсечки и события, когда запрос
	//     причины не несёт. Совпадение намеренное: предмет у обеих записей
	//     один — принудительный выход.
	RevokeReasonAdminForceLogout = "admin-force-logout"
)

// HumanSessionEndReasons — перечень ЗАКРЫТОГО словаря причин снятия записи
// сессии: ровно те значения, что принимает `human_sessions_ended_reason_check`.
// Причина отсечки RevokeReasonSecondFactorReset в него не входит — она не
// снимает ни одной записи.
//
// Функция, а не переменная: каждый вызов отдаёт СВЕЖИЙ срез, и вызывающий,
// дописавший в него, словаря не меняет. Элементы — константы по имени, а не
// литералы: слово объявлено один раз. Совпадение перечня с ограничением базы в
// обе стороны держит проба KN-SER-07
// (`internal/migrations/human_session_forced_exit_reason_integration_test.go`).
func HumanSessionEndReasons() []string {
	return []string{
		RevokeReasonLogout,
		RevokeReasonPasswordChange,
		RevokeReasonSecondFactorRemoved,
		RevokeReasonAdminForceLogout,
	}
}

// FormKind — вид формы, к которому привязан признак защиты от подделки
// запроса (Р12). Перечень ЗАКРЫТ и объявлен один раз; Ф4 и Ф5 дописывают свои
// виды сюда, а не заводят второй перечень.
type FormKind string

const (
	FormLogin    FormKind = "login"
	FormLogout   FormKind = "logout"
	FormPassword FormKind = "password"
	// FormRegister — форма регистрации (Ф4 Р1; форма защищена признаком, как и
	// прочие, меняющие состояние, — Ф1-39…43).
	FormRegister FormKind = "register"
	// Восстановление доступа (Ф5, `kacho#1271`) — две формы, два вида: запрос
	// кода и его предъявление с новым паролем. Признак одной не годится другой
	// (Ф1 Р6): у них разные предметы и разные последствия.
	FormRecovery         FormKind = "recovery"
	FormRecoveryComplete FormKind = "recovery-complete"
	// Второй фактор (Ф12, `kacho#1281`, Р4): один вид на четыре глагола
	// семейства `second-factor/*` — у них один предмет (заведённый фактор
	// самого человека) — и свой вид у церемонии повышения: её зовут и без
	// фактора, ветвью пароля (Ф11-09), и признак семейства ей не годится.
	FormSecondFactor FormKind = "second-factor"
	FormStepUp       FormKind = "step-up"
)

var formKinds = []FormKind{FormLogin, FormLogout, FormPassword, FormRegister, FormRecovery, FormRecoveryComplete, FormSecondFactor, FormStepUp}

// FormKinds — закрытый перечень видов формы, копией.
func FormKinds() []FormKind {
	out := make([]FormKind, len(formKinds))
	copy(out, formKinds)
	return out
}

// ParseFormKind — вид формы из строки запроса; вне перечня — отказ, называющий
// поле и перечень.
func ParseFormKind(s string) (FormKind, error) {
	for _, k := range formKinds {
		if string(k) == s {
			return k, nil
		}
	}
	return "", fmt.Errorf("Illegal argument form: must be one of %v", formKinds)
}
