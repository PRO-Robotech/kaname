// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package totpverify — проверяющий одноразового кода по времени (RFC 6238)
// и чеканка его секрета (фаза Ф12, задача PRO-Robotech/kacho#1281; приёмка
// `docs/engineering/acceptance/second-factor-totp-and-recovery-codes.md`, Р2, Р5).
//
// # Параметры — контракт, а не ручки (Р5)
//
// SHA-1, шесть цифр, шаг 30 с, секрет 20 байт (RFC 4226 §4: не короче 128 бит;
// 160 — размер выхода SHA-1), окно ±1 шаг. Это то, что понимает каждое
// приложение-аутентификатор без настройки; SHA-256 и восемь цифр «сильнее» и
// не поддерживаются частью приложений — человек с таким приложением не завёл бы
// фактор никогда. Окно ±2 — вдвое дешевле подбор ради часов, отстающих на
// минуту. Ручек у величин нет намеренно: значение, которое задают и не читают.
//
// # Почему весь материал живёт в ОДНОМ файле
//
// Секрет лежит в строке способа входа ОБЁРНУТЫМ (`internal/keywrap`, AES-256-GCM
// под своим перечнем ключей — Р2) внутри типа `domain.LoginVerifier`, выход у
// которого один — `Reveal`. Его вызывающих держит гейт дерева `internal/check`
// `TestLoginVerifierStaysInside`: разрешение дано ФАЙЛУ с причиной. Оттого
// снятие обёртки, вычисление HMAC и сравнение стоят здесь; наружу уходят только
// ИСХОД и ЧИСЛО (ступень принятого кода). Секрет в памяти — тип `Secret`, который
// не печатается и не сериализуется; клиенту он уходит один раз, ответом
// заведения, через `Base32` и `OtpauthURI`.
//
// # Порядок внутри проверки — несущий
//
// Материал есть? → обёртка открывается? → HMAC по трём ступеням окна →
// сравнение постоянным временем → повтор?
//
// «Материала нет» — ХОЛОСТАЯ сверка над неизменным холостым секретом той же
// длины (Р5, Ф12-33): иначе время ответа на «неверный пароль + код» выдавало бы,
// заведён ли фактор, тому, кто пароля не знает. «Обёртка не открывается» — НЕ
// отказ предъявителя, а недоступность (Р2, Ф12-35): человек предъявил верный
// код, а служба его не смогла сверить; наружу — 503 фиксированным текстом, в
// счёт попыток не идёт. Сравниваются ВСЕ три ступени окна, без остановки на
// первой совпавшей, каждое — постоянным временем. Повтор судится ПОСЛЕ
// совпадения по последнему принятому шагу СТРОКИ (не сессии): код шага не
// старше принятого — «повторён», снаружи неотличим от «не подошёл» (F4d-17);
// различает только клетка счётчика. Записывает шаг не проверяющий —
// вызывающий, условным оператором и только при полном успехе (Р5): здесь
// только суждение.
package totpverify

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- RFC 6238 в параметрах по умолчанию: SHA-1 — контракт приложений-аутентификаторов, не выбор
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/keywrap"
)

// Величины-контракты (Р5). Ручками не являются.
const (
	// SecretBytes — 20 байт случайности секрета.
	SecretBytes = 20
	// Digits — шесть цифр кода.
	Digits = 6
	// Period — шаг 30 секунд.
	Period = 30 * time.Second
	// Skew — окно расхождения часов: ±1 шаг.
	Skew = 1
	// Algorithm — как его печатают приложения-аутентификаторы.
	Algorithm = "SHA1"
)

// digitsModulus — 10^Digits.
const digitsModulus = 1000000

// secretRedacted — заглушка на всяком общем пути вывода секрета.
const secretRedacted = "[redacted totp secret]" // #nosec G101 -- текст заглушки, которым секрет ЗАМЕНЯЕТСЯ в выводе; самим секретом не является

// Secret — секрет кода по времени в памяти процесса. Не печатается, не
// сериализуется; клиенту уходит ответом заведения через `Base32`.
type Secret struct {
	box *secretBox
}

type secretBox struct {
	raw []byte
}

// NewSecret — свежий секрет из криптографического источника случайности.
func NewSecret() (Secret, error) {
	raw := make([]byte, SecretBytes)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return Secret{}, fmt.Errorf("totp secret: random source: %w", err)
	}
	return Secret{box: &secretBox{raw: raw}}, nil
}

// IsZero — секрета нет.
func (s Secret) IsZero() bool { return s.box == nil || len(s.box.raw) == 0 }

// Base32 — секрет в записи, которую принимают приложения-аутентификаторы:
// base32 без дополнения. ЕДИНСТВЕННЫЙ выход значения к клиенту.
func (s Secret) Base32() string {
	if s.box == nil {
		return ""
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(s.box.raw)
}

// String — заглушка.
func (s Secret) String() string { return secretRedacted }

// GoString — заглушка и для `%#v`.
func (s Secret) GoString() string { return "totpverify.Secret{" + secretRedacted + "}" }

// Format — заглушка на любом глаголе форматирования.
func (s Secret) Format(f fmt.State, verb rune) {
	if verb == 'v' && f.Flag('#') {
		_, _ = io.WriteString(f, s.GoString())
		return
	}
	_, _ = io.WriteString(f, secretRedacted)
}

// LogValue — заглушка для журнала.
func (s Secret) LogValue() slog.Value { return slog.StringValue(secretRedacted) }

// MarshalJSON — отказ.
func (s Secret) MarshalJSON() ([]byte, error) {
	return nil, fmt.Errorf("totp secret is not serializable")
}

// MarshalText — отказ.
func (s Secret) MarshalText() ([]byte, error) {
	return nil, fmt.Errorf("totp secret is not serializable")
}

// OtpauthURI — адрес для приложения-аутентификатора (Р5): домен посадки и адрес
// человека — метка записи, домен — издатель; параметры — контракт выше.
func OtpauthURI(domain, address string, s Secret) string {
	// Порядок параметров — как в приёмке (Ф12-01): secret, issuer, algorithm,
	// digits, period; `url.Values` сортирует ключи, поэтому строка собирается
	// вручную, значения экранируются.
	label := url.PathEscape(domain + ":" + address)
	return "otpauth://totp/" + label + "?secret=" + url.QueryEscape(s.Base32()) +
		"&issuer=" + url.QueryEscape(domain) + "&algorithm=" + Algorithm +
		"&digits=" + fmt.Sprint(Digits) + "&period=" + fmt.Sprint(int64(Period/time.Second))
}

// StepAt — ступень кода по часам вызывающего (форма Ф-ж).
func StepAt(at time.Time) int64 { return at.Unix() / int64(Period/time.Second) }

// IsWellFormedCode — форма кода по способу (Н12): ровно шесть ASCII-цифр.
// Судится ДО сверки транспортом: малоформенный код — отказ формы с именем
// поля, не попытка.
func IsWellFormedCode(code string) bool {
	if len(code) != Digits {
		return false
	}
	for i := 0; i < len(code); i++ {
		if code[i] < '0' || code[i] > '9' {
			return false
		}
	}
	return true
}

// Outcome — исход одной сверки. Перечень закрыт: клетки счётчика вызывающего
// заводятся по нему нулём до первого события (Ф12-43).
type Outcome string

const (
	OutcomeMatched            Outcome = "matched"
	OutcomeMismatched         Outcome = "mismatched"
	OutcomeReplayed           Outcome = "replayed"
	OutcomeMaterialMissing    Outcome = "material-missing"
	OutcomeMaterialUnreadable Outcome = "material-unreadable"
)

// OutcomeNames — закрытый перечень имён исходов.
func OutcomeNames() []string {
	return []string{
		string(OutcomeMatched), string(OutcomeMismatched), string(OutcomeReplayed),
		string(OutcomeMaterialMissing), string(OutcomeMaterialUnreadable),
	}
}

// Result — исход сверки. Материала не несёт: наружу уходят исход и ступень
// предъявленного кода (число), по которой вызывающий пишет принятый шаг.
type Result struct {
	Outcome Outcome
	// Step — ступень совпавшего кода; осмысленна только при OutcomeMatched.
	Step int64
}

// LastAccepted — последний принятый шаг строки: «шага ещё не было» отличимо
// от значения (нулевая ступень — законная величина оси).
type LastAccepted struct {
	step  int64
	known bool
}

// NoAcceptedStep — шага у строки ещё не было (строка только что подтверждена
// без записи либо `pending`).
func NoAcceptedStep() LastAccepted { return LastAccepted{} }

// AcceptedStep — последний принятый шаг известен.
func AcceptedStep(step int64) LastAccepted { return LastAccepted{step: step, known: true} }

// Verifier — проверяющий кода по времени: обёртка под своим перечнем ключей и
// холостой секрет для полосы «материала нет».
//
// Клеток счётчика у проверяющего нет: исход по способу × исходу считает
// ВЫЗЫВАЮЩИЙ (полоса — `humansession`, Ф12-43), у которого известен способ;
// второе семейство клеток здесь было бы вторым местом об одном предмете.
type Verifier struct {
	wrapper *keywrap.Wrapper
	decoy   []byte
}

// New — проверяющий. Обёртка обязательна: без неё секрет нечем открыть.
func New(wrapper *keywrap.Wrapper) (*Verifier, error) {
	if wrapper == nil {
		return nil, fmt.Errorf("totp verifier: key wrapper required — a stored secret cannot be opened without one")
	}
	decoy := make([]byte, SecretBytes)
	if _, err := io.ReadFull(rand.Reader, decoy); err != nil {
		return nil, fmt.Errorf("totp verifier: decoy: %w", err)
	}
	return &Verifier{wrapper: wrapper, decoy: decoy}, nil
}

// Wrap — секрет обёрнут первым ключом перечня и упакован в тип строки способа;
// материал — base64 обёртки (текстовая колонка).
func (v *Verifier) Wrap(s Secret) (domain.LoginVerifier, error) {
	if s.IsZero() {
		return domain.LoginVerifier{}, fmt.Errorf("totp verifier: nothing to wrap")
	}
	wrapped, err := v.wrapper.Wrap(s.box.raw)
	if err != nil {
		return domain.LoginVerifier{}, fmt.Errorf("totp verifier: %w", err)
	}
	return domain.NewLoginVerifier(base64.RawStdEncoding.EncodeToString(wrapped))
}

// Verify — сверка предъявленного кода с хранимым секретом на момент at.
//
// Исход о повторе судится по last — последнему принятому шагу СТРОКИ; запись
// шага остаётся за вызывающим (условным оператором, при полном успехе).
func (v *Verifier) Verify(stored domain.LoginVerifier, last LastAccepted, code string, at time.Time) Result {
	if stored.IsZero() {
		// Холостая сверка над неизменным холостым секретом: та же работа, тот
		// же путь; исход выбрасывается.
		_, _ = matchWindow(v.decoy, code, at)
		return Result{Outcome: OutcomeMaterialMissing}
	}
	raw, err := base64.RawStdEncoding.DecodeString(stored.Reveal())
	if err != nil {
		return Result{Outcome: OutcomeMaterialUnreadable}
	}
	secret, err := v.wrapper.Unwrap(raw)
	if err != nil {
		// Ни один ключ перечня не открыл: недоступность, а не отказ предъявителя.
		return Result{Outcome: OutcomeMaterialUnreadable}
	}
	step, ok := matchWindow(secret, code, at)
	if !ok {
		return Result{Outcome: OutcomeMismatched}
	}
	if last.known && step <= last.step {
		return Result{Outcome: OutcomeReplayed, Step: step}
	}
	return Result{Outcome: OutcomeMatched, Step: step}
}

// matchWindow — код против ступеней t−Skew…t+Skew по часам at. Сравниваются
// ВСЕ ступени окна постоянным временем; совпадение — ступень предъявленного.
func matchWindow(secret []byte, code string, at time.Time) (int64, bool) {
	if !IsWellFormedCode(code) {
		// Форму судит транспорт; здесь — та же цена, что у сверки, и «не
		// подошёл», чтобы вызывающий мимо транспорта не получил иного исхода.
		code = "------"
	}
	t := StepAt(at)
	var (
		matched int64
		found   bool
	)
	for d := int64(-Skew); d <= Skew; d++ {
		step := t + d
		if step < 0 {
			continue
		}
		want := hotp(secret, step)
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			matched, found = step, true
		}
	}
	return matched, found
}

// hotp — RFC 4226 §5.3 над шагом, шесть цифр.
func hotp(secret []byte, step int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step)) // #nosec G115 -- ступень неотрицательна: вызывающий пропускает отрицательные
	mac := hmac.New(sha1.New, secret)
	_, _ = mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[off])&0x7f)<<24 | uint32(sum[off+1])<<16 | uint32(sum[off+2])<<8 | uint32(sum[off+3])
	return fmt.Sprintf("%0*d", Digits, bin%digitsModulus)
}
