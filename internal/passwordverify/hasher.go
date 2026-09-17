// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package passwordverify

// hasher.go — ХЕШЕР вновь заводимых значений (фаза Ф3, задача
// PRO-Robotech/kacho#1269; ID-PW-1 PWV-07 в части Ф3, PWV-16).
//
// Читает ручку «что писать» (`Declared`) — первый её читатель в прод-коде
// (PWV-07.2). Формат и параметры берутся из объявленного, а не выписываются:
// объявленное уже прошло стража старта (`Declared.Validate`: записываемость,
// пол, потолок), поэтому значение, которое хешер кладёт, читается проверяющим
// того же файла by construction.
//
// Материал НАРУЖУ уходит только упакованным в `domain.LoginVerifier` — тип, из
// которого его достаёт единственный выход `Reveal`, разрешённый двум файлам
// (гейт `TestLoginVerifierStaysInside`). Этот файл выхода не зовёт.

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math"
	"strings"

	"golang.org/x/crypto/argon2"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

const (
	// argon2idSaltLen — соль 16 байт: рекомендация RFC 9106.
	argon2idSaltLen = 16
	// argon2idKeyLen — тело 32 байта.
	argon2idKeyLen = 32
)

// Hasher — хешер объявленного формата.
type Hasher struct {
	declared Declared
}

// NewHasher — хешер с объявлением, уже прошедшим страж старта. Незаданное или
// негодное объявление отвергается ЗДЕСЬ тем же правилом (`Declared.Validate`),
// чтобы хешер, собранный мимо стража, не написал ни одного значения.
func NewHasher(declared Declared) (*Hasher, error) {
	if err := declared.Validate(); err != nil {
		return nil, fmt.Errorf("password_hasher: %w", err)
	}
	return &Hasher{declared: declared}, nil
}

// Declared — объявление, которым хешер пишет.
func (h *Hasher) Declared() Declared { return h.declared }

// Hash — значение объявленного формата для пароля. Пустой пароль отвергается:
// «пустого пароля» у полосы не бывает, правило пароля отвергает его раньше, и
// второе объявление здесь — только страховка от вызова мимо правила.
func (h *Hasher) Hash(password string) (domain.LoginVerifier, error) {
	if password == "" {
		return domain.LoginVerifier{}, fmt.Errorf("password_hasher: empty password")
	}
	switch h.declared.Format {
	case domain.PasswordHashFormatArgon2id:
		return h.hashArgon2id(password)
	default:
		// Перечень записываемых форматов — один (argon2id); bcrypt объявлен
		// только читаемым, и `Declared.Validate` его сюда не пропускает.
		return domain.LoginVerifier{}, fmt.Errorf("password_hasher: format %q is not writable", h.declared.Format)
	}
}

func (h *Hasher) hashArgon2id(password string) (domain.LoginVerifier, error) {
	memory := h.declared.Params[domain.CostParamArgon2Memory]
	iterations := h.declared.Params[domain.CostParamArgon2Iterations]
	parallelism := h.declared.Params[domain.CostParamArgon2Parallelism]
	if parallelism > math.MaxUint8 {
		return domain.LoginVerifier{}, fmt.Errorf("password_hasher: parallelism %d exceeds the library bound", parallelism)
	}
	salt := make([]byte, argon2idSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return domain.LoginVerifier{}, fmt.Errorf("password_hasher: random source: %w", err)
	}
	body := argon2.IDKey([]byte(password), salt, iterations, memory, uint8(parallelism), argon2idKeyLen)
	return domain.NewLoginVerifier(argon2idMaterial(memory, iterations, parallelism, salt, body))
}

// argon2idMaterial — разметка PHC объявленного формата из параметров, соли и
// тела. ЕДИНСТВЕННОЕ место, где она собирается: хешер пишет ею значения,
// калибровка огибающей строит ею синтетические (`envelope.go`); второе
// написание разошлось бы с проверяющим молча.
func argon2idMaterial(memory, iterations, parallelism uint32, salt, body []byte) string {
	return fmt.Sprintf("%s%sm=%d,t=%d,p=%d$%s$%s",
		argon2idMarkerPrefix, argon2idVersionPrefix, memory, iterations, parallelism,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(body))
}

// --- набор запасных кодов (Ф12 Р6, kacho#1281) ---
//
// Набор чеканится ТЕМ ЖЕ хешером по ТОЙ ЖЕ настройке «что писать»
// (ID-PW-1 PWV-16): формат и параметры — в значении, как у пароля; соль ОДНА на
// набор, по элементу на каждый код. Форма материала набора:
//
//	$argon2id$v=19$m=<КиБ>,t=<проходы>,p=<параллельность>$<соль>$,<э1>,<э2>,…,<эN>,
//
// Элементы стоят МЕЖДУ запятыми, запятая по краям: потребление одного кода —
// снятие `,<э>,` из значения одним оператором адаптера, и подстрока элемента
// элементом не является. Исчерпанный набор — одна запятая после соли.
//
// Быстрый хеш отвергнут: десять знаков Crockford — около 50 бит, держатель
// дампа восстанавливал бы код перебором офлайн за часы, тогда как секрет кода
// по времени в той же таблице обёрнут ровно против дампа. Соль на каждый код
// отвергнута: десять вычислений на предъявление — десятикратная ёмкость ради
// множителя 10 на переборе в ≥ 2⁴⁸ при цене медленного хеша.

// Величины-контракты набора (Р6). Ручками не являются: у величины нет
// владельца, кроме этой строки.
const (
	// BackupCodeCount — кодов в наборе.
	BackupCodeCount = 10
	// BackupCodeLength — знаков в коде; алфавит Crockford base32 (32 знака) —
	// 50 бит случайности на код.
	BackupCodeLength = 10
	// backupCodeAlphabet — Crockford base32: без I, L, O, U.
	backupCodeAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	// setElementSeparator — разделитель элементов набора в значении.
	setElementSeparator = ","
)

// NewBackupCodes — десять кодов по десять знаков алфавита без визуально
// смешиваемых знаков, из криптографического источника случайности.
func NewBackupCodes() ([]string, error) {
	codes := make([]string, 0, BackupCodeCount)
	seen := make(map[string]bool, BackupCodeCount)
	for len(codes) < BackupCodeCount {
		raw := make([]byte, BackupCodeLength)
		if _, err := rand.Read(raw); err != nil {
			return nil, fmt.Errorf("backup codes: random source: %w", err)
		}
		b := make([]byte, BackupCodeLength)
		for i, r := range raw {
			b[i] = backupCodeAlphabet[int(r)%len(backupCodeAlphabet)]
		}
		code := string(b)
		if seen[code] {
			continue // два равных кода в наборе — один код, а не два; перечеканить
		}
		seen[code] = true
		codes = append(codes, code)
	}
	return codes, nil
}

// IsWellFormedBackupCode — форма кода набора (Н12): ровно BackupCodeLength
// знаков алфавита Crockford, регистр букв безразличен. Судится ДО сверки
// транспортом: малоформенный код — отказ формы с именем поля, не попытка.
func IsWellFormedBackupCode(code string) bool {
	if len(code) != BackupCodeLength {
		return false
	}
	for i := 0; i < len(code); i++ {
		c := code[i]
		if c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		if !strings.ContainsRune(backupCodeAlphabet, rune(c)) {
			return false
		}
	}
	return true
}

// normalizeBackupCode — предъявленный код к форме чеканки: заглавные буквы.
func normalizeBackupCode(code string) string { return strings.ToUpper(code) }

// HashSet — материал набора кодов объявленным форматом: одна соль, по элементу
// на код. Каждый код обязан быть годной формы; пустой набор не чеканится.
func (h *Hasher) HashSet(codes []string) (domain.LoginVerifier, error) {
	if len(codes) == 0 {
		return domain.LoginVerifier{}, fmt.Errorf("backup codes: empty set")
	}
	for i, c := range codes {
		if !IsWellFormedBackupCode(c) {
			return domain.LoginVerifier{}, fmt.Errorf("backup codes: code #%d is malformed", i+1)
		}
	}
	if h.declared.Format != domain.PasswordHashFormatArgon2id {
		return domain.LoginVerifier{}, fmt.Errorf("backup codes: format %q is not writable", h.declared.Format)
	}
	memory := h.declared.Params[domain.CostParamArgon2Memory]
	iterations := h.declared.Params[domain.CostParamArgon2Iterations]
	parallelism := h.declared.Params[domain.CostParamArgon2Parallelism]
	if parallelism > math.MaxUint8 {
		return domain.LoginVerifier{}, fmt.Errorf("backup codes: parallelism %d exceeds the library bound", parallelism)
	}
	salt := make([]byte, argon2idSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return domain.LoginVerifier{}, fmt.Errorf("backup codes: random source: %w", err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s%sm=%d,t=%d,p=%d$%s$%s",
		argon2idMarkerPrefix, argon2idVersionPrefix, memory, iterations, parallelism,
		base64.RawStdEncoding.EncodeToString(salt), setElementSeparator)
	for _, c := range codes {
		body := argon2.IDKey([]byte(normalizeBackupCode(c)), salt, iterations, memory, uint8(parallelism), argon2idKeyLen)
		b.WriteString(base64.RawStdEncoding.EncodeToString(body))
		b.WriteString(setElementSeparator)
	}
	return domain.NewLoginVerifier(b.String())
}
