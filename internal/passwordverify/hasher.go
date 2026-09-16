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
	material := fmt.Sprintf("%s%sm=%d,t=%d,p=%d$%s$%s",
		argon2idMarkerPrefix, argon2idVersionPrefix, memory, iterations, parallelism,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(body))
	return domain.NewLoginVerifier(material)
}
