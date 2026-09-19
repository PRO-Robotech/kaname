// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package webauthnverify

// decoykey.go — КЛЮЧ-ПРИМАНКА выравнивания времени: сверка подписи выполняется
// всегда, над настоящим открытым ключом строки либо над приманкой того же
// семейства, — и работа по неизвестному удостоверению стоит столько же, сколько
// по известному.
//
// # Почему приманка живёт здесь, а не у вызывающего
//
// Вызывающих у проверяющего два — церемония предъявления (Ф7) и полоса входа
// (Ф13), — и оба обязаны выравнивать время ОДИНАКОВО. Две реализации одного
// выравнивания разошлись бы молча: каждая по отдельности защитима, а
// расхождение видно только сравнением полос между собой — ни одна проба
// отдельной полосы его не показывает.
//
// Сам проверяющий по времени нейтрален — подставляет приманку ВЫЗЫВАЮЩИЙ; здесь
// объявлено лишь то, ЧЕМ он её подставляет.
//
// Приманка чеканится на старте и никуда не хранится: секретом её закрытая
// половина не является — она не нужна вовсе, сверяется только открытая.

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// Величины формы несжатой точки: приставка и длина координаты P-256. Названы
// здесь, чтобы срез читался предметом, а не числами.
const (
	uncompressedPointPrefix = 0x04
	p256CoordBytes          = 32
)

// DecoyKey — открытый ключ-приманка одного из объявленных семейств.
type DecoyKey struct {
	alg    Algorithm
	public []byte
}

// Algorithm — семейство приманки: то же, что у первого объявленного посадкой.
func (d DecoyKey) Algorithm() Algorithm { return d.alg }

// Public — открытый ключ приманки в форме COSE_Key.
func (d DecoyKey) Public() []byte { return d.public }

// NewDecoyKey — чеканка приманки названного семейства. Алгоритм вне словаря —
// отказ построения, а не молчаливый пропуск выравнивания.
func NewDecoyKey(alg Algorithm) (DecoyKey, error) {
	var m map[int64]any
	switch alg {
	case AlgES256:
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return DecoyKey{}, fmt.Errorf("webauthn verify: decoy key: %w", err)
		}
		// Координаты берутся из КАНОНИЧЕСКОГО несжатого представления
		// (`0x04 || X || Y`), а не из полей большого числа: прямой доступ к ним
		// объявлен устаревшим и, по слову самой библиотеки, способен дать
		// негодный ключ. Длина и признак формы проверяются здесь же — иначе
		// срез молча взял бы не те байты, если представление сменится.
		point, err := k.PublicKey.Bytes()
		if err != nil {
			return DecoyKey{}, fmt.Errorf("webauthn verify: decoy key: %w", err)
		}
		if len(point) != 1+2*p256CoordBytes || point[0] != uncompressedPointPrefix {
			return DecoyKey{}, fmt.Errorf(
				"webauthn verify: decoy key: P-256 public point is %d bytes with prefix %#x, expected %d bytes with prefix %#x",
				len(point), point[0], 1+2*p256CoordBytes, uncompressedPointPrefix)
		}
		x, y := point[1:1+p256CoordBytes], point[1+p256CoordBytes:]
		m = map[int64]any{1: int64(2), 3: int64(alg), -1: int64(1), -2: x, -3: y}
	case AlgRS256:
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return DecoyKey{}, fmt.Errorf("webauthn verify: decoy key: %w", err)
		}
		m = map[int64]any{1: int64(3), 3: int64(alg), -1: k.PublicKey.N.Bytes(), -2: []byte{1, 0, 1}}
	case AlgEdDSA:
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return DecoyKey{}, fmt.Errorf("webauthn verify: decoy key: %w", err)
		}
		m = map[int64]any{1: int64(1), 3: int64(alg), -1: int64(6), -2: []byte(pub)}
	default:
		return DecoyKey{}, fmt.Errorf("webauthn verify: decoy key: algorithm %d outside the dictionary", alg)
	}
	raw, err := cbor.Marshal(m)
	if err != nil {
		return DecoyKey{}, fmt.Errorf("webauthn verify: decoy key: %w", err)
	}
	return DecoyKey{alg: alg, public: raw}, nil
}
