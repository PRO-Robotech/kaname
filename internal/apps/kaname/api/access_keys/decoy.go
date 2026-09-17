// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_keys

// decoy.go — ключ-приманка для выравнивания времени на неизвестном
// удостоверении (Ф7-09): сверка подписи выполняется всегда, над настоящим
// открытым ключом либо над приманкой того же семейства. Приманка чеканится на
// старте и никуда не хранится.

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/fxamacker/cbor/v2"

	"github.com/PRO-Robotech/kaname/internal/webauthnverify"
)

type decoyKey struct {
	alg    webauthnverify.Algorithm
	public []byte
}

func newDecoyKey(alg webauthnverify.Algorithm) (decoyKey, error) {
	var m map[int64]any
	switch alg {
	case webauthnverify.AlgES256:
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return decoyKey{}, fmt.Errorf("access keys: decoy key: %w", err)
		}
		x, y := make([]byte, 32), make([]byte, 32)
		k.PublicKey.X.FillBytes(x)
		k.PublicKey.Y.FillBytes(y)
		m = map[int64]any{1: int64(2), 3: int64(alg), -1: int64(1), -2: x, -3: y}
	case webauthnverify.AlgRS256:
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return decoyKey{}, fmt.Errorf("access keys: decoy key: %w", err)
		}
		m = map[int64]any{1: int64(3), 3: int64(alg), -1: k.PublicKey.N.Bytes(), -2: []byte{1, 0, 1}}
	case webauthnverify.AlgEdDSA:
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return decoyKey{}, fmt.Errorf("access keys: decoy key: %w", err)
		}
		m = map[int64]any{1: int64(1), 3: int64(alg), -1: int64(6), -2: []byte(pub)}
	default:
		return decoyKey{}, fmt.Errorf("access keys: decoy key: algorithm %d outside the dictionary", alg)
	}
	raw, err := cbor.Marshal(m)
	if err != nil {
		return decoyKey{}, fmt.Errorf("access keys: decoy key: %w", err)
	}
	return decoyKey{alg: alg, public: raw}, nil
}
