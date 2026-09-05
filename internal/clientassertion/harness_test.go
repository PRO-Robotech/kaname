// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// harness_test.go — оснастка проб проверяющего утверждение клиента.
//
// # Почему утверждение собирается ЗДЕСЬ, а не библиотекой
//
// Пробы обязаны подавать входы, которые библиотека собрать НЕ ДАЁТ: имя члена
// заголовка дважды, член, помеченный обязательным к пониманию, встроенный ключ,
// число сегментов больше и меньше объявленного формой. Собери мы вход
// библиотекой — проверялось бы ровно то подмножество, которое она умеет
// произвести, то есть заведомо законное. Отсюда ручная сборка компактной формы:
// заголовок и полезная нагрузка кладутся ДОСЛОВНО тем текстом, который назвала
// проба.
package clientassertion_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/tokenpolicy"
)

// testKey — ключ клиента вместе с его зарегистрированной формой.
type testKey struct {
	alg     string
	private any
	// publicPEM — то, что лежит в реестре.
	publicPEM string
}

// newKey порождает ключ объявленного алгоритма.
func newKey(t *testing.T, alg string) testKey {
	t.Helper()
	var (
		priv any
		pub  any
	)
	switch alg {
	case tokenpolicy.AlgES256:
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("ES256: %v", err)
		}
		priv, pub = k, &k.PublicKey
	case tokenpolicy.AlgRS256:
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("RS256: %v", err)
		}
		priv, pub = k, &k.PublicKey
	case tokenpolicy.AlgEdDSA:
		p, s, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("EdDSA: %v", err)
		}
		priv, pub = s, p
	default:
		t.Fatalf("оснастка не умеет алгоритм %q", alg)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("PKIX: %v", err)
	}
	return testKey{
		alg:       alg,
		private:   priv,
		publicPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})),
	}
}

// b64 — кодирование сегмента компактной формы.
func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// assertion — собираемое утверждение. Заголовок и нагрузка держатся СЫРЫМ
// текстом: только так проба подаёт дублирующееся имя члена.
type assertion struct {
	headerJSON  string
	payloadJSON string
	key         testKey
	// tamper — подмена уже собранной подписи.
	tamper bool
	// segments — переопределение числа сегментов (0 = как получилось).
	segments int
}

// header собирает заголовок из пар. Порядок пар сохраняется, поэтому проба
// вправе назвать одно имя дважды.
func header(pairs ...string) string {
	if len(pairs)%2 != 0 {
		panic("header: пары")
	}
	out := "{"
	for i := 0; i < len(pairs); i += 2 {
		if i > 0 {
			out += ","
		}
		out += pairs[i] + ":" + pairs[i+1]
	}
	return out + "}"
}

// jsonString экранирует строку как член JSON.
func jsonString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// claims собирает полезную нагрузку из карты.
func claims(m map[string]any) string {
	b, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// sign собирает компактную форму и подписывает её ключом утверждения.
func (a assertion) sign(t *testing.T) string {
	t.Helper()
	signingInput := b64([]byte(a.headerJSON)) + "." + b64([]byte(a.payloadJSON))
	sig, err := signRaw(a.key, signingInput)
	if err != nil {
		t.Fatalf("подпись: %v", err)
	}
	if a.tamper {
		sig[0] ^= 0xff
	}
	out := signingInput + "." + b64(sig)
	switch {
	case a.segments == 0:
		return out
	case a.segments > 3:
		for i := 3; i < a.segments; i++ {
			out += "." + b64([]byte("extra"))
		}
		return out
	default:
		// Меньше объявленного формой: отрезаем хвост.
		parts := []string{b64([]byte(a.headerJSON)), b64([]byte(a.payloadJSON)), b64(sig)}
		out = parts[0]
		for i := 1; i < a.segments; i++ {
			out += "." + parts[i]
		}
		return out
	}
}

// signRaw — подпись строки подписи ключом. Алгоритм берётся у КЛЮЧА, а не у
// заголовка: проба обязана уметь объявить в заголовке одно, а подписать другим,
// иначе подмену алгоритма нечем произвести.
func signRaw(k testKey, signingInput string) ([]byte, error) {
	switch key := k.private.(type) {
	case *ecdsa.PrivateKey:
		sum := sha256.Sum256([]byte(signingInput))
		r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
		if err != nil {
			return nil, err
		}
		size := (key.Curve.Params().BitSize + 7) / 8
		out := make([]byte, 2*size)
		r.FillBytes(out[:size])
		s.FillBytes(out[size:])
		return out, nil
	case *rsa.PrivateKey:
		sum := sha256.Sum256([]byte(signingInput))
		return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	case ed25519.PrivateKey:
		return ed25519.Sign(key, []byte(signingInput)), nil
	default:
		return nil, fmt.Errorf("оснастка не умеет ключ %T", k.private)
	}
}
