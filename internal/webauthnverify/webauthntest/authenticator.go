// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package webauthntest — ПОДСТАВНОЙ аутентификатор для проб проверяющего
// ключей доступа (iam Ф7, PRO-Robotech/kacho#1273; приёмка
// `docs/engineering/acceptance/access-keys-are-ours.md`, §8, последняя строка).
//
// # Чем он отличается от настоящего — и чем НЕ отличается
//
// Подписывает настоящим ключом (ECDSA P-256, RSA-2048, Ed25519) и собирает
// результат церемонии и утверждение той же формой, что браузер: clientDataJSON,
// attestationObject (CBOR, формат `none`), authenticatorData с флагами, COSE-ключ.
// Проверяющий продукта его от настоящего не отличает — в этом его годность.
//
// Отличается тем, что УМЕЕТ ТО, ЧЕГО СООТВЕТСТВУЮЩИЙ НОРМЕ НЕ ДЕЛАЕТ: собрать
// результат на испытании, которое ему назовут (невыданном, чужом, повторном),
// снять бит присутствия, подписать данные для чужого имени доверяющей стороны,
// назвать другое происхождение, сообщить счётчик ниже прежнего, подделать
// подпись. Без этого оси Ф7-02/03/34, Ф7-44/45/48, Ф7-49, Ф7-52…55 не наблюдаемы:
// настоящий браузер подписывает только то, что получил от службы.
//
// Фикстура НЕ снисходительнее продукта: она ничего не проверяет и ничего не
// подделывает молча — каждое отступление от нормы есть явное поле опций.
package webauthntest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

// Алгоритмы COSE, которые фикстура умеет (те же три, что проверяющий).
const (
	AlgES256 int64 = -7
	AlgEdDSA int64 = -8
	AlgRS256 int64 = -257
)

// Биты флагов данных аутентификатора (норма §6.1).
const (
	flagUP = 1 << 0
	flagUV = 1 << 2
	flagBE = 1 << 3
	flagBS = 1 << 4
	flagAT = 1 << 6
)

// Authenticator — один ключ одного человека.
type Authenticator struct {
	alg    int64
	priv   crypto.Signer
	credID []byte
	aaguid [16]byte
	// counter — счётчик подписи, который аутентификатор сообщит следующим
	// утверждением; сдвигается фикстурой по её же правилу, а не продуктом.
	counter uint32
}

// New чеканит ключ названного алгоритма и случайный идентификатор удостоверения.
func New(t testing.TB, alg int64) *Authenticator {
	t.Helper()
	a := &Authenticator{alg: alg}
	switch alg {
	case AlgES256:
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		a.priv = k
	case AlgRS256:
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		a.priv = k
	case AlgEdDSA:
		_, k, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		a.priv = k
	default:
		t.Fatalf("webauthntest: алгоритм %d фикстуре неизвестен", alg)
	}
	a.credID = make([]byte, 32)
	_, err := rand.Read(a.credID)
	require.NoError(t, err)
	_, err = rand.Read(a.aaguid[:])
	require.NoError(t, err)
	return a
}

// CredentialID — идентификатор удостоверения (`rawId`).
func (a *Authenticator) CredentialID() []byte { return append([]byte(nil), a.credID...) }

// SetCredentialID подменяет идентификатор: Ф7-05 (тот же `K` у двух ключей).
func (a *Authenticator) SetCredentialID(id []byte) { a.credID = append([]byte(nil), id...) }

// Algorithm — алгоритм COSE ключа.
func (a *Authenticator) Algorithm() int64 { return a.alg }

// SetCounter задаёт счётчик, который сообщит СЛЕДУЮЩЕЕ утверждение.
func (a *Authenticator) SetCounter(c uint32) { a.counter = c }

// Counter — счётчик, который сообщит следующее утверждение.
func (a *Authenticator) Counter() uint32 { return a.counter }

// COSEPublicKey — открытый ключ в форме COSE_Key (норма §6.5.1 / RFC 9053).
func (a *Authenticator) COSEPublicKey(t testing.TB) []byte {
	t.Helper()
	return a.cosePublicKey(t, a.alg)
}

func (a *Authenticator) cosePublicKey(t testing.TB, claimedAlg int64) []byte {
	t.Helper()
	var m map[int64]any
	switch k := a.priv.(type) {
	case *ecdsa.PrivateKey:
		x := make([]byte, 32)
		y := make([]byte, 32)
		k.PublicKey.X.FillBytes(x)
		k.PublicKey.Y.FillBytes(y)
		m = map[int64]any{1: int64(2), 3: claimedAlg, -1: int64(1), -2: x, -3: y}
	case *rsa.PrivateKey:
		e := big3(k.PublicKey.E)
		m = map[int64]any{1: int64(3), 3: claimedAlg, -1: k.PublicKey.N.Bytes(), -2: e}
	case ed25519.PrivateKey:
		pub := k.Public().(ed25519.PublicKey)
		m = map[int64]any{1: int64(1), 3: claimedAlg, -1: int64(6), -2: []byte(pub)}
	}
	out, err := cbor.Marshal(m)
	require.NoError(t, err)
	return out
}

func big3(e int) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(e)) // #nosec G115 -- экспонента RSA 65537 помещается
	for len(b) > 1 && b[0] == 0 {
		b = b[1:]
	}
	return b
}

// RegistrationOptions — что фикстура кладёт в результат церемонии. Пустые
// поля означают норму; каждое отступление названо полем.
type RegistrationOptions struct {
	// Challenge — испытание, которое подпишется; фикстура берёт ЛЮБОЕ, а не
	// только выданное службой — так строятся Ф7-02, Ф7-03, Ф7-34.
	Challenge []byte
	// Origin — что назовёт clientDataJSON.
	Origin string
	// RPID — имя доверяющей стороны, чей хэш ляжет в данные аутентификатора.
	RPID string
	// UserPresentUnset — снять бит присутствия (Ф7-48).
	UserPresentUnset bool
	// UserVerified — поставить бит проверки пользователя.
	UserVerified bool
	// BackupEligible / BackupState — биты резервного копирования.
	BackupEligible bool
	BackupState    bool
	// ClaimedAlg — назвать в COSE-ключе иной алгоритм (Ф7-35): подпись ключа
	// при регистрации не сверяется (аттестация `none`), поэтому алгоритм
	// проверяющий читает из ключа.
	ClaimedAlg *int64
	// Type — тип клиентских данных; пустое — `webauthn.create`.
	Type string
	// SignCount — счётчик в данных аутентификатора.
	SignCount uint32
	// AttestationFormat — формат аттестации; пустое — `none`. Другой формат
	// строит Ф7-31: результат с аттестацией принимается, содержимое не хранится.
	AttestationFormat string
}

// Register собирает clientDataJSON и attestationObject.
func (a *Authenticator) Register(t testing.TB, o RegistrationOptions) (clientDataJSON, attestationObject []byte) {
	t.Helper()
	typ := o.Type
	if typ == "" {
		typ = "webauthn.create"
	}
	clientDataJSON = clientData(t, typ, o.Challenge, o.Origin)
	flags := byte(flagAT)
	if !o.UserPresentUnset {
		flags |= flagUP
	}
	if o.UserVerified {
		flags |= flagUV
	}
	if o.BackupEligible {
		flags |= flagBE
	}
	if o.BackupState {
		flags |= flagBS
	}
	alg := a.alg
	if o.ClaimedAlg != nil {
		alg = *o.ClaimedAlg
	}
	authData := a.authData(t, o.RPID, flags, o.SignCount, true, alg)
	fmtName := o.AttestationFormat
	if fmtName == "" {
		fmtName = "none"
	}
	attStmt := map[string]any{}
	if fmtName != "none" {
		// Содержимое аттестации фикстура не подписывает: продукт её не
		// проверяет и не хранит (Р4), а форма поля — лишь бы была непустой.
		attStmt["alg"] = alg
		attStmt["sig"] = []byte{0x30, 0x00}
	}
	att, err := cbor.Marshal(map[string]any{"fmt": fmtName, "attStmt": attStmt, "authData": authData})
	require.NoError(t, err)
	return clientDataJSON, att
}

// AssertionOptions — что фикстура кладёт в утверждение.
type AssertionOptions struct {
	Challenge []byte
	Origin    string
	RPID      string
	// UserPresentUnset — снять бит присутствия (Ф7-49).
	UserPresentUnset bool
	UserVerified     bool
	BackupEligible   bool
	BackupState      bool
	// SignCount — счётчик, который сообщит утверждение. Нулевой указатель —
	// фикстура сдвигает свой счётчик сама (на единицу, если он положителен) и
	// сообщает его.
	SignCount *uint32
	// ForgeSignature — подписать случайным ключом того же алгоритма (Ф7-07).
	ForgeSignature bool
	// Type — тип клиентских данных; пустое — `webauthn.get`.
	Type string
}

// Assertion — собранное утверждение.
type Assertion struct {
	CredentialID      []byte
	ClientDataJSON    []byte
	AuthenticatorData []byte
	Signature         []byte
}

// Assert собирает утверждение и подписывает его.
func (a *Authenticator) Assert(t testing.TB, o AssertionOptions) Assertion {
	t.Helper()
	typ := o.Type
	if typ == "" {
		typ = "webauthn.get"
	}
	cd := clientData(t, typ, o.Challenge, o.Origin)
	flags := byte(0)
	if !o.UserPresentUnset {
		flags |= flagUP
	}
	if o.UserVerified {
		flags |= flagUV
	}
	if o.BackupEligible {
		flags |= flagBE
	}
	if o.BackupState {
		flags |= flagBS
	}
	count := a.counter
	if o.SignCount != nil {
		count = *o.SignCount
	} else if a.counter > 0 {
		count = a.counter + 1
		a.counter = count
	}
	authData := a.authData(t, o.RPID, flags, count, false, a.alg)
	h := sha256.Sum256(cd)
	msg := append(append([]byte(nil), authData...), h[:]...)
	signer := a.priv
	if o.ForgeSignature {
		signer = New(t, a.alg).priv
	}
	sig := sign(t, signer, a.alg, msg)
	return Assertion{CredentialID: a.CredentialID(), ClientDataJSON: cd, AuthenticatorData: authData, Signature: sig}
}

func sign(t testing.TB, k crypto.Signer, alg int64, msg []byte) []byte {
	t.Helper()
	switch alg {
	case AlgES256, AlgRS256:
		h := sha256.Sum256(msg)
		sig, err := k.Sign(rand.Reader, h[:], crypto.SHA256)
		require.NoError(t, err)
		return sig
	case AlgEdDSA:
		sig, err := k.Sign(rand.Reader, msg, crypto.Hash(0))
		require.NoError(t, err)
		return sig
	}
	t.Fatalf("webauthntest: подпись алгоритмом %d", alg)
	return nil
}

func (a *Authenticator) authData(t testing.TB, rpID string, flags byte, count uint32, attested bool, alg int64) []byte {
	t.Helper()
	h := sha256.Sum256([]byte(rpID))
	out := append([]byte(nil), h[:]...)
	out = append(out, flags)
	c := make([]byte, 4)
	binary.BigEndian.PutUint32(c, count)
	out = append(out, c...)
	if attested {
		out = append(out, a.aaguid[:]...)
		l := make([]byte, 2)
		binary.BigEndian.PutUint16(l, uint16(len(a.credID))) // #nosec G115 -- идентификатор короче 2^16
		out = append(out, l...)
		out = append(out, a.credID...)
		out = append(out, a.cosePublicKey(t, alg)...)
	}
	return out
}

func clientData(t testing.TB, typ string, challenge []byte, origin string) []byte {
	t.Helper()
	cd, err := json.Marshal(map[string]any{
		"type":      typ,
		"challenge": base64.RawURLEncoding.EncodeToString(challenge),
		"origin":    origin,
	})
	require.NoError(t, err)
	return cd
}

// RPIDHash — хэш имени доверяющей стороны, как его кладёт аутентификатор.
func RPIDHash(rpID string) []byte {
	h := sha256.Sum256([]byte(rpID))
	return h[:]
}

// String — для сообщений проб.
func (a *Authenticator) String() string {
	return fmt.Sprintf("authenticator(alg=%d, cred=%x)", a.alg, a.credID[:4])
}
