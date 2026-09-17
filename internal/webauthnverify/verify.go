// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package webauthnverify — проверяющий ключей доступа: результат церемонии
// регистрации и утверждение по норме WebAuthn Level 2 (§7.1 и §7.2), без
// аттестации (iam Ф7, PRO-Robotech/kacho#1273; приёмка
// `docs/engineering/acceptance/access-keys-are-ours.md`).
//
// # Предмет
//
// Пакет судит БАЙТЫ, пришедшие от браузера, против того, что служба выдала и
// объявила: испытание, происхождение (перечень посадки, никогда — заголовок
// запроса), хэш имени доверяющей стороны, бит присутствия, алгоритм открытого
// ключа, подпись. Всё это — сверки нормы, и норма ставит их в обе процедуры
// одной фразой (Р2, перемерено по тексту).
//
// # Чего здесь НЕТ — и почему
//
// Ни хранилища, ни испытаний, ни счётчика как состояния: пакет чист, его
// вызывающий держит строку ключа и выданное испытание. Проверяющий ОДИН на
// дерево — полоса входа Ф13 обязана звать его же (Ф13 Р13), поэтому он не
// знает ни сессии, ни человека: связывание с вызывающим — дело глагола.
//
// Аттестация не требуется, не проверяется и не хранится (Р4): формат
// `attestationObject` читается ради `authData` и только ради него;
// `attStmt` не разбирается ни при каком формате, и в результате поля для него
// нет by construction (Ф7-31).
//
// # Отказ — причина ВНУТРИ, единый текст СНАРУЖИ
//
// Каждый отказ несёт `Reason` — для журнала и счётчиков оператора. Наружу
// глагол утверждения отдаёт единый отказ аутентификации (§3.0, четырнадцать
// полос); различимость причин здесь — не оракул, потому что она не доезжает
// до предъявителя.
package webauthnverify

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/fxamacker/cbor/v2"
)

// Algorithm — идентификатор алгоритма COSE (RFC 9053 §2, §8.2; RFC 8812).
type Algorithm int64

// Словарь алгоритмов проверяющего ЗАКРЫТ: три семейства, и посадка выбирает
// подмножество (Р2, третья величина контракта). Идентификатор вне словаря —
// отказ разбора перечня, а не «прочее».
const (
	AlgES256 Algorithm = -7
	AlgEdDSA Algorithm = -8
	AlgRS256 Algorithm = -257
)

// KnownAlgorithms — словарь в устойчивом порядке.
func KnownAlgorithms() []Algorithm { return []Algorithm{AlgES256, AlgEdDSA, AlgRS256} }

// Name — имя алгоритма по реестру IANA COSE (для текстов отказа и документа
// оператора); идентификатор вне словаря имени не имеет.
func (a Algorithm) Name() string {
	switch a {
	case AlgES256:
		return "ES256"
	case AlgEdDSA:
		return "EdDSA"
	case AlgRS256:
		return "RS256"
	default:
		return ""
	}
}

// ParseAlgorithms читает перечень посадки: каждый идентификатор обязан быть
// в словаре, перечень — непустым (пустой означает «церемония невозможна», Р2).
func ParseAlgorithms(raw []int64) ([]Algorithm, error) {
	if len(raw) == 0 {
		return nil, errors.New("webauthn: перечень алгоритмов открытого ключа пуст — церемония невозможна")
	}
	out := make([]Algorithm, 0, len(raw))
	seen := map[Algorithm]bool{}
	for _, v := range raw {
		a := Algorithm(v)
		if !isKnown(a) {
			return nil, fmt.Errorf("webauthn: алгоритм %d не входит в словарь проверяющего %v", v, KnownAlgorithms())
		}
		if !seen[a] {
			out = append(out, a)
			seen[a] = true
		}
	}
	return out, nil
}

func isKnown(a Algorithm) bool {
	for _, k := range KnownAlgorithms() {
		if k == a {
			return true
		}
	}
	return false
}

// Binding — привязка: три ручки посадки (Р2).
type Binding struct {
	RPID       string
	Origins    []string
	Algorithms []Algorithm
}

func (b Binding) allowsOrigin(o string) bool {
	for _, x := range b.Origins {
		if x == o {
			return true
		}
	}
	return false
}

func (b Binding) allowsAlgorithm(a Algorithm) bool {
	for _, x := range b.Algorithms {
		if x == a {
			return true
		}
	}
	return false
}

// Reason — причина отказа; закрытый перечень.
type Reason string

const (
	ReasonMalformed           Reason = "malformed"
	ReasonClientDataType      Reason = "client-data-type"
	ReasonChallengeMismatch   Reason = "challenge-mismatch"
	ReasonOriginNotAllowed    Reason = "origin-not-allowed"
	ReasonRPIDHashMismatch    Reason = "rp-id-hash-mismatch"
	ReasonUserNotPresent      Reason = "user-not-present"
	ReasonAlgorithmNotAllowed Reason = "algorithm-not-allowed"
	ReasonSignature           Reason = "signature"
)

// Reasons — закрытый перечень причин, чтобы клетки счётчика заводились нулём.
func Reasons() []Reason {
	return []Reason{ReasonMalformed, ReasonClientDataType, ReasonChallengeMismatch, ReasonOriginNotAllowed,
		ReasonRPIDHashMismatch, ReasonUserNotPresent, ReasonAlgorithmNotAllowed, ReasonSignature}
}

// Refusal — отказ проверяющего с причиной для оператора.
type Refusal struct {
	Reason Reason
	Detail string
}

func (r *Refusal) Error() string {
	if r.Detail == "" {
		return "webauthn: " + string(r.Reason)
	}
	return "webauthn: " + string(r.Reason) + ": " + r.Detail
}

func refuse(reason Reason, detail string) error { return &Refusal{Reason: reason, Detail: detail} }

// Flags — биты флагов данных аутентификатора (норма §6.1).
type Flags struct {
	UserPresent    bool
	UserVerified   bool
	BackupEligible bool
	BackupState    bool
}

const (
	flagUP = 1 << 0
	flagUV = 1 << 2
	flagBE = 1 << 3
	flagBS = 1 << 4
	flagAT = 1 << 6
)

func flagsOf(b byte) Flags {
	return Flags{UserPresent: b&flagUP != 0, UserVerified: b&flagUV != 0, BackupEligible: b&flagBE != 0, BackupState: b&flagBS != 0}
}

// ClientData — разобранные клиентские данные (норма §5.8.1).
type ClientData struct {
	Type      string
	Challenge []byte
	Origin    string
}

// ParseClientData читает `clientDataJSON`: тип, испытание (base64url без
// дополнения) и происхождение. Читается ДО сверки: по испытанию вызывающий
// находит выданное.
func ParseClientData(raw []byte) (ClientData, error) {
	var cd struct {
		Type      string `json:"type"`
		Challenge string `json:"challenge"`
		Origin    string `json:"origin"`
	}
	if err := json.Unmarshal(raw, &cd); err != nil {
		return ClientData{}, refuse(ReasonMalformed, "clientDataJSON is not JSON")
	}
	ch, err := base64.RawURLEncoding.DecodeString(cd.Challenge)
	if err != nil || len(ch) == 0 {
		return ClientData{}, refuse(ReasonMalformed, "clientDataJSON.challenge is not base64url")
	}
	if cd.Type == "" || cd.Origin == "" {
		return ClientData{}, refuse(ReasonMalformed, "clientDataJSON lacks type or origin")
	}
	return ClientData{Type: cd.Type, Challenge: ch, Origin: cd.Origin}, nil
}

// Типы клиентских данных двух процедур.
const (
	ClientDataTypeCreate = "webauthn.create"
	ClientDataTypeGet    = "webauthn.get"
)

// judgeClientData — общие для обеих процедур сверки клиентских данных
// (норма §7.1 шаги 7–9, §7.2 шаги 11–13): тип, испытание, происхождение.
func judgeClientData(raw []byte, wantType string, challenge []byte, b Binding) (ClientData, error) {
	cd, err := ParseClientData(raw)
	if err != nil {
		return ClientData{}, err
	}
	if cd.Type != wantType {
		return ClientData{}, refuse(ReasonClientDataType, fmt.Sprintf("want %s, got %s", wantType, cd.Type))
	}
	if !bytes.Equal(cd.Challenge, challenge) {
		return ClientData{}, refuse(ReasonChallengeMismatch, "")
	}
	// Происхождение сверяется с ОБЪЯВЛЕННЫМ перечнем и никогда не берётся из
	// запроса; пустой перечень означает «никого» (Ф7-13, Ф7-44).
	if !b.allowsOrigin(cd.Origin) {
		return ClientData{}, refuse(ReasonOriginNotAllowed, cd.Origin)
	}
	return cd, nil
}

// authenticatorData — разобранная форма данных аутентификатора (норма §6.1).
type authenticatorData struct {
	RPIDHash  []byte
	Flags     Flags
	raw       byte
	SignCount uint32
	// Только при флаге AT (регистрация):
	AAGUID       [16]byte
	CredentialID []byte
	PublicKey    []byte // COSE_Key, байты как приняты
}

const authDataMinLen = 32 + 1 + 4

func parseAuthenticatorData(raw []byte, attested bool) (authenticatorData, error) {
	if len(raw) < authDataMinLen {
		return authenticatorData{}, refuse(ReasonMalformed, "authenticator data shorter than its fixed part")
	}
	ad := authenticatorData{RPIDHash: raw[:32], raw: raw[32], Flags: flagsOf(raw[32]), SignCount: binary.BigEndian.Uint32(raw[33:37])}
	if !attested {
		return ad, nil
	}
	if ad.raw&flagAT == 0 {
		return authenticatorData{}, refuse(ReasonMalformed, "attested credential data flag is unset on a registration result")
	}
	rest := raw[37:]
	if len(rest) < 16+2 {
		return authenticatorData{}, refuse(ReasonMalformed, "attested credential data truncated")
	}
	copy(ad.AAGUID[:], rest[:16])
	l := int(binary.BigEndian.Uint16(rest[16:18]))
	rest = rest[18:]
	if l == 0 || len(rest) < l {
		return authenticatorData{}, refuse(ReasonMalformed, "credential id truncated")
	}
	ad.CredentialID = append([]byte(nil), rest[:l]...)
	rest = rest[l:]
	// Открытый ключ — ОДИН CBOR-элемент; хвост после него нормой не
	// предусмотрен (расширения здесь не запрашиваются).
	key, tail, err := splitFirstCBOR(rest)
	if err != nil {
		return authenticatorData{}, refuse(ReasonMalformed, "credential public key is not CBOR")
	}
	if len(tail) != 0 {
		return authenticatorData{}, refuse(ReasonMalformed, "trailing bytes after the credential public key")
	}
	ad.PublicKey = append([]byte(nil), key...)
	return ad, nil
}

// decMode — строгий разбор CBOR: дубли ключей и бесконечная вложенность — отказ.
var decMode = func() cbor.DecMode {
	dm, err := cbor.DecOptions{DupMapKey: cbor.DupMapKeyEnforcedAPF, MaxNestedLevels: 8, IndefLength: cbor.IndefLengthForbidden}.DecMode()
	if err != nil {
		panic(err)
	}
	return dm
}()

func splitFirstCBOR(raw []byte) (first, tail []byte, err error) {
	var v cbor.RawMessage
	rest, err := decMode.UnmarshalFirst(raw, &v)
	if err != nil {
		return nil, nil, err
	}
	return []byte(v), rest, nil
}

// RegistrationInput — что сверяет приём результата церемонии.
type RegistrationInput struct {
	// Challenge — выданное испытание (найдено вызывающим по клиентским данным).
	Challenge         []byte
	Binding           Binding
	ClientDataJSON    []byte
	AttestationObject []byte
}

// RegistrationResult — принятый материал строки ключа. Поля аттестации здесь
// нет by construction (Р4, Ф7-31).
type RegistrationResult struct {
	CredentialID []byte
	// PublicKey — COSE_Key байт в байт, как принят: по нему сверяется подпись.
	PublicKey []byte
	Algorithm Algorithm
	SignCount uint32
	Flags     Flags
	AAGUID    [16]byte
}

// VerifyRegistration — норма §7.1 без шагов аттестации: клиентские данные,
// хэш имени доверяющей стороны, бит присутствия, алгоритм ключа из перечня.
func VerifyRegistration(in RegistrationInput) (RegistrationResult, error) {
	if _, err := judgeClientData(in.ClientDataJSON, ClientDataTypeCreate, in.Challenge, in.Binding); err != nil {
		return RegistrationResult{}, err
	}
	var att struct {
		Fmt      string          `cbor:"fmt"`
		AttStmt  cbor.RawMessage `cbor:"attStmt"`
		AuthData []byte          `cbor:"authData"`
	}
	if err := decMode.Unmarshal(in.AttestationObject, &att); err != nil {
		return RegistrationResult{}, refuse(ReasonMalformed, "attestationObject is not CBOR")
	}
	if att.Fmt == "" || att.AuthData == nil {
		return RegistrationResult{}, refuse(ReasonMalformed, "attestationObject lacks fmt or authData")
	}
	// `attStmt` не читается ни при каком `fmt` (Р4).
	ad, err := parseAuthenticatorData(att.AuthData, true)
	if err != nil {
		return RegistrationResult{}, err
	}
	if err := judgeAuthData(ad, in.Binding); err != nil {
		return RegistrationResult{}, err
	}
	alg, _, err := parseCOSEKey(ad.PublicKey)
	if err != nil {
		return RegistrationResult{}, err
	}
	if !in.Binding.allowsAlgorithm(alg) {
		return RegistrationResult{}, refuse(ReasonAlgorithmNotAllowed, fmt.Sprintf("%d", alg))
	}
	return RegistrationResult{CredentialID: ad.CredentialID, PublicKey: ad.PublicKey, Algorithm: alg, SignCount: ad.SignCount, Flags: ad.Flags, AAGUID: ad.AAGUID}, nil
}

// judgeAuthData — хэш имени доверяющей стороны и бит присутствия: обе сверки
// стоят в обеих процедурах (Р2, Ф7-45/Ф7-12, Ф7-48/Ф7-49).
func judgeAuthData(ad authenticatorData, b Binding) error {
	want := sha256.Sum256([]byte(b.RPID))
	if !bytes.Equal(ad.RPIDHash, want[:]) {
		return refuse(ReasonRPIDHashMismatch, "")
	}
	if !ad.Flags.UserPresent {
		return refuse(ReasonUserNotPresent, "")
	}
	return nil
}

// AssertionInput — что сверяет проверка утверждения.
type AssertionInput struct {
	Challenge         []byte
	Binding           Binding
	ClientDataJSON    []byte
	AuthenticatorData []byte
	Signature         []byte
	// PublicKey / Algorithm — материал НАЗВАННОЙ строки (Ф7-08).
	PublicKey []byte
	Algorithm Algorithm
}

// AssertionResult — что утверждение сообщило: флаги ЭТОГО утверждения (§3.8) и
// счётчик для оператора сдвига (Р6).
type AssertionResult struct {
	Flags     Flags
	SignCount uint32
}

// VerifyAssertion — норма §7.2: клиентские данные, хэш имени, бит присутствия,
// подпись над `authData || SHA-256(clientDataJSON)` открытым ключом строки.
func VerifyAssertion(in AssertionInput) (AssertionResult, error) {
	if _, err := judgeClientData(in.ClientDataJSON, ClientDataTypeGet, in.Challenge, in.Binding); err != nil {
		return AssertionResult{}, err
	}
	ad, err := parseAuthenticatorData(in.AuthenticatorData, false)
	if err != nil {
		return AssertionResult{}, err
	}
	if err := judgeAuthData(ad, in.Binding); err != nil {
		return AssertionResult{}, err
	}
	alg, pub, err := parseCOSEKey(in.PublicKey)
	if err != nil {
		return AssertionResult{}, err
	}
	if alg != in.Algorithm {
		return AssertionResult{}, refuse(ReasonAlgorithmNotAllowed, "stored key names another algorithm than its row")
	}
	h := sha256.Sum256(in.ClientDataJSON)
	msg := append(append([]byte(nil), in.AuthenticatorData...), h[:]...)
	if !verifySignature(alg, pub, msg, in.Signature) {
		return AssertionResult{}, refuse(ReasonSignature, "")
	}
	return AssertionResult{Flags: ad.Flags, SignCount: ad.SignCount}, nil
}

// parseCOSEKey читает COSE_Key (RFC 9053 §7) и отдаёт алгоритм и открытый ключ.
func parseCOSEKey(raw []byte) (Algorithm, crypto.PublicKey, error) {
	var m map[int64]cbor.RawMessage
	if err := decMode.Unmarshal(raw, &m); err != nil {
		return 0, nil, refuse(ReasonMalformed, "COSE key is not a map")
	}
	var kty, alg int64
	if err := decodeInt(m[1], &kty); err != nil {
		return 0, nil, refuse(ReasonMalformed, "COSE key type")
	}
	if err := decodeInt(m[3], &alg); err != nil {
		return 0, nil, refuse(ReasonMalformed, "COSE key algorithm")
	}
	a := Algorithm(alg)
	if !isKnown(a) {
		return 0, nil, refuse(ReasonAlgorithmNotAllowed, fmt.Sprintf("%d", alg))
	}
	switch {
	case a == AlgES256 && kty == 2:
		var crv int64
		var x, y []byte
		if decodeInt(m[-1], &crv) != nil || crv != 1 || decodeBytes(m[-2], &x) != nil || decodeBytes(m[-3], &y) != nil || len(x) != 32 || len(y) != 32 {
			return 0, nil, refuse(ReasonMalformed, "EC2 key")
		}
		// Несжатая точка SEC 1 §2.3.3: 0x04 || X || Y; разбор сам проверяет,
		// что точка лежит на кривой, — ключ вне кривой не собирается вовсе.
		point := make([]byte, 0, 65)
		point = append(point, 0x04)
		point = append(point, x...)
		point = append(point, y...)
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
		if err != nil {
			return 0, nil, refuse(ReasonMalformed, "EC2 point is not on P-256")
		}
		return a, pub, nil
	case a == AlgRS256 && kty == 3:
		var n, e []byte
		if decodeBytes(m[-1], &n) != nil || decodeBytes(m[-2], &e) != nil || len(n) < 256 || len(e) == 0 || len(e) > 4 {
			return 0, nil, refuse(ReasonMalformed, "RSA key")
		}
		return a, &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}, nil
	case a == AlgEdDSA && kty == 1:
		var crv int64
		var x []byte
		if decodeInt(m[-1], &crv) != nil || crv != 6 || decodeBytes(m[-2], &x) != nil || len(x) != ed25519.PublicKeySize {
			return 0, nil, refuse(ReasonMalformed, "OKP key")
		}
		return a, ed25519.PublicKey(x), nil
	}
	return 0, nil, refuse(ReasonMalformed, fmt.Sprintf("COSE key type %d does not fit algorithm %d", kty, alg))
}

func decodeInt(raw cbor.RawMessage, out *int64) error {
	if raw == nil {
		return errors.New("absent")
	}
	return decMode.Unmarshal(raw, out)
}

func decodeBytes(raw cbor.RawMessage, out *[]byte) error {
	if raw == nil {
		return errors.New("absent")
	}
	return decMode.Unmarshal(raw, out)
}

func verifySignature(alg Algorithm, pub crypto.PublicKey, msg, sig []byte) bool {
	switch alg {
	case AlgES256:
		k, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return false
		}
		h := sha256.Sum256(msg)
		return ecdsa.VerifyASN1(k, h[:], sig)
	case AlgRS256:
		k, ok := pub.(*rsa.PublicKey)
		if !ok {
			return false
		}
		h := sha256.Sum256(msg)
		return rsa.VerifyPKCS1v15(k, crypto.SHA256, h[:], sig) == nil
	case AlgEdDSA:
		k, ok := pub.(ed25519.PublicKey)
		if !ok {
			return false
		}
		return ed25519.Verify(k, msg, sig)
	}
	return false
}

// CounterVerdict — исход сверки счётчика подписи по таблице Р6.
type CounterVerdict int

const (
	// CounterZeroUnjudged — ключ сообщает ноль и сообщал ноль прежде: не судится.
	CounterZeroUnjudged CounterVerdict = iota
	// CounterAdvances — сообщённый больше сохранённого: штатный сдвиг.
	CounterAdvances
	// CounterRegressed — сообщённый положителен и не больше сохранённого, либо
	// ноль при положительном сохранённом: единственный сигнал клонирования.
	CounterRegressed
)

// JudgeCounter классифицирует ЧТЕНИЕ; инвариант держит атомарный оператор
// сдвига с условием на прежнее значение, а не это сравнение (Р6).
func JudgeCounter(stored, reported uint32) CounterVerdict {
	switch {
	case stored == 0 && reported == 0:
		return CounterZeroUnjudged
	case reported > stored:
		return CounterAdvances
	default:
		return CounterRegressed
	}
}
