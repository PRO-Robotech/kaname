// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package tokensigner — подписант токенов платформы (задача #897).
//
// # Что этот подписант производит
//
// Наш токен для наших поверхностей. Все три величины, которые в токене выбирают
// сторону, — алгоритм, адресат и идентификатор ключа — выбираем МЫ.
//
// # Почему он отдельный от подписи утверждения, которая в дереве уже есть
//
// Существующая подпись производит утверждение для третьей стороны ПОД ЕЁ ЖЕ
// регистрацией: алгоритм, адресат и идентификатор ключа там выбраны тем, кому
// утверждение предъявляется, и меняются вместе с его требованиями. Сведение
// двух вещей, у которых форму диктуют разные стороны, к одной реализации —
// унификация по более широкой семантике: следующее изменение чужих требований
// пришло бы в наш подписант. Общей делается ПОЛИТИКА (перечень допустимых
// алгоритмов, запрет `alg=none`, форма заголовка, требование `kid`), а не
// подписывающая функция.
//
// # Часы — вход
//
// Источник времени передаётся, а не берётся из окружения. Без этого сценарии
// расхождения часов недетерминированы, а детерминизм входа — условие того,
// чтобы проба вообще могла упасть предсказуемо.
package tokensigner

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho/pkg/ids"
)

// Отказы выпуска. Каждый — ОТДЕЛЬНЫЙ, потому что вызывающий на них отвечает
// по-разному, а «одна ошибка на всё» превращает разбор в чтение прозы.
var (
	// ErrExpiryRequired — выпуск без срока либо со сроком в прошлом.
	// Обязательность срока стоит НА ВЫПУСКЕ, а не оставлена проверяющему:
	// токен без срока не должен существовать вовсе.
	ErrExpiryRequired = errors.New("tokensigner: token must carry an expiry")
	// ErrTTLAboveCeiling — запрошенный срок сверх объявленного потолка.
	// Потолок — слагаемое арифметики отсрочки снятия ключа; молчаливое
	// урезание сделало бы это слагаемое неизвестным вызывающему.
	ErrTTLAboveCeiling = errors.New("tokensigner: requested lifetime exceeds the declared ceiling")
	// ErrAudienceRequired — незаданный адресат означает «любой».
	ErrAudienceRequired = errors.New("tokensigner: token must name its audience")
	// ErrSubjectRequired — токен, не называющий, за кого он говорит, не
	// адресуется отзывом.
	ErrSubjectRequired = errors.New("tokensigner: token must name its subject")
	// ErrTokenTypeRequired — тип объявляется, потому что проверяющий его
	// требует; токен без типа не прошёл бы собственную приёмную сторону.
	ErrTokenTypeRequired = errors.New("tokensigner: token must declare its type")
	// ErrEmptyConfirmation — привязка запрошена и не заполнена. Токен с
	// пустым отпечатком выглядел бы привязанным и не был бы им.
	ErrEmptyConfirmation = errors.New("tokensigner: confirmation was requested but carries no thumbprint")
	// ErrNoSigningKey — подписывающего ключа нет. Отказ, а не подпись
	// умолчанием.
	ErrNoSigningKey = errors.New("tokensigner: no signing key")
)

// Clock — источник времени подписанта.
type Clock func() time.Time

// SigningMaterial — подписной материал, отданный ключницей: приватная половина
// уже развёрнута, алгоритм закреплён за ключом.
type SigningMaterial struct {
	KID           domain.KeyID
	Algorithm     domain.SigningAlgorithm
	PrivateKeyPEM []byte
	PublicKeyPEM  string
}

// KeyProvider — порт ключницы. Определён здесь, у вызывающего, а реализован
// адаптером: подписант не знает ни про базу, ни про обёртку.
type KeyProvider interface {
	ActiveSigningKey(ctx context.Context) (SigningMaterial, error)
}

// Confirmation — привязка токена к ключу владельца.
//
// Значение берётся из ПРЕДЪЯВЛЕННОГО при выдаче материала — отпечатка ключа
// доказательства владения либо отпечатка клиентского сертификата — и никогда
// не выдумывается подписантом.
type Confirmation struct {
	// JKT — отпечаток ключа доказательства владения (RFC 9449).
	JKT string
	// X5TS256 — отпечаток клиентского сертификата (RFC 8705).
	X5TS256 string
}

func (c Confirmation) empty() bool { return c.JKT == "" && c.X5TS256 == "" }

// Request — вход выпуска.
type Request struct {
	Subject   string
	Audience  []string
	TokenType string
	TTL       time.Duration
	// Confirmation — привязка. nil означает «не запрашивали», и это законно
	// для человеческого принципала.
	Confirmation *Confirmation
	// Claims — дополнительные утверждения контура. Зарезервированные имена
	// отсюда не берутся: состав, на котором держится проверка, собирает
	// подписант, а не вызывающий.
	Claims map[string]any
}

// Token — выпущенный токен.
type Token struct {
	Token     string
	KID       domain.KeyID
	JTI       string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// Config — настройка подписанта. Каждое поле ОБЯЗАТЕЛЬНО: незаданное здесь
// означало бы «не сужаем», а не «по умолчанию».
type Config struct {
	Issuer      string
	Clock       Clock
	MaxTokenTTL time.Duration
}

// Signer — подписант.
type Signer struct {
	cfg  Config
	keys KeyProvider
}

// New строит подписанта. Неполная настройка — ОТКАЗ ПОСТРОЕНИЯ, а не
// умолчание: подписант, собранный наполовину, выпускал бы токены, которые
// проверяющий обязан отвергнуть, — и узналось бы это на первом запросе.
func New(cfg Config, keys KeyProvider) (*Signer, error) {
	switch {
	case cfg.Issuer == "":
		return nil, fmt.Errorf("tokensigner: issuer is required")
	case cfg.Clock == nil:
		return nil, fmt.Errorf("tokensigner: clock is required (time source is an input, not the environment)")
	case cfg.MaxTokenTTL <= 0:
		return nil, fmt.Errorf("tokensigner: max token lifetime must be declared as a positive number")
	case keys == nil:
		return nil, fmt.Errorf("tokensigner: key provider is required")
	}
	return &Signer{cfg: cfg, keys: keys}, nil
}

// MaxTokenTTL возвращает объявленный потолок срока. Читается арифметикой
// отсрочки снятия ключа — она берёт слагаемое отсюда, а не из своей копии.
func (s *Signer) MaxTokenTTL() time.Duration { return s.cfg.MaxTokenTTL }

// Issuer возвращает объявленного издателя.
func (s *Signer) Issuer() string { return s.cfg.Issuer }

// Sign выпускает токен подписывающим ключом ключницы.
func (s *Signer) Sign(ctx context.Context, req Request) (Token, error) {
	if err := validate(req, s.cfg.MaxTokenTTL); err != nil {
		return Token{}, err
	}
	mat, err := s.keys.ActiveSigningKey(ctx)
	if err != nil {
		return Token{}, fmt.Errorf("%w: %w", ErrNoSigningKey, err)
	}
	method, err := signingMethod(mat.Algorithm)
	if err != nil {
		return Token{}, err
	}
	key, err := parsePrivateKey(mat.Algorithm, mat.PrivateKeyPEM)
	if err != nil {
		return Token{}, err
	}

	now := s.cfg.Clock().UTC().Truncate(time.Second)
	exp := now.Add(req.TTL)
	jti := ids.NewID("tok")

	claims := jwt.MapClaims{}
	// Дополнительные утверждения кладутся ПЕРВЫМИ, поэтому ни одно из них не
	// может переписать состав, на котором держится проверка.
	for k, v := range req.Claims {
		claims[k] = v
	}
	claims["iss"] = s.cfg.Issuer
	claims["sub"] = req.Subject
	claims["aud"] = req.Audience
	claims["iat"] = now.Unix()
	claims["nbf"] = now.Unix()
	claims["exp"] = exp.Unix()
	claims["jti"] = jti
	if req.Confirmation != nil {
		cnf := map[string]any{}
		if req.Confirmation.JKT != "" {
			cnf["jkt"] = req.Confirmation.JKT
		}
		if req.Confirmation.X5TS256 != "" {
			cnf["x5t#S256"] = req.Confirmation.X5TS256
		}
		claims["cnf"] = cnf
	}

	tok := jwt.NewWithClaims(method, claims)
	tok.Header["kid"] = string(mat.KID)
	tok.Header["typ"] = req.TokenType

	raw, err := tok.SignedString(key)
	if err != nil {
		// Причина не пересказывается наружу: наружу уходит опознавательное
		// слово, подробность — вызывающему в журнал.
		return Token{}, fmt.Errorf("tokensigner: sign: %w", err)
	}
	return Token{Token: raw, KID: mat.KID, JTI: jti, IssuedAt: now, ExpiresAt: exp}, nil
}

func validate(req Request, ceiling time.Duration) error {
	if req.TTL <= 0 {
		return ErrExpiryRequired
	}
	if req.TTL > ceiling {
		return fmt.Errorf("%w: %s > %s", ErrTTLAboveCeiling, req.TTL, ceiling)
	}
	if req.Subject == "" {
		return ErrSubjectRequired
	}
	if len(req.Audience) == 0 {
		return ErrAudienceRequired
	}
	for _, a := range req.Audience {
		if a == "" {
			return ErrAudienceRequired
		}
	}
	if req.TokenType == "" {
		return ErrTokenTypeRequired
	}
	if req.Confirmation != nil && req.Confirmation.empty() {
		return ErrEmptyConfirmation
	}
	return nil
}

// signingMethod переводит закреплённый за ключом алгоритм в метод подписи.
//
// Словарь ЗАКРЫТ: алгоритм вне него — отказ, а не «подписать чем-нибудь».
func signingMethod(alg domain.SigningAlgorithm) (jwt.SigningMethod, error) {
	switch alg {
	case domain.SigningAlgRS256:
		return jwt.SigningMethodRS256, nil
	case domain.SigningAlgES256:
		return jwt.SigningMethodES256, nil
	case domain.SigningAlgEdDSA:
		return jwt.SigningMethodEdDSA, nil
	default:
		return nil, fmt.Errorf("tokensigner: signing algorithm %q is not one of %v", alg, domain.SigningAlgorithms())
	}
}

func parsePrivateKey(alg domain.SigningAlgorithm, pemBytes []byte) (any, error) {
	switch alg {
	case domain.SigningAlgRS256:
		k, err := jwt.ParseRSAPrivateKeyFromPEM(pemBytes)
		if err != nil {
			return nil, fmt.Errorf("tokensigner: parse signing key: %w", err)
		}
		return k, nil
	case domain.SigningAlgES256:
		k, err := jwt.ParseECPrivateKeyFromPEM(pemBytes)
		if err != nil {
			return nil, fmt.Errorf("tokensigner: parse signing key: %w", err)
		}
		return k, nil
	case domain.SigningAlgEdDSA:
		k, err := jwt.ParseEdPrivateKeyFromPEM(pemBytes)
		if err != nil {
			return nil, fmt.Errorf("tokensigner: parse signing key: %w", err)
		}
		return k, nil
	default:
		return nil, fmt.Errorf("tokensigner: signing algorithm %q is not one of %v", alg, domain.SigningAlgorithms())
	}
}
