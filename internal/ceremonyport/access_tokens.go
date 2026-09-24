// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package ceremonyport

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/PRO-Robotech/corelib/oauthceremony"
	"github.com/PRO-Robotech/corelib/tokenpolicy"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/publishedkey"
	"github.com/PRO-Robotech/kaname/internal/tokensigner"
)

// Signer — подписант службы так, как его видит порт выпуска. Реализует
// `*tokensigner.Signer`.
type Signer interface {
	Sign(ctx context.Context, req tokensigner.Request) (tokensigner.Token, error)
	// Issuer — издатель, которым подписант подписывает. Опознание сверяет
	// предъявленный токен с ним же: второго источника издателя здесь нет.
	Issuer() string
	// MaxTokenTTL — потолок срока подписанта.
	MaxTokenTTL() time.Duration
}

// KeySetSource — публикуемый набор ключей: тем же набором, которым токен
// сверяют потребители, опознание сверяет подпись здесь.
type KeySetSource interface {
	PublishedSet(ctx context.Context) ([]domain.PublishedKey, error)
}

// IssuanceRecorder — писатель записи выпуска: идентификатор выпуска →
// семейство. Реализует `(*pg.OAuthCeremonyRepo).RecordAccessToken`.
//
// Контракт, на котором стоит выпуск: запись ложится только в ЖИВОЕ семейство
// (иначе `domain.ErrAccessTokenFamilyNotLive`), и отметка отзыва семейства
// доезжает до каждой его записи — это держит схема службы, а не проверка перед
// вставкой. По записи о семействе выпуска отвечают `IsRevoked` службы отзыва и
// правило отзыва (`tokenrevocation`): других сведений о семействе токена у
// поверхностей предъявления нет (kaname#319, решение К10 вариант А).
type IssuanceRecorder interface {
	RecordAccessToken(ctx context.Context, jti, familyID string, issuedAt, expiresAt time.Time) error
}

// AccessTokens — адаптер порта выпуска и опознания токена доступа церемонии.
type AccessTokens struct {
	signer   Signer
	keys     KeySetSource
	recorder IssuanceRecorder
}

var _ oauthceremony.AccessTokenIssuer = (*AccessTokens)(nil)

// NewAccessTokens собирает адаптер. Без подписанта выпускать нечем, без набора
// нечем опознавать, без писателя записи выпуска некуда записать семейство
// выданного — сборка отказывает, а не отвечает на первом запросе.
func NewAccessTokens(signer Signer, keys KeySetSource, recorder IssuanceRecorder) (*AccessTokens, error) {
	switch {
	case signer == nil:
		return nil, errors.New("ceremonyport: access token issuer needs the service signer")
	case keys == nil:
		return nil, errors.New("ceremonyport: access token issuer needs the published key set")
	case recorder == nil:
		return nil, errors.New("ceremonyport: access token issuer needs the issuance record writer; " +
			"a token recorded in no family would outlive the revocation of its family")
	case strings.TrimSpace(signer.Issuer()) == "":
		return nil, errors.New("ceremonyport: the service signer names no issuer")
	}
	return &AccessTokens{signer: signer, keys: keys, recorder: recorder}, nil
}

// IssueAccessToken выпускает токен доступа по гранту (K2) и записывает выпуск в
// семейство гранта (K1).
//
// # Что идёт в токен — ПЕРЕЧЕНЬ, а не отбор
//
// Субъект — `grant.Session.Subject`, клиент — `grant.ClientID`, области —
// `grant.GrantedScopes`, получатели — `grant.GrantedAudiences`. Остальное
// подписант кладёт сам (`iss`, `iat`, `nbf`, `exp`, `jti`). Запрошенное
// (`Requested*`), протокольные поля запроса (`Form`) и утверждения сеанса
// (`Session.Claims`, `Session.Username`) в токен не идут: перечень собирается
// здесь поимённо, и поля, которого в нём нет, выпуск не видит.
//
// # Семейство — в ЗАПИСИ выпуска, а не в токене
//
// Семейство выданного (`grant.GrantID`) ложится записью jti → семейство, и по
// ней о семействе отвечают все поверхности предъявления, включая край, который
// спрашивает службу отзыва по одному jti. Утверждение, несущее семейство, было
// бы вторым хранилищем того же решения со своим писателем и своей уборкой
// (kaname#319, решение К10 вариант А).
//
// Запись ложится ПОСЛЕ подписи — jti, iat и exp чеканит подписант — и ДО того,
// как токен уедет. Её отказ роняет выпуск: токен без записи правило отзыва
// читает как «семейству не принадлежит», и отзыв семейства его не снял бы.
// Выпуск в уже отозванное семейство (опередивший на одновременном повторе кода
// прочитал семейство живым до отметки) поэтому не состоится: запись в
// отозванное семейство схема не принимает. Выпуск, записанный раньше отметки,
// снимает сама отметка — она доезжает до каждой записи семейства.
//
// # Чего выпуск не делает
//
// Не выпускает без границы срока, без семейства, без субъекта, без клиента и
// без выданного получателя: незаданный получатель означал бы «любой», а токен
// без семейства записать не во что.
func (a *AccessTokens) IssueAccessToken(ctx context.Context, grant oauthceremony.GrantRecord) (oauthceremony.IssuedAccessToken, error) {
	bound, named := grant.Session.ExpiresAt[oauthceremony.TokenKindAccess]
	switch {
	case !named || bound.IsZero():
		return oauthceremony.IssuedAccessToken{}, errors.New("ceremonyport: the ceremony named no expiry bound for the access token")
	case grant.GrantID == "":
		return oauthceremony.IssuedAccessToken{}, errors.New("ceremonyport: the grant names no family; " +
			"an issuance recorded in no family would outlive the revocation of its family")
	case grant.Session.Subject == "":
		return oauthceremony.IssuedAccessToken{}, errors.New("ceremonyport: the grant names no subject")
	case grant.ClientID == "":
		return oauthceremony.IssuedAccessToken{}, errors.New("ceremonyport: the grant names no client")
	case len(grant.GrantedAudiences) == 0:
		return oauthceremony.IssuedAccessToken{}, errors.New("ceremonyport: the grant names no granted audience; " +
			"a token without an audience would be good for any surface")
	}

	claims := map[string]any{"client_id": grant.ClientID}
	if len(grant.GrantedScopes) > 0 {
		// RFC 9068 §2.2.3: области — одной строкой через пробел.
		claims["scope"] = strings.Join(grant.GrantedScopes, " ")
	}
	tok, err := a.signer.Sign(ctx, tokensigner.Request{
		Subject:   grant.Session.Subject,
		Audience:  append([]string(nil), grant.GrantedAudiences...),
		TokenType: tokenpolicy.TokenTypeAccess,
		// Запрошенный срок — потолок подписанта; действительный — меньшее из
		// него и границы церемонии, и сравнивает их подписант по СВОИМ часам.
		TTL:      a.signer.MaxTokenTTL(),
		NotAfter: bound,
		Claims:   claims,
	})
	if err != nil {
		return oauthceremony.IssuedAccessToken{}, fmt.Errorf("ceremonyport: issue access token: %w", err)
	}
	if err := a.recorder.RecordAccessToken(ctx, tok.JTI, grant.GrantID, tok.IssuedAt, tok.ExpiresAt); err != nil {
		return oauthceremony.IssuedAccessToken{}, fmt.Errorf("ceremonyport: record access token issuance: %w", err)
	}
	return oauthceremony.IssuedAccessToken{
		Token:     tok.Token,
		ID:        tok.JTI,
		IssuedAt:  tok.IssuedAt,
		ExpiresAt: tok.ExpiresAt,
	}, nil
}

// IdentifyAccessToken отдаёт jti предъявленного токена этого издателя (K3).
//
// # Судится ТОЛЬКО подлинность
//
// Подпись ключом публикуемого набора (алгоритм из закрытого словаря платформы и
// закреплённый за ключом, `kid` допустимой формы, критичные заголовки понятны),
// издатель — наш, вид — токен доступа, `jti` назван. Срок НЕ судится: его судит
// церемония по записи гранта, и истёкший подлинный токен опознаётся своим jti —
// иначе отзыв по нему ответил бы успехом, не сняв семейства.
//
// # Исходов три
//
//   - подлинный → (jti, nil);
//   - не наш — чужая подпись, неизвестный `kid`, `alg` none либо HS256, битая
//     форма, непрозрачное значение, чужой издатель, не тот вид, без jti →
//     ("", ErrGrantNotFound), и никакого иного вердикта о токене;
//   - опознать не удалось — набор недоступен либо СВОЙ ключ набора не
//     разбирается → отказ операции, а не «не наш».
//
// # Предъявленное значение — секрет (K4)
//
// Оно не пишется ни в журнал (адаптер журнала не ведёт), ни в текст отказа:
// отказ «не наш» — опознаватель фундамента без подробностей, отказ операции
// несёт только причину сбоя набора.
func (a *AccessTokens) IdentifyAccessToken(ctx context.Context, token string) (string, error) {
	keys, err := a.keys.PublishedSet(ctx)
	if err != nil {
		return "", fmt.Errorf("ceremonyport: identify access token: the published key set is unavailable: %w", err)
	}
	claims := jwt.MapClaims{}
	parser := jwt.NewParser(
		// «Без подписи» и подпись общим секретом отвергаются закрытым словарём
		// алгоритмов, а не отдельной веткой, которую можно забыть.
		jwt.WithValidMethods(tokenpolicy.Algorithms()),
		// Срок и прочие утверждения времени здесь не судятся — см. шапку.
		jwt.WithoutClaimsValidation(),
	)
	// Ключ проверки выбирает правило набора — то же, что у читателя
	// предъявленного и интроспекции (`publishedkey`).
	tok, err := publishedkey.Parse(parser, token, claims, publishedkey.SetLookup(keys))
	if errors.Is(err, publishedkey.ErrUnavailable) {
		// Ключ ИЗ НАШЕГО набора не разобрался — наша поломка, а не чужой токен.
		return "", fmt.Errorf("ceremonyport: identify access token: %w", err)
	}
	if err != nil {
		return "", oauthceremony.ErrGrantNotFound
	}
	headerType, _ := tok.Header["typ"].(string)
	iss, _ := claims["iss"].(string)
	jti, _ := claims["jti"].(string)
	if iss != a.signer.Issuer() || headerType != tokenpolicy.TokenTypeAccess || jti == "" {
		return "", oauthceremony.ErrGrantNotFound
	}
	return jti, nil
}
