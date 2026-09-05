// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// mint_endtoend_integration_test.go — бутстрап-удостоверение выпускается НА
// ПОДНЯТОЙ С НУЛЯ базе, без внешней стороны, и оно того вида, который принимает
// край (задача #1119, предикаты снятия п.2 и п.3).
//
// # Почему пакет ВНЕШНИЙ (`bootstrap_token_test`)
//
// Проба собирает контур ТЕМ ЖЕ кодом, каким его собирает процесс: настоящий
// use-case, настоящий переходник чеканки, настоящий подписант и настоящее
// объявление состава утверждений. Внутренний тестовый пакет этого не может —
// переходник живёт в сборке, а она импортирует use-case, и цикл замкнулся бы.
//
// Копию переходника писать нельзя: дублёр, выполняющий контракт СВОЕЙ копией,
// делает невидимым ровно тот дефект, ради которого его подставляют.
//
// # Что здесь ПОДСТАВНОЕ и почему это законно
//
// Ключница. Настоящая держит приватную половину в базе под обёрткой, и её
// предмет — хранение ключа, а не форма выпущенного токена. Подписант при этом
// НАСТОЯЩИЙ: `kid`, срок, тип, издатель и состав проставляет он.
package bootstrap_token_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	bootstraptoken "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/bootstrap_token"
	"github.com/PRO-Robotech/kacho-iam/internal/bootstraptokenwire"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
	"github.com/PRO-Robotech/kacho-iam/internal/service"
	"github.com/PRO-Robotech/kacho-iam/internal/tokensigner"
	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"
	"github.com/PRO-Robotech/kacho/pkg/tokenpolicy"
)

const (
	testIssuer   = "https://iam.kacho.local"
	testAudience = "https://api.kacho.cloud"
)

// memKeys — ключница в памяти: держит один подписывающий ключ ES256.
type memKeys struct {
	kid  domain.KeyID
	priv *ecdsa.PrivateKey
	pem  []byte
}

func newMemKeys(t *testing.T) *memKeys {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)
	return &memKeys{
		kid:  domain.KeyID("key-under-test"),
		priv: priv,
		pem:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}),
	}
}

func (k *memKeys) ActiveSigningKey(context.Context) (tokensigner.SigningMaterial, error) {
	return tokensigner.SigningMaterial{
		KID:           k.kid,
		Algorithm:     domain.SigningAlgES256,
		PrivateKeyPEM: k.pem,
	}, nil
}

// enrichSAPort / ownClientPort — переходники чтения, зеркалящие те, что собирает
// композиционный корень. Тонкие: ни одной строки политики.
type enrichSAPort struct{ sa *kachopg.SAOAuthClientRepo }

func (p enrichSAPort) LookupByOAuthClientID(ctx context.Context, id domain.OAuthClientID) (domain.ServiceAccountOAuthClient, error) {
	return p.sa.GetByOAuthClientID(ctx, id)
}

func (p enrichSAPort) FindByExternalSubject(ctx context.Context, issuer, sub string) (domain.ServiceAccountOAuthClient, error) {
	return p.sa.FindByExternalSubject(ctx, issuer, sub)
}

func (p enrichSAPort) GetServiceAccount(ctx context.Context, id domain.ServiceAccountID) (domain.ServiceAccount, error) {
	return p.sa.GetServiceAccount(ctx, id)
}

type ownClientPort struct {
	sa    *kachopg.SAOAuthClientRepo
	users *kachopg.UserOAuthClientRepo
}

func (p ownClientPort) GetUserToken(ctx context.Context, id domain.UserOAuthClientID) (domain.UserOAuthClient, error) {
	return p.users.Get(ctx, id)
}

func (p ownClientPort) GetSAKey(ctx context.Context, id domain.SAOAuthClientID) (domain.ServiceAccountOAuthClient, error) {
	return p.sa.Get(ctx, id)
}

// TestBootstrapTokenIsMintedByUsAndLooksLikeWhatTheEdgeAccepts — свежая база,
// никакой внешней стороны, на выходе — предъявитель, чью подпись, издателя,
// адресата, тип и принципала проверяет край.
//
// Утверждается СОДЕРЖИМОЕ выданного, а не «функция не позвана»: последнее
// зеленело бы на реализации, выдающей строку, которую край отвергнет.
func TestBootstrapTokenIsMintedByUsAndLooksLikeWhatTheEdgeAccepts(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres в контейнере: пропуск под -short, прогон — make test-pg-outside-selection")
	}
	ctx := context.Background()
	dsn := pgtest.NewDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	keys := newMemKeys(t)
	signer, err := tokensigner.New(tokensigner.Config{
		Issuer:      testIssuer,
		Clock:       time.Now,
		MaxTokenTTL: tokenpolicy.MaxTokenTTL,
	}, keys)
	require.NoError(t, err)

	saRepo := kachopg.NewSAOAuthClientRepo(pool)
	userRepo := kachopg.NewUserOAuthClientRepo(pool)
	users := kachopg.NewUserPoolRepo(pool)
	claims := service.NewTokenEnrichmentService(
		service.TokenEnrichmentConfig{Domain: "api.kacho.cloud", HydraIssuer: testIssuer},
		users,
	).
		WithSAPort(enrichSAPort{sa: saRepo}).
		WithOwnClientPort(ownClientPort{sa: saRepo, users: userRepo})

	// Сборка — ТА ЖЕ, что у процесса, и ни одного поля про внешнюю сторону в ней
	// нет: подставить поставщика в этот прогон НЕЛЬЗЯ — не «мы не стали», а
	// «нечем».
	handler, err := bootstraptokenwire.Build(pool, bootstraptokenwire.BuildConfig{
		SigningKeyPEM:   genBootstrapKeyPEM(t),
		Signer:          signer,
		Claims:          claims,
		GatewayAudience: testAudience,
		TokenTTL:        bootstraptoken.MaxTTL,
	})
	require.NoError(t, err)

	res, err := handler.MintBootstrapToken(ctx, nil)
	require.NoError(t, err, "свежая база + наш подписант обязаны дать удостоверение без внешней стороны")
	require.NotEmpty(t, res.GetAccessToken())
	require.Equal(t, "Bearer", res.GetTokenType())

	// ── то, что проверяет край ──────────────────────────────────────────────
	parsed, err := jwt.Parse(res.GetAccessToken(), func(tok *jwt.Token) (any, error) {
		return &keys.priv.PublicKey, nil
	}, jwt.WithValidMethods([]string{"ES256"}),
		jwt.WithIssuer(testIssuer),
		jwt.WithAudience(testAudience))
	require.NoError(t, err, "подпись, издатель и адресат обязаны сойтись — иначе край отвергнет")
	require.True(t, parsed.Valid)
	require.Equal(t, string(keys.kid), parsed.Header["kid"],
		"без `kid` край не выберет ключ из набора")
	require.Equal(t, tokenpolicy.TokenTypeAccess, parsed.Header["typ"],
		"полоса нашего издателя требует объявленного типа")

	mc, ok := parsed.Claims.(jwt.MapClaims)
	require.True(t, ok)
	// ПРИНЦИПАЛ. Смена чеканки не вправе тихо сменить того, за кого говорит
	// токен: край резолвит его по этим утверждениям, а не по `sub`.
	require.Equal(t, "service_account", mc["kacho_principal_type"])
	require.Equal(t, bootstraptoken.DeriveIdentity().SvaID, mc["kacho_principal_id"])
	require.Equal(t, bootstraptoken.DeriveIdentity().SocID, mc["kacho_sa_key_id"])
	require.Equal(t, bootstraptoken.DeriveIdentity().SvaID, res.GetPrincipalId())
	// `sub` называет ТОГО ЖЕ принципала. Край сегодня резолвит его по утверждениям
	// выше, но `sub` читают журнал и всякий сторонний потребитель токена: субъект
	// с двумя именами дал бы две записи об одном действии.
	//
	// Утверждение добавлено ПОСЛЕ инъекции: подмена субъекта на постороннего
	// проходила молча, потому что проба спрашивала только про утверждения.
	sub, serr := parsed.Claims.GetSubject()
	require.NoError(t, serr)
	require.Equal(t, bootstraptoken.DeriveIdentity().SvaID, sub)
	// Срок сообщается тот, что стоит в токене.
	exp, err := parsed.Claims.GetExpirationTime()
	require.NoError(t, err)
	require.Equal(t, exp.Unix(), res.GetExpiresAt().AsTime().Unix())
}

// TestBootstrapMintRefusesToBuildWithoutOurSigner — контур объявлен включённым,
// а выпускать нечем ⇒ ОТКАЗ ПОСТРОЕНИЯ.
//
// Положительный контроль к пробе выше: без него «собралось» зеленело бы и на
// сборке, которая молча отдаёт handler, отвечающий отказом на первом запросе —
// то есть тогда, когда кластер поднимают и чинить уже поздно.
func TestBootstrapMintRefusesToBuildWithoutOurSigner(t *testing.T) {
	_, err := bootstraptokenwire.Build(nil, bootstraptokenwire.BuildConfig{
		SigningKeyPEM:   genBootstrapKeyPEM(t),
		GatewayAudience: testAudience,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "token-signing",
		"отказ обязан назвать ручку, иначе оператору нечего чинить")
}

// TestBootstrapMintDisabledBuildsQuietly — выключенный контур собирается без
// подписанта: выключенное — законное состояние, а не полусобранная зависимость.
func TestBootstrapMintDisabledBuildsQuietly(t *testing.T) {
	h, err := bootstraptokenwire.Build(nil, bootstraptokenwire.BuildConfig{
		GatewayAudience: testAudience,
	})
	require.NoError(t, err)
	require.NotNil(t, h)
}

func genBootstrapKeyPEM(t *testing.T) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}
