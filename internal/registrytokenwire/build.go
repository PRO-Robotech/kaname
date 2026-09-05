// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package registrytokenwire

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	registrytokenuc "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/registry_token"
	"github.com/PRO-Robotech/kacho-iam/internal/handler/registrytokenhttp"
	kachopg "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
	"github.com/PRO-Robotech/kacho-iam/internal/tokensigner"
)

// BuildConfig — the composition inputs for the registry `/iam/token` shim.
type BuildConfig struct {
	// Logger — журнал причин отказа выдачи. Наружу тело фиксировано; без этого
	// поля причина не уходила никуда, и разные по природе отказы выглядели
	// одинаково. nil допустим — тогда журналирования нет.
	Logger *slog.Logger
	// Realm — the WWW-Authenticate realm URL advertised to docker clients
	// (e.g. https://api.kacho.local/iam/token). Must match the data-plane's
	// advertised Bearer realm.
	Realm string
	// Service — the default registry service name (→ requested token audience +
	// WWW-Authenticate service, e.g. registry.kacho.local).
	Service string
	// HydraTokenURL — the Hydra public token endpoint the shim POSTs the exchange
	// to (cluster-internal in production, e.g.
	// http://kacho-umbrella-hydra-public.<ns>.svc:4444/oauth2/token).
	HydraTokenURL string
	// AssertionAudience — the `aud` of the client_assertion: the Hydra token
	// endpoint URL Hydra recognises (its external issuer's token endpoint).
	AssertionAudience string
	// Scope — optional scope requested from Hydra.
	Scope string
	// AnonymousClientID / AnonymousKeyID / AnonymousPrivateKeyPEM — the configured
	// public-principal identity the shim authenticates as for anonymous pull (RG-1
	// D-7). The data-plane resolves this client_id's token to the FGA wildcard
	// `user:*`. Empty (the default) leaves anonymous pull DISABLED — no-Basic-creds
	// then fails closed to a 401 challenge (secure-by-default; anon is opt-in).
	// HydraTokenCAFile — the anchor the hop to the provider's token endpoint is
	// verified against, when the profile pins one. Empty ⇒ the default transport,
	// which is what a plaintext in-cluster address needs; the production boot guard
	// is what forbids claiming https without an anchor.
	HydraTokenCAFile       string
	AnonymousClientID      string
	AnonymousKeyID         string
	AnonymousPrivateKeyPEM string
	// Signer — НАШ подписант. nil означает «контур ещё на прежнем издателе»:
	// законное состояние до перевода, а не полусобранная зависимость.
	Signer *tokensigner.Signer
	// TokenTTL — срок выпускаемого токена контура. Слагаемое арифметики
	// отсрочки снятия ключа, поэтому объявлено числом, а не выведено.
	TokenTTL time.Duration

	// KeyMaterialWindowUntil — ОКНО ПЕРЕХОДА ЛОМАЮЩЕГО ИЗМЕНЕНИЯ #1143:
	// мгновение, до которого полоса ПРОДОЛЖАЕТ принимать ключевой материал в
	// поле пароля наряду с базовым токеном доступа. Нулевое — окна нет
	// (умолчание, fail-closed).
	//
	// Приезжает РАЗОБРАННЫМ из настройки: разбор живёт у стража старта, а не
	// здесь, иначе неразборчивое значение доживало бы до первого входа клиента.
	// Разбор нормы, цена обоих умолчаний и предикат снятия —
	// registry_token/key_material_window.go.
	KeyMaterialWindowUntil time.Time

	// CredentialKindObserver — счётчик исходов полос по виду предъявленного
	// удостоверения. nil → счёта нет; решения полосы это не меняет.
	//
	// Единственное НАБЛЮДАЕМОЕ различие между закрытым и открытым окном: наружу
	// оба отвечают одинаково (различимость снаружи была бы оракулом посадки).
	// Без него оператор не знает ни скольких ломает закрытое окно, ни когда
	// открытое можно закрыть.
	CredentialKindObserver registrytokenuc.CredentialKindObserver
}

// Build assembles the registry `/iam/token` shim from a pgx pool: the authority
// on the presented BASIC ACCESS TOKEN (the only credential kind this lane accepts,
// задача #1143), plus the ES256 client_assertion signer and the Hydra token
// exchanger the ANONYMOUS flow still needs on a contour not yet moved to our own
// minting. The caller mounts the returned mux on an EXTERNAL-reachable HTTP
// listener.
//
// Composition root only — this is the single wire-up call for serve.go. Unlike
// the deprecated RS256 signer, the shim needs NO JWKS encryption key: it does not
// mint tokens (Hydra does) and does not decrypt any at-rest signing key. The
// data-plane's verification keys are Hydra's, served via the separate
// cluster-internal jwks-proxy mirror (internal/handler/jwksproxyhttp) — not by this
// `/iam/token` shim.
func Build(pool *pgxpool.Pool, cfg BuildConfig) (*http.ServeMux, error) {
	// Страж построения полосы: без объявленного адресата выдача чеканит тому,
	// кого назовёт вызывающий (задача #1184).
	//
	// Отказ ЗДЕСЬ — отказ в старте, видимый оператору сразу и называющий
	// настройку. Пропустив пустое, мы получили бы полосу, выдающую
	// удостоверение поверхности, которую посадка не объявляла, — и это не
	// проявилось бы ничем: запрос проходит, токен выдаётся, клиент доволен.
	if strings.TrimSpace(cfg.Service) == "" {
		return nil, fmt.Errorf(
			"registrytokenwire: api-server.registry-token.service is empty — it is the audience this " +
				"lane is declared to mint for, and an unset one means «mint for whatever the caller names»")
	}
	signer := registrytokenuc.ES256AssertionSigner{}
	// Полоса обмена выбирается по тому, ПЕРЕВЕДЁН ли контур на свою чеканку:
	// переведённый к прежнему издателю не ходит ни одним путём, поэтому дорога к
	// нему не строится и её пригодность ничего не решает. Непереведённый требует
	// её ровно как прежде. Разбор — provider_hop.go.
	exchanger, err := providerExchangeFor(cfg)
	if err != nil {
		return nil, err
	}

	useCase := registrytokenuc.NewIssueRegistryTokenUseCase(registrytokenuc.Config{
		AssertionAudience: cfg.AssertionAudience,
		// Внешняя граница ЭТОЙ полосы — служба реестра, объявленная посадкой.
		// Ровно её реестр называет докер-клиенту в вызове на аутентификацию, и
		// ровно её клиент возвращает в `?service=`; всё прочее эта полоса не
		// обслуживает by construction. Перечнем, а не строкой: расширить его
		// станет правкой настройки, а не правкой кода.
		AllowedAudiences: []string{cfg.Service},
		DefaultService:   cfg.Service,
		Scope:            cfg.Scope,
		// Anonymous-pull identity (RG-1 D-7). Empty → anonymous pull disabled; the
		// shim then serves the SA-key path only (no-Basic-creds → 401 challenge).
		Anonymous: registrytokenuc.AnonymousIdentity{
			ClientID:      cfg.AnonymousClientID,
			KeyID:         cfg.AnonymousKeyID,
			PrivateKeyPEM: cfg.AnonymousPrivateKeyPEM,
		},
	}, signer, exchanger)

	// ПОЛОСА БАЗОВОГО СЕКРЕТА (#1142) — ЕДИНСТВЕННАЯ полоса предъявленного
	// удостоверения после задачи #1143. Авторитет — тот же пул, что и у прочих
	// читателей: своей связи и своих величин полоса не заводит.
	//
	// Провязка безусловна: полоса, объявленная и не провязанная, — мёртвый
	// контроль. Непровязанная, она отвечала бы недоступностью издателя на
	// КАЖДЫЙ вход в реестр, и заметить это можно было бы только по жалобе
	// клиента.
	useCase = useCase.WithBasicCredentialResolver(kachopg.NewBasicCredentialRepo(pool))

	// СЧЁТЧИК ИСХОДОВ — до окна: он обязан считать и отказы прежнему виду,
	// то есть работать ИМЕННО ТОГДА, когда окна нет. Счётчик, провязываемый
	// вместе с окном, молчал бы ровно на той посадке, ради которой заведён.
	useCase = useCase.WithCredentialKindObserver(cfg.CredentialKindObserver)

	// ОКНО ПЕРЕХОДА #1143. Мгновение и проверяющий уезжают ОДНИМ вызовом:
	// порознь они дают два неисправных состояния, и оба выглядят настроенными
	// (разбор — registry_token/key_material_window.go).
	//
	// Проверяющий строится ТОЛЬКО при объявленном окне: собранный безусловно,
	// он был бы полосой приёма снятого вида, ждущей одного флажка, — а
	// объявленное и неисполнимое окно, наоборот, обещало бы оператору приём,
	// которого нет.
	if !cfg.KeyMaterialWindowUntil.IsZero() {
		useCase = useCase.WithKeyMaterialWindow(
			cfg.KeyMaterialWindowUntil,
			registrytokenuc.NewSAKeyValidator(NewSAClientLookup(kachopg.NewSAOAuthClientRepo(pool))),
		)
	}

	if cfg.Signer != nil {
		// Контур переводится на СВОЮ чеканку. Прежний издатель на нём больше
		// не звучит; окно двух издателей закрывается сроком уже выданных
		// токенов, а не решением.
		useCase = useCase.WithLocalMinter(NewLocalMinter(cfg.Signer, cfg.TokenTTL))
	}

	tokenHandler := registrytokenhttp.NewTokenHandler(registrytokenhttp.Config{
		Realm:          cfg.Realm,
		DefaultService: cfg.Service,
	}, useCase).WithLogger(cfg.Logger)

	return registrytokenhttp.NewMux(tokenHandler), nil
}
