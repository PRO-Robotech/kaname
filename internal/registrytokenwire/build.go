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

	registrytokenuc "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/registry_token"
	"github.com/PRO-Robotech/kaname/internal/handler/registrytokenhttp"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/tokensigner"
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
	// Scope — объём, который полоса кладёт в выпускаемый токен (пусто — не
	// кладёт).
	Scope string
	// AnonymousClientID — объявленный публичный принципал анонимного чтения
	// (RG-1 D-7): субъект токена, который приёмная сторона резолвит в
	// подстановочного `user:*`. Пусто (умолчание) — анонимный поток ВЫКЛЮЧЕН, и
	// вход без удостоверения получает 401-вызов (secure-by-default).
	AnonymousClientID string
	// Signer — НАШ подписант, ЕДИНСТВЕННЫЙ издатель полосы. Обязателен: без него
	// сборка отказывает (kaname#494), другого издателя у полосы нет.
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

	// BasicCredentialTimeout — предел ОДНОГО обращения авторитета о базовом
	// секрете к базе (kaname#379). Обязателен: без него сборка отказывает.
	//
	// Предел подаётся авторитету, а не ставится этой полосой у своего вызова:
	// у авторитета вызывающих больше одного, и оператор у них один. Величину
	// объявляет композиционный корень — ту же, что у полос выдачи токена:
	// для строки удостоверения человека оператор читает и отсечку
	// отзыва-всех.
	BasicCredentialTimeout time.Duration
}

// Build assembles the registry `/iam/token` shim from a pgx pool: the authority
// on the presented BASIC ACCESS TOKEN (the only credential kind this lane accepts,
// задача #1143) and OUR signer, the lane's only issuer. The caller mounts the
// returned mux on an EXTERNAL-reachable HTTP listener.
//
// Composition root only — this is the single wire-up call for serve.go. The shim
// mints the registry token itself through NewLocalMinter, and the data-plane
// verifies it against OUR key set published by the cluster-internal key-set
// listener (internal/handler/jwksproxyhttp, record keyed by our issuer). The shim
// decrypts no at-rest signing key: key material lives in the signer's keystore,
// not here.
//
// # Без нашего подписанта — отказ в старте (kaname#494)
//
// Прежде пустой подписант выбирал другую дорогу — обмен подписанного
// утверждения у внешнего поставщика. Дорога снята, и пустой подписант выбирать
// больше нечего: собранная без него полоса поднималась бы Ready и не выдавала бы
// ни одного токена. Поэтому это ПЕРВЫЙ отказ сборки, до всякого другого её
// входа, и он называет оба выхода оператора. Режима посадки сборка не читает —
// отказ один на любую посадку.
func Build(pool *pgxpool.Pool, cfg BuildConfig) (*http.ServeMux, error) {
	if cfg.Signer == nil {
		return nil, fmt.Errorf(
			"registrytokenwire: the docker-token lane has no issuer — our own signer is not wired, " +
				"and the lane has no other one. Enable authn.token-signing.enabled, or declare " +
				"api-server.registry-token.endpoint empty in the settings file so the lane is not raised")
	}
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
	useCase, err := registrytokenuc.NewIssueRegistryTokenUseCase(registrytokenuc.Config{
		// Внешняя граница ЭТОЙ полосы — служба реестра, объявленная посадкой.
		// Ровно её реестр называет докер-клиенту в вызове на аутентификацию, и
		// ровно её клиент возвращает в `?service=`; всё прочее эта полоса не
		// обслуживает by construction. Перечнем, а не строкой: расширить его
		// станет правкой настройки, а не правкой кода.
		AllowedAudiences: []string{cfg.Service},
		DefaultService:   cfg.Service,
		Scope:            cfg.Scope,
		// Anonymous-pull identity (RG-1 D-7). Empty → anonymous pull disabled
		// (no-Basic-creds → 401 challenge).
		Anonymous: registrytokenuc.AnonymousIdentity{ClientID: cfg.AnonymousClientID},
	}, NewLocalMinter(cfg.Signer, cfg.TokenTTL))
	if err != nil {
		return nil, fmt.Errorf("registrytokenwire: %w", err)
	}

	// ПОЛОСА БАЗОВОГО СЕКРЕТА (#1142) — ЕДИНСТВЕННАЯ полоса предъявленного
	// удостоверения после задачи #1143. Авторитет — тот же пул, что и у прочих
	// читателей, и тот же объявленный корнем предел на обращение: своей связи и
	// своих величин полоса не заводит.
	//
	// Провязка безусловна: полоса, объявленная и не провязанная, — мёртвый
	// контроль. Непровязанная, она отвечала бы недоступностью издателя на
	// КАЖДЫЙ вход в реестр, и заметить это можно было бы только по жалобе
	// клиента.
	basicAuthority, err := kanamepg.NewBasicCredentialRepo(pool, cfg.BasicCredentialTimeout)
	if err != nil {
		return nil, fmt.Errorf("registrytokenwire: %w", err)
	}
	useCase = useCase.WithBasicCredentialResolver(basicAuthority)

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
			registrytokenuc.NewSAKeyValidator(NewSAClientLookup(kanamepg.NewSAOAuthClientRepo(pool))),
		)
	}

	tokenHandler := registrytokenhttp.NewTokenHandler(registrytokenhttp.Config{
		Realm:          cfg.Realm,
		DefaultService: cfg.Service,
	}, useCase).WithLogger(cfg.Logger)

	return registrytokenhttp.NewMux(tokenHandler), nil
}
