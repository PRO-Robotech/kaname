// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"fmt"
	"net/url"
	"strings"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/grpcsrv"
	"github.com/PRO-Robotech/kacho/pkg/tokenpolicy"

	"go.uber.org/multierr"
)

// Validate checks Config invariants (pure function — no logger, no
// side-effects).
//
// Returns a multierr containing ALL detected problems at once.
//
// Checks base fields + (in production modes) the required AuthN secrets +
// production-strict TLS invariants.
func (c Config) Validate() error {
	var errs error

	errs = multierr.Append(errs, c.validateMode())

	// Страж величин фоновой уборки (задача #1292). Зовёт ТОТ ЖЕ предикат, что и
	// построитель уборщика: две проверки об одном предмете разошлись бы молча —
	// и разошлись бы там, где расхождение не видно, ведь обе отвечают «годно»
	// на годном. Уборка с нулевой партией исполняется и не убирает ничего, то
	// есть выглядит работающей, будучи мёртвой.
	errs = multierr.Append(errs, c.Retention.Validate())

	// Страж своей чеканки токенов (задача #897). Действует в ЛЮБОМ режиме, а
	// не только в производственном: незаданный издатель и пустой перечень
	// допустимых алгоритмов означают «не сужаем» на всяком поднятом стенде, и
	// «зелёный dev» такое состояние маскирует.
	errs = multierr.Append(errs, c.AuthN.TokenSigning.Validate())

	// Страж токен-эндпоинта платформы (задача #898). Он принимает настройку
	// своей чеканки параметром: эндпоинт выпускает нашим подписантом и
	// объявляет нашего издателя единственной принимаемой формой адресата
	// утверждения, поэтому связь двух настроек проверяется там, где она есть.
	errs = multierr.Append(errs, c.AuthN.ClientToken.Validate(c.AuthN.TokenSigning, c.APIServer.RegistryToken.ListenAddress()))

	// Страж докерной полосы выдачи (задача #1184): адресат, которому она
	// чеканит, обязан входить в перечень адресатов платформы. Полос выдачи по
	// ключу служебной учётки две, и объявления обеих сверяются здесь — иначе
	// одна выдаёт удостоверение туда, куда вторая его отвергает, и решал это
	// не оператор, а порядок, в котором писались полосы.
	errs = multierr.Append(errs, c.APIServer.RegistryToken.Validate(c.AuthN.ClientToken))

	// Страж над половиной ВЫДАЧИ у контроля связанных с отправителем токенов
	// (задача #1137). Действует в любом режиме: величина, у которой нет
	// читателя, не читается и на стенде разработчика, а «зелёный dev» именно
	// это и маскирует.
	errs = multierr.Append(errs, c.validateMachineTokenBinding())

	// Срок токена контура — СЛАГАЕМОЕ арифметики отсрочки снятия ключа. Срок
	// сверх объявленного потолка не «урезается на выпуске»: молчаливое
	// урезание сделало бы слагаемое неизвестным тому, кто его настраивал, и
	// отсрочка перестала бы вычисляться. Отказ здесь виден оператору сразу;
	// отказ на выпуске виден вызывающему и выглядит неисправностью выдачи.
	if c.AuthN.TokenSigning.Enabled {
		if ttl := c.APIServer.RegistryToken.TokenTTL(); ttl > tokenpolicy.MaxTokenTTL {
			errs = multierr.Append(errs, fmt.Errorf(
				"api-server.registry-token.token-ttl is %s, above the declared ceiling %s — "+
					"the ceiling is a term of the key-removal grace arithmetic, and raising one "+
					"without the other lets a key be removed while tokens signed by it are alive",
				ttl, tokenpolicy.MaxTokenTTL))
		}
	}

	// Страж уборщика истёкших удостоверений (задача #1264). Срок докерного
	// токена — СЛАГАЕМОЕ вычисляемой нижней границы отсрочки, поэтому он
	// приходит стражу параметром из живой конфигурации: константа здесь
	// вывела бы отсрочку из-под её же основания при поднятом сроке.
	errs = multierr.Append(errs,
		c.Jobs.ExpiredCredentialReclaim.Validate(c.APIServer.RegistryToken.TokenTTL()))

	// Страж обновления снимка каталога (задача #1816). Своего слагаемого у него
	// нет: величина обязана быть положительной, потому что снимок без обновления
	// отстаёт бессрочно и при этом продолжает отвечать — то есть выглядит
	// исправным.
	errs = multierr.Append(errs, c.Jobs.CatalogSnapshot.Validate())

	// logger.level must be a known level so a typo fails fast at boot rather
	// than silently degrading observability. SlogLevel reports the allowed set.
	if _, err := c.Logger.SlogLevel(); err != nil {
		errs = multierr.Append(errs, err)
	}

	if listenAddress(c.APIServer.Endpoint) == "" {
		errs = multierr.Append(errs,
			fmt.Errorf("api-server.endpoint is empty"))
	}
	if listenAddress(c.APIServer.InternalEndpoint) == "" {
		errs = multierr.Append(errs,
			fmt.Errorf("api-server.internal-endpoint is empty"))
	}

	// Словарь принимаемых значений — НЕ свой: он приходит из дома семантики
	// строки подключения (`pkg/db`), объявленный один раз на всё дерево (задача
	// продукта #1464). Здесь судится ФОРМА значения, а не посадка: боевую ось
	// («шифруется ли канал») забрал центральный дескриптор ещё в #1406, и
	// возвращать её сюда нельзя — предмет у неё один.
	switch {
	case coredb.SSLModeConfigurable(c.Repository.Postgres.SSLMode):
	case strings.TrimSpace(c.Repository.Postgres.SSLMode) == "":
		// permitted — baseDSN will substitute "disable"
	default:
		errs = multierr.Append(errs,
			fmt.Errorf("repository.postgres.ssl-mode=%q (allowed: %s)",
				c.Repository.Postgres.SSLMode,
				strings.Join(coredb.ConfigurableSSLModes(), ", ")))
	}

	if strings.TrimSpace(c.Repository.Postgres.URL) == "" {
		errs = multierr.Append(errs,
			fmt.Errorf("repository.postgres.url is empty"))
	}

	// Круг отправителей чужой личности проверяется на ЛЮБОМ старте, а не только в
	// боевом режиме, — поэтому стоит ВНЕ ветки IsProduction (см.
	// validateTrustedForwarders).
	//
	// Эту ось судит ТАКЖЕ центральный дескриптор посадки (`pkg/servicecontract`,
	// отказ старта О1), который iam принимает в композиционном корне. Второго
	// ИСТОЧНИКА при этом не заводится, и различие тут существенное: обе стороны
	// зовут ОДНУ функцию общей библиотеки (`grpcsrv.TrustedForwarders.Require`)
	// с одними именами ручек — это второе место ВЫЗОВА, а не второй перечень
	// безопасных значений. Разойтись им не на чем: решение принимает один код.
	// Ранняя проверка здесь при этом полезна — она отказывает ещё в `main`, до
	// `runServe`.
	errs = multierr.Append(errs, c.validateTrustedForwarders())

	if c.AuthN.Mode.IsProduction() {
		errs = multierr.Append(errs, c.validateProductionAuthNSecrets())
		errs = multierr.Append(errs, c.validateProductionBootstrapMint())

		// ПОСАДКА ЛИЧНОСТИ и требования ЕЁ полосы (задача #1125). Три
		// провайдерских стража, стоявшие здесь безусловно, стали строками
		// таблицы LaneRequirements и предъявляются только под `external`: под
		// `own` внешнего поставщика нет вовсе, и требовать его адресов значило
		// бы не пускать в старт стенд, которому они не нужны ни для чего.
		//
		// Половина ПОЛНОТЫ ПРОВЯЗКИ (ValidateLaneWiring) остаётся в
		// композиционном корне: настройка объектов не видит и выразить их
		// отсутствие не может.
		errs = multierr.Append(errs, c.validateIdentityProviderLane())

		// Шифрование до собственной базы здесь БОЛЬШЕ НЕ СУДИТСЯ — сведено к
		// одному источнику (задача продукта #1406). Требование не ослаблено: тот
		// же перечень безопасных значений, один на всё дерево, судит центральный
		// дескриптор посадки (`pkg/servicecontract`, отказ старта О8), который
		// iam принимает в композиционном корне ДО открытия пула.
		//
		// Снятая копия к тому же судила НАМЕРЕНИЕ, а не исход: она читала поле
		// настройки, тогда как в пул уходит строка, собранная `Config.DSN()`, —
		// `sslmode` приходит и из сырого URL, а пустое поле деривится в
		// `disable`. Стенд, задавший режим прямо в URL, копия отвергала при
		// исправной посадке. Дескриптор читает ТУ строку, что уходит в пул.
	}

	return errs
}

// validateProductionBootstrapMint refuses to start a production binary whose
// bootstrap-admin token mint is ENABLED (the signing key is present, so the RPC
// will actually issue tokens) but has NO caller allow-list.
//
// MintBootstrapToken returns a Hydra-signed cluster `system_admin` Bearer. It
// carries no ReBAC gate by construction (it exists to obtain the FIRST token,
// before any relation exists), so the ONLY thing standing between a caller and
// full control-plane takeover is the client-certificate SPIFFE allow-list
// enforced by authzguard.CallerPolicy. With that list empty the runtime already
// denies everyone — but shipping an enabled-yet-uncallable mint is a
// misconfiguration whose usual "fix" is to reopen the hole, so it fails at boot
// with a message naming the setting (core rule #16: no WARN-and-continue guard).
//
// Scoped to the ENABLED mint: a deployment that never supplies a signing key does
// not use the mint at all and boots unchanged.
//
// Only the PRESENCE of the key is read — never its value, and the value never
// appears in the error (security.md).
func (c Config) validateProductionBootstrapMint() error {
	if !c.AuthN.BootstrapMint.Enabled() {
		return nil
	}
	if len(c.AuthN.BootstrapMint.AllowedSANs()) > 0 {
		return nil
	}
	return fmt.Errorf(
		"production mode: authn.bootstrap-mint.allowed-client-sans is empty while the bootstrap mint is enabled (%s is set) — "+
			"MintBootstrapToken issues a cluster system_admin token and must be restricted to explicit client-certificate SPIFFE SANs; "+
			"set the allow-list or unset the signing key",
		c.AuthN.BootstrapMint.ResolveSigningKeyEnv())
}

// validateTrustedForwarders refuses to start a binary that has not narrowed the
// circle of senders permitted to FORWARD an end-user identity.
//
// Both listeners build CertIdentityExtract →
// TrustedPrincipalExtract(WithTrustedForwarders(cfg.AuthN.TrustedForwarders())).
// The corelib contract (pkg/grpcsrv principalIsTrusted) narrows that circle ONLY
// on a non-empty circle; on an unnarrowed one it answers "trusted" for ANY peer
// that passed client-certificate verification, and the forwarded metadata
// identity becomes the subject of every authorization decision iam then makes.
//
// The consequence is not abstract: on :9090 iam deliberately does NOT re-ReBAC
// the end user (the api-gateway is the single authZ front door), so a neighbour
// with its own legitimate certificate would read and mutate any tenant's
// accounts, projects, groups, roles and grants, and mint personal tokens and
// service-account keys, as the named victim.
//
// The guard fires on ANY start, not only in production: a guard whose branch
// never executes on the local stand finds "the circle was left open" only on the
// production profile, where the cost of the mistake is highest. Outside
// production an unnarrowed circle stays possible, but as an EXPLICIT opt-in.
// The shared guard is grpcsrv.TrustedForwarders.Require — one outcome and one
// refusal text across all seven services; only the knob names differ. The
// central posture descriptor calls THE SAME guard with the same knob names, so
// this is a second call site rather than a second source (see Validate).
func (c Config) validateTrustedForwarders() error {
	return c.AuthN.TrustedForwarders().Require(grpcsrv.ForwarderGate{
		Production:   c.AuthN.Mode.IsProduction(),
		DevTrustAny:  c.AuthN.TrustAnyForwarder,
		SANsKnob:     "authn.trusted-forwarder-sans (env KACHO_IAM_AUTHN__TRUSTED_FORWARDER_SANS)",
		TrustAnyKnob: "authn.trust-any-forwarder (env KACHO_IAM_AUTHN__TRUST_ANY_FORWARDER)",
	})
}

// validateProductionProviderAdminHop refuses to start a production binary whose
// route to the identity provider's ADMIN API is GUESSED, or carries the
// administrative bearer in the clear.
//
// iam is the platform's sole facade to the provider: registering the OAuth2
// client behind a personal token or a service-account key, recording a trust
// grant, tearing down a login session — all of it goes over this hop, with the
// administrative bearer attached. The provider's admin API authenticates nobody;
// being able to reach it IS the authorization. So both properties below are
// load-bearing, and they fail for different reasons.
//
// DECLARED, NOT DERIVED. The address falls back to a derivation from the issuer
// ("hydra.X" → "hydra-admin.X", else "https://hydra-admin.<domain>"). A derived
// address is never empty, so the facade reads as configured on a profile that
// never declared it — and the derivation yields the PUBLIC ingress hostname,
// which does not resolve inside the cluster. Every call then fails, or worse,
// eventually resolves to whatever answers on that public name and receives the
// administrative bearer. Requiring the declaration is the platform rule that a
// security-relevant dependency address is never worked out from a neighbour's.
//
// NOT IN THE CLEAR. Same reason the edge gateway's hop is held to it: the bearer
// is readable by anything on the path, and it opens an API that asks for nothing
// else.
//
// Only the explicit sources count as declared — the YAML setting and its ENV
// override — because those are the two an operator actually writes. dev keeps the
// derivation and tolerates plaintext: an in-process fixture has no provider, and
// a developer stand may run one without a certificate.
func (c Config) validateProductionProviderAdminHop() error {
	declared := c.AuthN.DeclaredHydraAdminURL()
	if declared == "" {
		return fmt.Errorf(
			"production mode: authn.hydra-admin-url is not declared (env override " +
				"KACHO_IAM_HYDRA_ADMIN_URL) — it then falls back to a name DERIVED from the " +
				"issuer, which is the public ingress host and does not resolve inside the " +
				"cluster; the derivation is never empty, so the facade reads as configured " +
				"while addressing a host nobody chose. Name the cluster-internal admin " +
				"Service explicitly")
	}
	u, err := url.Parse(declared)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf(
			"production mode: authn.hydra-admin-url is not an absolute http(s) URL (got %q)",
			declared)
	}
	if u.Scheme != "https" {
		return fmt.Errorf(
			"production mode: authn.hydra-admin-url is plaintext (%q) — every OAuth2 client "+
				"registration, trust grant and session teardown carries the administrative "+
				"bearer over this hop, and the admin API it opens authenticates nobody, so "+
				"anything on the path can read the credential and use it; address the admin "+
				"listener over https",
			declared)
	}
	// TLS without an anchor is not a partial improvement here. The provider's
	// in-cluster certificate is issued by the internal CA and this process trusts
	// the system roots, so every call would fail on an unknown authority — after
	// the address already reads as hardened.
	if c.AuthN.ResolveHydraAdminCAFile() == "" {
		return fmt.Errorf(
			"production mode: authn.hydra-admin-url is https (%q) but authn.hydra-admin-ca-file "+
				"is empty (env KACHO_IAM_HYDRA_ADMIN_CA_FILE) — the provider's in-cluster "+
				"certificate is issued by the internal CA and this process trusts the system "+
				"roots, so every call on the hop fails with an unknown authority; pin the "+
				"bundle together with the address",
			declared)
	}
	return nil
}

// providerPublicHop — one of iam's hops to the identity provider's PUBLIC
// listener, as the boot guard sees it: what an operator declared, what anchor was
// pinned with it, and the names to put in a refusal so a stand can be fixed
// without reading this file.
type providerPublicHop struct {
	setting     string
	env         string
	declared    string
	caSetting   string
	caEnv       string
	caFile      string
	whatItISFor string
}

// validateProductionProviderPublicHops holds the two hops to the provider's
// PUBLIC listener to the same discipline the ADMIN hop already has: the address
// is DECLARED, never worked out from a neighbour's, and TLS is never claimed
// without something to verify the peer against.
//
// DECLARED, NOT DERIVED. Both addresses fall back to a derivation from the issuer
// — `<issuer>/.well-known/jwks.json` and `<issuer>/oauth2/token`. A derivation is
// never empty, so the facade reads as configured on a profile that declared
// neither, while addressing the PUBLIC ingress hostname: in-cluster that name
// usually does not resolve at all (the JWKS mirror then fail-closes 502 and every
// docker pull gets a 401, with no line at start-up naming why), and where it does
// resolve it is not the process the operator meant. This is the platform rule that
// the address of a dependency an access decision rests on is never derived.
//
// WHAT EACH HOP CARRIES, because the two are not interchangeable:
//   - the JWKS upstream is the ONLY thing that decides which signatures the
//     data-plane accepts. iam re-serves the fetched keyset verbatim on its
//     cluster-internal mirror, so whatever answers this address chooses the
//     platform's verification keys.
//   - the token endpoint carries a signed client assertion out and the minted
//     bearer back in the response body.
//
// TRANSPORT IS NOT ASSERTED HERE, and that is a boundary, not an oversight. The
// provider serves its public listener in plain http on every profile, and the
// per-listener TLS override this version does NOT support was measured false on
// 2026-07-30 — see the note in
// deploy/helm/umbrella/templates/hydra-admin-certificate.yaml. Moving the public
// listener moves the ingress, the JWKS mirror and the token endpoint together; it
// is its own change with its own acceptance. Requiring https here would only add a
// second reason for the same stand not to boot, and the fix for it would not be
// this guard's.
//
// WHAT IS ASSERTED IS THE HALF THAT CAN BE GOT WRONG SILENTLY: the moment a
// profile writes https, an anchor must be pinned with it. Without one the process
// verifies against the SYSTEM roots, which an internal-CA certificate never chains
// to — so the address reads as hardened while every fetch fails on an unknown
// authority, and the JWKS mirror answers 502 to the whole data-plane.
//
// Only the explicit sources count as declared — the YAML setting and its ENV
// override — because those are the two an operator actually writes. dev keeps the
// derivation and tolerates anything: an in-process fixture has no provider.
// providerPublicHopKind — какой из двух публичных контуров проверяется. Их
// разделили, потому что таблица требований полос называет их РАЗНЫМИ
// обязательными элементами: набор проверочных ключей решает, чьи подписи
// принимает data-plane, а адрес обмена возит подписанное утверждение. Отказ по
// одному не есть отказ по другому, и клетка произведения у каждого своя.
type providerPublicHopKind int

const (
	providerHopJWKS providerPublicHopKind = iota
	providerHopToken
)

// providerPublicHops — объявление обоих контуров. Одно место: тексты отказов
// часть контракта оператора, и вторая копия разошлась бы с первой молча.
func (c Config) providerPublicHops() []providerPublicHop {
	return []providerPublicHop{
		{
			setting:   "authn.hydra-jwks-url",
			env:       "KACHO_IAM_HYDRA_JWKS_URL",
			declared:  c.AuthN.DeclaredHydraJWKSURL(),
			caSetting: "authn.hydra-jwks-ca-file",
			caEnv:     "KACHO_IAM_HYDRA_JWKS_CA_FILE",
			caFile:    c.AuthN.ResolveHydraJWKSCAFile(),
			whatItISFor: "the keyset this process mirrors on its cluster-internal listener is the " +
				"data-plane's only anchor for deciding whether a token was signed by the provider",
		},
		{
			setting:   "authn.hydra-token-url",
			env:       "KACHO_IAM_HYDRA_TOKEN_URL",
			declared:  c.AuthN.DeclaredHydraTokenURL(),
			caSetting: "authn.hydra-token-ca-file",
			caEnv:     "KACHO_IAM_HYDRA_TOKEN_CA_FILE",
			caFile:    c.AuthN.ResolveHydraTokenCAFile(),
			whatItISFor: "the exchange posts a signed client assertion to this address and reads the " +
				"minted bearer back out of the response body",
		},
	}
}

// validateProviderPublicHop проверяет ОДИН публичный контур поставщика.
func (c Config) validateProviderPublicHop(kind providerPublicHopKind) error {
	hops := c.providerPublicHops()
	if int(kind) < 0 || int(kind) >= len(hops) {
		return fmt.Errorf("internal: unknown provider public hop %d", int(kind))
	}
	return c.validateProviderPublicHops([]providerPublicHop{hops[kind]})
}

// validateProviderPublicHops — общее тело проверки перечня контуров.
func (c Config) validateProviderPublicHops(hops []providerPublicHop) error {
	var errs error
	for _, h := range hops {
		if h.declared == "" {
			errs = multierr.Append(errs, fmt.Errorf(
				"production mode: %s is not declared (env override %s) — it then falls back to a "+
					"name DERIVED from the issuer, which is the public ingress host and does not "+
					"resolve inside the cluster; the derivation is never empty, so the facade reads "+
					"as configured while addressing a host nobody chose. %s. Name the cluster-internal "+
					"Service explicitly", h.setting, h.env, h.whatItISFor))
			continue
		}
		u, err := url.Parse(h.declared)
		if err != nil || u.Scheme == "" || u.Host == "" {
			errs = multierr.Append(errs, fmt.Errorf(
				"production mode: %s is not an absolute http(s) URL (got %q)", h.setting, h.declared))
			continue
		}
		if u.Scheme == "https" && h.caFile == "" {
			errs = multierr.Append(errs, fmt.Errorf(
				"production mode: %s is https (%q) but %s is empty (env %s) — the provider's "+
					"in-cluster certificate is issued by the internal CA and this process trusts the "+
					"system roots, so every call on the hop fails with an unknown authority while the "+
					"address reads as hardened; pin the bundle together with the address",
				h.setting, h.declared, h.caSetting, h.caEnv))
		}
	}
	return errs
}

// validateMode ensures Mode is a known ENUM value.
func (c Config) validateMode() error {
	switch c.AuthN.Mode {
	case ModeDev, ModeProduction, ModeProductionStrict:
		return nil
	default:
		return fmt.Errorf("authn.mode invalid (got %s)", c.AuthN.Mode)
	}
}

// validateProductionAuthNSecrets requires the AuthN secrets the binary needs to
// authenticate the Ory hooks. In dev mode these may legitimately be empty (the
// hook handlers accept calls without a Bearer); in any production mode a missing
// secret is a boot-time misconfiguration that would otherwise only surface as a
// runtime fail-closed (availability risk).
//
// The JWKS encryption key is still demanded here even though nothing decrypts
// Ключ обёртки требуется потому, что им оборачивается приватная половина
// подписного ключа в ключнице (задача #897). Ручка об этом предмете в дереве
// одна, и её значение меняет исход старта: объявленная и нечитаемая ручка была
// бы мёртвым стражем.
//
// Secrets resolve from the YAML field OR the ENV indirection
// (hook-shared-secret-env / jwks-encryption-key-hex-env) — the same precedence
// the composition root uses (cmd/kacho-iam/hooks_mux.go). Only os.Getenv is read
// (no other side-effects), consistent with the Resolve* methods.
//
// Errors name WHICH setting is missing — never the secret value (security.md).
func (c Config) validateProductionAuthNSecrets() error {
	var errs error
	if strings.TrimSpace(c.AuthN.ResolveHookSharedSecret()) == "" {
		errs = multierr.Append(errs, fmt.Errorf(
			"production mode: authn.hook-shared-secret is empty (set authn.hook-shared-secret-env / KACHO_IAM_HOOK_TOKEN)"))
	}
	if _, err := c.AuthN.ResolveJWKSEncryptionKeys(); err != nil {
		// ResolveJWKSEncryptionKeys already reports WHICH setting / what shape is
		// wrong (empty, bad hex, wrong length) without echoing the value.
		errs = multierr.Append(errs, fmt.Errorf(
			"production mode: authn.jwks-encryption-key-hex invalid: %w", err))
	}
	return errs
}

// InsecureDevWarnings returns a list of non-blocking warnings about
// insecure dev-defaults. Returns nil in production mode.
func (c Config) InsecureDevWarnings() []string {
	if c.AuthN.Mode.IsProduction() {
		return nil
	}
	var out []string
	mode := strings.ToLower(c.Repository.Postgres.SSLMode)
	if mode == "" || mode == "disable" {
		out = append(out,
			"repository.postgres.ssl-mode=disable — DB plaintext (dev only)")
	}
	return out
}
