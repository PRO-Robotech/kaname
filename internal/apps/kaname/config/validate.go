// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"fmt"
	"net/url"
	"strings"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/grpcsrv"
	"github.com/PRO-Robotech/corelib/tokenpolicy"

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

	// Страж величин НАШЕГО отправителя письма приглашения (приёмка ID-MAIL-1,
	// §10 п. 20). Действует в ЛЮБОМ режиме: половина объявленного удостоверения
	// выглядит настройкой на всяком поднятом стенде, а «зелёный dev» именно это
	// и маскирует.
	//
	// ЧТО ОН НЕ СУДИТ, названо в его собственной шапке и повторяется здесь,
	// чтобы область не выводил читатель: он судит СОГЛАСОВАННОСТЬ объявленных
	// величин, а не факт объявления полосы. «Объявлена ли она вообще» — предмет
	// стража рендера профиля и шага подстановки (Р4а, места С1 и С2): у них есть
	// доступ к объявлениям профиля и к фактической величине из секрета, а здесь
	// его нет by construction.
	errs = multierr.Append(errs, c.InviteMail.Validate())

	// Страж срока приглашения (приёмка ID-MAIL-1, §10 п. 22). Действует в ЛЮБОМ
	// режиме: бессрочно выкупаемое приглашение — не дев-удобство, а
	// предъявитель, переживающий решение о составе участников.
	errs = multierr.Append(errs, c.Invite.Validate())

	// Страж своей чеканки токенов (задача #897). Действует в ЛЮБОМ режиме, а
	// не только в производственном: незаданный издатель и пустой перечень
	// допустимых алгоритмов означают «не сужаем» на всяком поднятом стенде, и
	// «зелёный dev» такое состояние маскирует.
	errs = multierr.Append(errs, c.AuthN.TokenSigning.Validate())
	errs = multierr.Append(errs, c.AuthN.PresentedCredential.Validate(c.AuthN.TokenSigning, c.AuthN.ClientToken.TokenTTL))

	// СВЯЗЫВАНИЕ «поверхность предъявления ⇒ её читатель» (задача продукта #2191).
	//
	// Отдельно от стража величин выше: тот судит согласованность величин
	// ВКЛЮЧЁННОГО читателя, а этот — противоречие между двумя объявлениями.
	// Действует в ЛЮБОМ режиме: фронт без читателя отвечает одинаково на годное
	// и на негодное на всяком поднятом стенде, и «зелёный dev» именно это и
	// маскирует.
	errs = multierr.Append(errs, c.AuthN.PresentedCredential.ValidateBinding(c.AuthN.Mode.IsProduction()))

	// Страж токен-эндпоинта платформы (задача #898). Он принимает настройку
	// своей чеканки параметром: эндпоинт выпускает нашим подписантом и
	// объявляет нашего издателя единственной принимаемой формой адресата
	// утверждения, поэтому связь двух настроек проверяется там, где она есть.
	errs = multierr.Append(errs, c.AuthN.ClientToken.Validate(c.AuthN.TokenSigning, c.APIServer.RegistryToken.ListenAddress()))
	// Величины точки авторизации (kaname#315, П4 и П5) — при собранной
	// церемонии, а не при включённом эндпоинте: без церемонии точки нет.
	errs = multierr.Append(errs, c.AuthN.ValidateCeremonyPace())

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

	// Страж доставки манифестов модулей (задача #1875). Действует в ЛЮБОМ
	// режиме: посадка, объявившая опору на манифесты и не назвавшая каталога,
	// читает пустой путь одинаково и на стенде разработчика, и в бою — а
	// «зелёный dev» именно это и маскирует.
	errs = multierr.Append(errs, c.Manifests.Validate())

	// Страж окна отзыва СОБСТВЕННОЙ ДВЕРИ (задача #2307). Действует в ЛЮБОМ
	// режиме по той же причине, что и соседи выше: окно отзыва действует на
	// всяком поднятом стенде, а «зелёный dev» маскирует именно величину,
	// которую никто не выбирал. Дверь строит кеш сама, минуя дескриптор
	// носителя, — значит и страж ей нужен свой, тот же довод у него общий с
	// `pkg/servicecontract`.
	errs = multierr.Append(errs, c.AuthZ.Validate())

	// ТРИ СОБСТВЕННЫХ ПОТОЛКА — БЕЗУСЛОВНО, а не только в боевом режиме
	// (приёмка `KAN-QUOTA-1`, `П25`; own_ceilings.go).
	//
	// Послабление по режиму завело бы посадку, в которой объявленный потолок не
	// исполняется, — то есть режим, годный только для стенда. Величина нужна
	// службе всегда: без неё списание не знает, с чем сравнивать, и первый же
	// приём аккаунта отвергается отказом «потолок не назван».
	errs = multierr.Append(errs, c.OwnCeilings.Validate())

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

	// АДРЕС БАЗЫ СУДИТСЯ ПО ХОСТУ, А НЕ ПО ПУСТОТЕ СТРОКИ.
	//
	// Прежде здесь стояла только проверка на целиком пустую строку. По пути чарта
	// она не могла сработать НИ ПРИ КАКОМ входе: шаблон собирает строку из частей
	// (`postgres://<user>@<host>:<port>/<db>`), поэтому при незаданном адресе базы
	// она выходит НЕПУСТОЙ и с пустым хостом — `postgres://iam@:5432/kaname`.
	// Предикат был уже своего предмета, и настоящий отказ оператора шёл мимо него.
	//
	// Цена измерена в кластере: установка с незаданным адресом базы не давала ни
	// отказа, ни текста — контейнер миграций оставался в `running` с НУЛЁМ байт
	// журнала, ожидая базу, которой не будет никогда. Само ожидание законно и
	// нужно (база поднимается рядом и может быть не готова); незаконно не
	// различать «ещё не поднялась» и «адрес не задан»: первое сходится само,
	// второе не сойдётся никогда.
	//
	// Форма `ключ=значение` (её тоже принимает драйвер) здесь НЕ судится: чарт её
	// не производит, а разбирать вторым способом значило бы завести второй кодек,
	// который разойдётся с первым молча.
	if dsn := strings.TrimSpace(c.Repository.Postgres.URL); dsn == "" {
		errs = multierr.Append(errs,
			fmt.Errorf("repository.postgres.url is empty"))
	} else if !DSNNamesAHost(dsn) {
		errs = multierr.Append(errs,
			fmt.Errorf("repository.postgres.url=%q names no host: the database address is not set, "+
				"and waiting for it would never converge; set the chart's db.host (or the host part of the DSN)",
				RedactDSN(dsn)))
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
	errs = multierr.Append(errs, c.validateTrustDomain())

	if c.AuthN.Mode.IsProduction() {
		errs = multierr.Append(errs, c.validateProductionAuthNSecrets())
		errs = multierr.Append(errs, c.validateProductionBootstrapMint())

		// ТРЕБОВАНИЯ ПОЛОСЫ своего входа и своей чеканки (задача #1125). Прежде
		// их выбирал ключ посадки; ключ снят вместе с внешним поставщиком
		// (kaname#363), и строки таблицы LaneRequirements предъявляются всякому
		// боевому старту.
		//
		// Половина ПОЛНОТЫ ПРОВЯЗКИ (ValidateLaneWiring) остаётся в
		// композиционном корне: настройка объектов не видит и выразить их
		// отсутствие не может.
		errs = multierr.Append(errs, c.validateLaneRequirements())

		// АДРЕСАТ выпускаемых удостоверений (задача #2127). Из `authn.domain`
		// выводится клеймо адресата, уезжающее в КАЖДОМ выпущенном токене и
		// читаемое всяким, кто токен разбирает, — без нашего исходного кода.
		//
		// Прежде значение подставляло построение, и подставляло оно доменное имя
		// ЧУЖОГО продукта: ни один профиль ручку не объявлял, поэтому адресат
		// каждого удостоверения выбирал не оператор. Стражем такая величина быть
		// не может — он зелен при любом входе, потому что незаданной она не
		// бывает; поэтому умолчание снято, а поставщик заведён в профиле.
		//
		// Ban #16: всякий развёрнутый стенд работает в production-посадке,
		// поэтому проверка здесь связывает и стенд разработчика. В in-process
		// фикстуре, не поднимающей выдачи, её предмета нет.
		errs = multierr.Append(errs, c.validateDeclaredDomain())

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

// validateDeclaredDomain requires the deployment to NAME the domain its tokens
// are addressed to.
//
// Отказ называет ПОЛЕ и ПЕРЕМЕННУЮ: оператору иначе нечего искать, а отказ, не
// восстанавливающий следующий шаг, отправляет его в цикл. Значение доменного
// имени в тексте не скрывается — оно не секрет и его же оператор и задаёт.
func (c Config) validateDeclaredDomain() error {
	if strings.TrimSpace(c.AuthN.Domain) != "" {
		return nil
	}
	return fmt.Errorf(
		"authn.domain is not declared (set it in the chart profile or via ENV " +
			"KANAME_AUTHN__DOMAIN): the audience claim of every issued token is derived " +
			"from it, and a value the build substitutes silently would make this check " +
			"vacuous — the deployment would look configured while addressing its " +
			"credentials at a domain nobody chose")
}

// validateProductionBootstrapMint refuses to start a production binary whose
// bootstrap-admin token mint is ENABLED (the signing key is present, so the RPC
// will actually issue tokens) but has NO caller allow-list.
//
// MintBootstrapToken returns a cluster `system_admin` Bearer signed by our own signer. It
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
// appears in the error.
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
		SANsKnob:     "authn.trusted-forwarder-sans (env KANAME_AUTHN__TRUSTED_FORWARDER_SANS)",
		TrustAnyKnob: "authn.trust-any-forwarder (env KANAME_AUTHN__TRUST_ANY_FORWARDER)",
	})
}

// validateTrustDomain refuses to start a binary whose installation has not named
// its trust domain.
//
// Круг отправителей выше отвечает на вопрос «кому позволено говорить за
// пользователя»; домен — на предыдущий: чьи предъявители вообще наши. По
// необъявленному домену не опознаётся НИ ОДИН сертификат, поэтому процесс,
// поднявшийся без него, отвергает каждого соседа — и отвергает молча, отказом,
// неотличимым от вызова без личности.
//
// Отказ срабатывает на ЛЮБОМ старте, а не только в боевом: у необъявленного
// домена нет посадки, в которой он работает. Опт-ина «поднимусь без домена» нет
// и быть не может — он означал бы согласие не работать.
//
// Страж ОБЩИЙ на все службы — `grpcsrv.TrustDomain.Require`, один исход и один
// текст отказа; различаются только имена ручек. Дескриптор посадки зовёт ТУ ЖЕ
// функцию с тем же именем ручки, поэтому здесь второе место ВЫЗОВА, а не второй
// источник решения. Ранняя проверка полезна тем же, чем и у соседки: она
// отказывает ещё в `main`, до `runServe`, и называет оператору ключ.
func (c Config) validateTrustDomain() error {
	return c.AuthN.TrustDomain().Require(grpcsrv.TrustDomainGate{
		Knob: "authn.trust-domain (env KANAME_AUTHN__TRUST_DOMAIN)",
	})
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

// validateProductionAuthNSecrets requires the key the binary wraps the private
// half of its signing key with.
//
// Ключ обёртки требуется потому, что им оборачивается приватная половина
// подписного ключа в ключнице (задача #897). Ручка об этом предмете в дереве
// одна, и её значение меняет исход старта: объявленная и нечитаемая ручка была
// бы мёртвым стражем.
//
// Здесь же прежде требовался общий секрет хуков внешнего поставщика. Хуки сняты
// вместе с поставщиком (kaname#363): секрет не читает никто, и требовать его
// значило бы требовать величину без читателя.
//
// The secret resolves from the YAML field OR the ENV indirection
// (jwks-encryption-key-hex-env). Only os.Getenv is read (no other
// side-effects), consistent with the Resolve* methods.
//
// Errors name WHICH setting is missing — never the secret value.
func (c Config) validateProductionAuthNSecrets() error {
	var errs error
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

// DSNNamesAHost — называет ли строка подключения хост, к которому идти.
//
// ПРЕДИКАТ ОДИН НА ДВУХ ВЫЗЫВАЮЩИХ, и это несущее свойство, а не удобство: его
// зовут страж старта службы (`Config.Validate` выше) и точка наката миграций,
// которая в поставке исполняется ПЕРВОЙ. Своя редакция у каждого разошлась бы
// молча — и разошлась бы там, где расхождение не видно: обе стороны отвечают
// «годно» на годном входе.
//
// СУДИТСЯ ХОСТ, А НЕ ПУСТОТА СТРОКИ. Шаблон чарта собирает строку из частей,
// поэтому при незаданном адресе базы она выходит НЕПУСТОЙ и с пустым хостом
// (`postgres://iam@:5432/kaname`). Предикат «строка непуста» по этому пути не
// срабатывает НИ ПРИ КАКОМ входе.
//
// ФОРМА `ключ=значение` (её тоже принимает драйвер) считается называющей хост:
// чарт её не производит, а разбирать её вторым способом значило бы завести
// второй кодек. Предикат отвечает на один вопрос и не притворяется разбором DSN.
func DSNNamesAHost(dsn string) bool {
	trimmed := strings.TrimSpace(dsn)
	if trimmed == "" {
		return false
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return true
	}
	if parsed.Scheme != "postgres" && parsed.Scheme != "postgresql" {
		return true
	}
	return strings.TrimSpace(parsed.Hostname()) != ""
}

// RedactDSN — строка подключения, годная для ЖУРНАЛА и текста отказа.
//
// Строка подключения несёт пароль базы: он приезжает из объекта Secret и
// подставляется в DSN перед употреблением. Текст отказа уезжает в журнал пода, а
// журнал читает всякий, у кого есть доступ к кластеру, — поэтому величина,
// названная оператору, обязана быть обеззаражена.
//
// ПОЧЕМУ ОБЕЗЗАРАЖИВАНИЕ, А НЕ УМОЛЧАНИЕ ЗНАЧЕНИЯ. Отказ, не назвавший адреса
// вовсе, отправляет оператора искать, какой из трёх источников подставил
// негодную величину. Обеззараженная строка называет всё, кроме пароля: хост,
// пользователя, базу и параметры — то есть ровно то, чем оператор чинит.
//
// Нечитаемая строка возвращается ЗАМЕНЁННОЙ ЦЕЛИКОМ: раз разобрать её не
// удалось, то и найти в ней пароль нельзя, а печатать неразобранное значило бы
// печатать возможный секрет.
func RedactDSN(dsn string) string {
	trimmed := strings.TrimSpace(dsn)
	if trimmed == "" {
		return ""
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "(строка подключения не разобрана; не печатается, чтобы не раскрыть пароль)"
	}
	return parsed.Redacted()
}
