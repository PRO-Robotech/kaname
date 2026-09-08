// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"go.uber.org/multierr"

	"github.com/PRO-Robotech/kacho/pkg/tokenpolicy"
)

// ServiceAccountOAuthClient — Class A workload identity (Hydra static client).
//
// private_key_jwt mode: kaname mints an ECDSA P-256 keypair per SA
// key, registers the public JWK with Hydra (`token_endpoint_auth_method =
// private_key_jwt`), and returns the private PEM to the caller exactly once.
// Hydra stores only the JWK; kaname keeps the SPKI public PEM (for
// rotation diagnostics) plus the algorithm. The legacy
// `client_secret_basic` flow is dropped: no secret ever exists.
//
// 1:1 SA→client.
type ServiceAccountOAuthClient struct {
	ID              SAOAuthClientID
	SvaID           ServiceAccountID
	OAuthClientID   OAuthClientID
	Description     Description
	CreatedByUserID UserID
	CreatedAt       time.Time
	ExpiresAt       *time.Time
	LastUsedAt      *time.Time

	// PublicKeyPEM — SPKI-encoded ECDSA P-256 public key registered with
	// Hydra as a JWK. Empty for legacy rows that pre-date the private_key_jwt
	// mode (migrated with DEFAULT '') AND for FEDERATED rows where the
	// key material lives in the external IdP rather than kaname.
	PublicKeyPEM string
	// KeyAlgorithm — JOSE alg of the registered key. One of {"ES256",
	// "RS256", "EdDSA"}. Empty for legacy rows; new private_key_jwt keys
	// always set "ES256"; federated rows leave it empty.
	KeyAlgorithm string

	// TrustedSubjects — федеративный вид ключа. Непустой перечень означает, что
	// удостоверение предъявляет ВНЕШНИЙ издатель по RFC 7521/7523: своего
	// ключевого материала строка не несёт вовсе, а подпись проверяется ключом
	// издателя из НАШЕГО перечня доверенных издателей (задача #1124), который
	// читает проверяющий утверждения на пути запроса.
	//
	// Каждый элемент сужает, какая внешняя пара `(iss, sub)` вправе выступать
	// за этот ключ. Пустой перечень — обычный вид с ключевым материалом.
	TrustedSubjects []TrustedSubject

	// DeclaredAudiences — сужение адресатов, ОБЪЯВЛЕННОЕ заказчиком при выдаче
	// (`IssueSAKeyRequest.audience`, задача #1136). Create-only, как и всё
	// остальное на этом ресурсе: глагола правки у ключа нет.
	//
	// Перечней в тракте выдачи ДВА, и этот — внутренний: он говорит, для чего
	// заведён ЭТОТ ключ, и действует ВНУТРИ перечня, объявленного посадкой.
	// Расширить внешнюю границу он не может ничем.
	//
	// Пустой перечень означает «сужения не объявлено», а не «любой адресат»:
	// внешняя граница остаётся и требуется непустой стражем старта выдачи.
	DeclaredAudiences []string

	// CredentialKind — вид удостоверения. ЗАПИСЫВАЕТСЯ при вставке; читателем
	// не вычисляется и из состава прочих полей не выводится.
	CredentialKind CredentialKind
	// SecretHash — sha256 по идентификатору строки И секретной части вместе,
	// 32 байта. Непуст ТОЛЬКО у вида SECRET. Сам секрет не хранится нигде: он
	// существует только в теле ответа, полученного вызывающим выдачи.
	SecretHash []byte

	// Name — человекочитаемое имя ключа, выставляется на Issue (create-only,
	// immutable — ресурс несёт только Issue/List/Revoke). Пусто для legacy-строк.
	Name OAuthClientName
	// Labels — произвольные метки ключа, выставляются на Issue (create-only,
	// immutable). Пусто для legacy-строк.
	Labels Labels
}

// TrustedSubject — one (issuer, subject) tuple permitted to assert a federated
// ServiceAccountOAuthClient. `Issuer` MUST match the external OIDC `iss` claim
// verbatim; `SubjectPattern` is a LITERAL-anchored exact subject (`^<literal>$`,
// no regex metacharacters).
//
// Точная форма субъекта требуется потому, что доверие выдаётся ПОИМЁННО: запись,
// покрывающая субъектов образцом, называет тех, кого выдававший не перечислял, и
// установить их состав нельзя ни по записи, ни по журналу.
//
// # Перечень — НАША таблица (задача #1124)
//
// Прежде решение о доверии принимал поставщик: запись жила у него, и там же
// лежал ключ издателя. Отсюда была выведена и прежняя редакция этого
// комментария — «служба прав вне пути запроса, поэтому образец было бы нечем
// применить». Сегодня служба прав НА пути запроса: перечень читает её проверка
// утверждения (`internal/clientassertion`, федеративная полоса). Точная форма
// осталась, но держит её теперь названный выше довод, а не чужая реализация.
type TrustedSubject struct {
	Issuer         string
	SubjectPattern string
	// PublicKeyPEM — открытый ключ ИЗДАТЕЛЯ (SPKI PEM). Тот, которым подписано
	// внешнее утверждение; нашего ключевого материала федеративная строка не
	// несёт вовсе.
	PublicKeyPEM string
	// KeyAlgorithm — зарегистрированный алгоритм издателя. Пустое значение
	// означает «ключа нет», а НЕ «любой алгоритм».
	KeyAlgorithm string
}

// literalSubjectRe — a subject_pattern anchored with `^…$` around a run of
// characters that are NOT regex metacharacters (so the enclosed text is a literal
// subject, сверяемый с `sub` предъявленного утверждения дословно).
var literalSubjectRe = regexp.MustCompile(`^\^[^.\\*+?()\[\]{}|^$]+\$$`)

// LiteralSubject returns the exact subject enclosed by a valid literal-anchored
// pattern (`^<literal>$` → `<literal>`), and false when the pattern is not a
// literal-anchored subject (wildcard / unanchored / regex metacharacters).
func (ts TrustedSubject) LiteralSubject() (string, bool) {
	if !literalSubjectRe.MatchString(ts.SubjectPattern) {
		return "", false
	}
	return strings.TrimSuffix(strings.TrimPrefix(ts.SubjectPattern, "^"), "$"), true
}

// Validate — Issuer must be an https URL to a public host (anti-SSRF on the
// trust-config: no non-https / loopback / private / link-local host);
// SubjectPattern must be a literal-anchored exact subject. Length caps mirror the
// proto (≤512 each).
//
// Ключевой материал издателя обязателен и проверяется на РАЗБИРАЕМОСТЬ здесь, а
// не при первом предъявлении: непригодный ключ, принятый на выдаче, даёт запись
// доверия, которая не примет никогда никого, — то есть возможность, объявленную
// и не работающую ни при каком входе. Отказ на выдаче виден тому, кто её
// заказал; отказ на предъявлении виден постороннему и неотличим для него от
// «доверия нет».
func (ts TrustedSubject) Validate() error {
	var errs error
	switch {
	case ts.Issuer == "":
		errs = multierr.Append(errs, fmt.Errorf("Illegal argument issuer: required"))
	case len(ts.Issuer) > 512:
		errs = multierr.Append(errs, fmt.Errorf("Illegal argument issuer: length must be <=512"))
	case !isPublicHTTPSIssuer(ts.Issuer):
		errs = multierr.Append(errs, fmt.Errorf("Illegal argument issuer: must be an https URL to a public host"))
	}
	switch {
	case ts.SubjectPattern == "":
		errs = multierr.Append(errs, fmt.Errorf("Illegal argument subject_pattern: required"))
	case len(ts.SubjectPattern) > 512:
		errs = multierr.Append(errs, fmt.Errorf("Illegal argument subject_pattern: length must be <=512"))
	default:
		if _, ok := ts.LiteralSubject(); !ok {
			errs = multierr.Append(errs, fmt.Errorf(
				"Illegal argument subject_pattern: must be a literal anchored subject (^...$, no wildcards)"))
		}
	}
	switch {
	case ts.KeyAlgorithm == "":
		errs = multierr.Append(errs, fmt.Errorf("Illegal argument key_algorithm: required"))
	case !tokenpolicy.AlgorithmAllowed(ts.KeyAlgorithm):
		errs = multierr.Append(errs, fmt.Errorf(
			"Illegal argument key_algorithm: must be one of %v", tokenpolicy.Algorithms()))
	}
	switch {
	case ts.PublicKeyPEM == "":
		errs = multierr.Append(errs, fmt.Errorf("Illegal argument public_key_pem: required"))
	case len(ts.PublicKeyPEM) > 8192:
		errs = multierr.Append(errs, fmt.Errorf("Illegal argument public_key_pem: length must be <=8192"))
	default:
		if err := validateSPKIPublicKeyPEM(ts.PublicKeyPEM); err != nil {
			errs = multierr.Append(errs, fmt.Errorf("Illegal argument public_key_pem: %v", err))
		}
	}
	return errs
}

// validateSPKIPublicKeyPEM — ключ разбирается и он ОТКРЫТЫЙ.
//
// Проверяется и то, что блок вообще разбирается, и то, что это не закрытая
// половина: закрытый ключ, попавший сюда по недосмотру называющего, был бы
// принят как «ключ есть» и осел бы в нашей таблице — то есть мы приняли бы на
// хранение чужой секрет, которого просить не должны.
func validateSPKIPublicKeyPEM(raw string) error {
	block, _ := pem.Decode([]byte(raw))
	if block == nil {
		return fmt.Errorf("not a PEM block")
	}
	if strings.Contains(block.Type, "PRIVATE") {
		return fmt.Errorf("a private key was supplied where a public key is expected")
	}
	if _, err := x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		return fmt.Errorf("not an SPKI public key")
	}
	return nil
}

// isPublicHTTPSIssuer — true when raw parses as an https URL whose host is not a
// loopback / private / link-local / unspecified IP and not `localhost`. A DNS
// hostname (including cluster-internal FQDNs like `kube.cluster.local`) passes;
// an IP literal is admitted only when it is a routable public address.
func isPublicHTTPSIssuer(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return false
	}
	host := u.Hostname()
	if host == "" || strings.EqualFold(host, "localhost") {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
			ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return false
		}
	}
	return true
}

func (c ServiceAccountOAuthClient) Validate() error {
	var errs error
	errs = multierr.Append(errs, c.ID.Validate())
	errs = multierr.Append(errs, c.OAuthClientID.Validate())
	errs = multierr.Append(errs, c.Description.Validate())
	if c.SvaID == "" {
		errs = multierr.Append(errs, fmt.Errorf("Illegal argument sva_id: required"))
	}
	if c.CreatedByUserID == "" {
		errs = multierr.Append(errs, fmt.Errorf("Illegal argument created_by_user_id: required"))
	}
	if c.ExpiresAt != nil && !c.CreatedAt.IsZero() && !c.ExpiresAt.After(c.CreatedAt) {
		errs = multierr.Append(errs, fmt.Errorf("Illegal argument expires_at: must be > created_at"))
	}
	switch c.KeyAlgorithm {
	case "", "ES256", "RS256", "EdDSA":
		// allowed; empty kept for legacy rows AND for federated rows.
	default:
		errs = multierr.Append(errs,
			fmt.Errorf("Illegal argument key_algorithm: must be one of {ES256,RS256,EdDSA}"))
	}
	errs = multierr.Append(errs, c.Name.Validate())
	errs = multierr.Append(errs, c.Labels.Validate())
	for i, a := range c.DeclaredAudiences {
		switch {
		case strings.TrimSpace(a) == "":
			// Пустой элемент — адресат, которого нельзя заказать ничем: он не
			// совпал бы ни с одним запросом и молча сузил бы ключ до
			// недостижимого. Отказ здесь виден заказавшему выдачу; отказ на
			// обмене виден машине и неотличим для неё от «прав нет».
			errs = multierr.Append(errs, fmt.Errorf("Illegal argument audience[%d]: must not be empty", i))
		case len(a) > 512:
			errs = multierr.Append(errs, fmt.Errorf("Illegal argument audience[%d]: length must be <=512", i))
		}
	}
	for i, ts := range c.TrustedSubjects {
		if err := ts.Validate(); err != nil {
			errs = multierr.Append(errs, fmt.Errorf("trusted_subjects[%d]: %w", i, err))
		}
	}
	// A federated row (TrustedSubjects non-empty) must NOT carry private-key
	// material; conversely a private_key_jwt row must carry public PEM. The
	// reverse direction (legacy rows with empty PublicKeyPEM AND no trusted
	// subjects) is permitted for backwards-compat on baseline DEFAULT '' rows.
	if len(c.TrustedSubjects) > 0 && (c.PublicKeyPEM != "" || c.KeyAlgorithm != "") {
		errs = multierr.Append(errs, fmt.Errorf(
			"Illegal argument: federated SA-key (trusted_subjects set) must not carry public_key_pem / key_algorithm"))
	}
	return errs
}

// SAOAuthClientID — новый формат `soc<17-crockford>` (corelib `ids.NewID`, без
// подчёркивания). id существующих строк immutable (id = Hydra client id + JWK
// kid), поэтому валидатор принимает и legacy `soc_<17-crockford>`.
type SAOAuthClientID string

var socIDRe = regexp.MustCompile(`^soc_?[0-9a-hjkmnp-tv-z]{17}$`)

func (id SAOAuthClientID) Validate() error {
	if !socIDRe.MatchString(string(id)) {
		return fmt.Errorf("Illegal argument id: must match ^soc_?[0-9a-hjkmnp-tv-z]{17}$")
	}
	return nil
}

// OAuthClientID — opaque hydra client id (length 1..128, [A-Za-z0-9._:-]).
type OAuthClientID string

var oauthClientIDRe = regexp.MustCompile(`^[A-Za-z0-9._:-]+$`)

func (h OAuthClientID) Validate() error {
	s := string(h)
	if len(s) < 1 || len(s) > 128 {
		return fmt.Errorf("Illegal argument hydra_client_id: length must be 1..128")
	}
	if !oauthClientIDRe.MatchString(s) {
		return fmt.Errorf("Illegal argument hydra_client_id: must match [A-Za-z0-9._:-]+")
	}
	return nil
}
