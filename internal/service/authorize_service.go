// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// authorize_service.go — AuthorizeService use-case.
//
// Pipeline (per request):
//
//  1. Resolve permission → FGA relation (`<domain>.<resource>.<verb>` →
//     `<resource>_<verb>` per kacho-corelib/authz convention).
//  2. Build Conditions context (`current_time` from server clock; merges
//     user-provided `context` from the RPC body).
//  3. Вердикт реляционной формы по плану, скомпилированному из модели прав.
//     Allowed=false → return deny ("no path").
//  4. Allow.
//
// Clean Architecture: domain.* + port-ifaces only. Adapter wiring lives in
// cmd/kacho-iam/main.go.
//
// The OPA guardrail overlay step (`data.kacho.iam.guardrails.deny`) was removed.
// FGA is the sole policy gate; the OPA sidecar and bundle wiring are gone.
//
// Latency budget: ≤30ms p95 — FGA Check ≤10ms, 20ms margin for
// principal-extraction + transport.
//
// Cluster-admin short-circuit cost: the per-object FGA resolve runs FIRST and
// the cluster-admin super-gate (cluster:…#system_admin) is the FALLBACK on a DENY.
// So the common ALLOW path is ONE FGA round-trip (no redundant cluster-admin Check);
// only a DENIED request pays a SECOND round-trip to test cluster-admin authority.
// BatchCheck memoizes the cluster-admin verdict per-subject so a same-subject batch
// resolves it at most once. Correctness/fail-closed unchanged — cluster-admin is
// still allowed on everything, resolved second.
package service

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/PRO-Robotech/kacho/pkg/grpcsrv"

	"github.com/PRO-Robotech/kacho-iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho-iam/internal/authztypes"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
)

// serverAuthoritativeCondKeys are CEL condition-context attributes that describe
// the authenticated principal or the connection. They MUST be server-derived —
// never taken from a client-supplied request body. AuthorizeService is reachable
// on the PUBLIC listener and the inner caller-authority gate allows a self-query,
// so a tenant could otherwise set these in `req.Context` and forge satisfaction
// of a security condition (mfa_fresh / source_ip_in_range / non_expired /
// device_compliant) it does not actually hold (CWE-807 / security.md "no
// reliance on untrusted inputs in a security decision").
var serverAuthoritativeCondKeys = []string{
	"current_time",       // server clock (always forced below)
	"acr_value",          // authentication assurance level (overlaid from trusted ctx)
	"amr_claims",         // authentication methods
	"mfa_at",             // last MFA timestamp
	"client_ip",          // connection source address
	"source_ip",          // connection source address (alias)
	"valid_until",        // grant expiry
	"device_attestation", // device posture
}

// buildCondContext assembles the condition-context the verdict is evaluated
// against. It starts from the client-supplied req.Context but STRIPS every
// server-authoritative attribute (a client cannot forge principal/connection
// facts) and then overlays only values the server actually trusts: the server
// clock as current_time, and the FD-4-trusted acr from the request ctx (the same
// trusted acr the ACR-floor interceptor enforces). Attributes the server cannot
// yet derive from a trusted source (amr_claims / mfa_at / client_ip /
// device_attestation) are left ABSENT so the dependent condition fails CLOSED
// rather than being satisfiable by a forged value. Genuinely request-scoped,
// non-security attributes pass through unchanged.
func buildCondContext(ctx context.Context, reqContext map[string]any, now time.Time) map[string]any {
	condCtx := make(map[string]any, len(reqContext)+1)
	for k, v := range reqContext {
		condCtx[k] = v
	}
	for _, k := range serverAuthoritativeCondKeys {
		delete(condCtx, k)
	}
	condCtx["current_time"] = now.Unix()
	if acr, trusted := grpcsrv.TrustedACRFromContext(ctx); trusted && acr != "" {
		condCtx["acr_value"] = acr
	}
	return condCtx
}

// Authorizer — port-iface narrowed to AuthorizeService needs.
// Authorizer — ИСТОЧНИК ВЕРДИКТА для края.
//
// Поверхность сузилась вместе со снятием внешнего движка отношений, и сузилась
// по существу, а не по вкусу: из неё ушло всё, что было вопросом к ЧУЖОМУ
// хранилищу — перечисление объектов без продолжения, чтение и запись кортежей,
// сведения о хранилище. Осталось то, что спрашивают у РЕШЕНИЯ.
//
// Реализация — `internal/authzcascade.Client` поверх реляционной формы.
type Authorizer interface {
	// CheckWithContext — вердикт об объекте с условным контекстом запроса.
	CheckWithContext(ctx context.Context, subject, relation, object string, condCtx map[string]any) (bool, error)
	// BatchCheckWithContext — вердикт о СТРАНИЦЕ объектов ОДНИМ вопросом.
	//
	// Объявлен ОБЯЗАТЕЛЬНЫМ методом порта, а не «способностью, если она есть».
	// Необязательность здесь была бы запасным путём с тихой деградацией: дверь без
	// этого метода молча возвращала бы партию к пообъектной полосе, и свойство
	// «партия стоит один вопрос» держалось бы тем, какую реализацию провязал
	// композиционный корень, — то есть не держалось бы ничем.
	//
	// Ответ — той же длины и в порядке заданных объектов: верный, но
	// переставленный вердикт отфильтровал бы страницу чужим ответом.
	BatchCheckWithContext(ctx context.Context, subject, relation string, objects []string,
		condCtx map[string]any) ([]bool, error)
	// ListSubjects — кто держит отношение на объекте, страницей С КУРСОРОМ.
	ListSubjects(ctx context.Context, objectType, objectID, relation string, pageSize int, pageToken string) ([]string, string, error)
	// Sources — кого называют основания права на объекте (разбор «почему»).
	Sources(ctx context.Context, objectType, objectID, relation string) ([]string, error)
	// DirectRelations — какие отношения субъект уже держит НА ЭТОМ объекте.
	//
	// Читатель один — текст отказа («не хватает `editor`; сейчас есть [`viewer`]»).
	// Прежде на это отвечало чтение кортежей у движка; читатель и единица те же,
	// источник — своя таблица.
	DirectRelations(ctx context.Context, subject, objectType, objectID string, limit int) ([]string, error)
	// DirectRelationsMany — то же о СТРАНИЦЕ объектов одного типа, одним вопросом.
	//
	// Хвост текста отказа платится на КАЖДОМ отказанном объекте, а страница
	// списка отказами и состоит — она ими и сужается. Пообъектная диагностика
	// поэтому возвращала стоимость набора ровно там, где вердикт её уже перестал
	// платить: партия из ста отказов стоила ста вопросов диагностики.
	//
	// Ключ ответа — идентификатор объекта; объект без прямых отношений в ответе
	// отсутствует (пустой срез и отсутствие ключа означают одно и то же — «хвоста
	// не будет»).
	DirectRelationsMany(ctx context.Context, subject, objectType string, objectIDs []string,
		limit int) (map[string][]string, error)
}

type AuthorizeService struct {
	relations Authorizer
	// clusterAdmin — flat cluster-admin super-gate (explicit RBAC model). When
	// wired, Check/CheckRelation short-circuit to ALLOW for a subject holding
	// cluster:cluster_kacho_root#system_admin BEFORE the per-object FGA resolve.
	// Optional / nil-safe: an unwired checker never short-circuits (the
	// ordinary FGA path is the sole decision — backward-compatible).
	clusterAdmin authzguard.RelationChecker
}

// AuthorizeServiceConfig — вход сборщика.
type AuthorizeServiceConfig struct {
	Relations Authorizer
	// ClusterAdminChecker — плоский надзор администратора облака.
	//
	// Спрашивает о ДРУГОМ объекте, чем тот, о котором идёт вопрос:
	// `cluster:<синглтон>#system_admin`. Именно поэтому три верхних уровня
	// супер-доступа сделаны каскадом, а не материализацией: человек, обязанный
	// всё починить, не должен зависеть от состояния доставки.
	//
	// Со снятия внешнего движка на этот вопрос отвечает ТА ЖЕ форма, что и на
	// вопрос об объекте, — обе стороны спрашивают одно значение, поэтому «два
	// действующих источника ответа» перестало быть возможным by construction.
	ClusterAdminChecker authzguard.RelationChecker
}

// NewAuthorizeService — builder.
func NewAuthorizeService(cfg AuthorizeServiceConfig) *AuthorizeService {
	return &AuthorizeService{
		relations:    cfg.Relations,
		clusterAdmin: cfg.ClusterAdminChecker,
	}
}

// CheckRequest — input for `Check`.
type CheckRequest struct {
	Subject  string // "user:usr_xxx" / "service_account:sva_xxx" / "group:grp_xxx#member"
	Resource ResourceRef
	Action   string // "<domain>.<resource>.<verb>"
	// RequiredRelation — when non-empty, overrides verb-derived relation.
	// api-gateway middleware populates this from the catalog's
	// `required_relation` annotation so admin-only RPCs (e.g.
	// `vpc.address_pools.list` with `required_relation=system_admin`) gate
	// on the explicit relation instead of the auto-derived `viewer` which
	// would slip through `cluster.viewer = user:*`.
	RequiredRelation string
	Context          map[string]any // optional CEL-context
}

// ResourceRef — typed resource ref.
type ResourceRef struct {
	Type string
	ID   string
}

// CheckResult — output.
type CheckResult struct {
	Allowed     bool
	DenyReasons []string
	CheckedAt   time.Time
}

// batchCheckParallelism — сколько ПРОГОНОВ одного прохода `BatchCheck`
// разрешается держать на хранилище одновременно.
//
// # Единица — прогон, и она сменилась вместе с предметом
//
// Здесь стояло «сколько ПУНКТОВ», и рядом было сказано, что один вопрос на пункт
// присущ пообъектному предикату, а остаток («партия отвечается парой обращений, а
// стоит сотни») назван ОТКРЫТЫМ. Остаток закрыт: однородная часть партии —
// прогон — отвечается ОДНИМ вопросом, поэтому связывать пункты этим пределом
// больше нечем, и абзац про открытый остаток снят вместе с самим остатком (иначе
// он пережил бы свой предмет и звал закрывать закрытое).
//
// # Почему предел вообще нужен, и почему он не «сколько прогонов есть»
//
// Довод не изменился, изменилась только единица: бюджет вызывающего принадлежит
// ЗАПРОСУ. Партия, чьи пункты называют РАЗНЫЕ субъекты (форму метод поддерживает
// явно), даёт столько прогонов, сколько субъектов, и последовательный проход по
// ним стоил бы прогоны × время ответа хранилища — то самое ожидание, которое
// съедало секунду вызывающего и роняло его ПОЛОЖИТЕЛЬНЫЙ список в UNAVAILABLE.
//
// Восемь, а не «горутина на прогон»: вопросы в полёте умножаются на собственную
// одновременность хранилища и на одновременные списки других вызывающих, поэтому
// неограниченный всплеск меняет задержку одного вызывающего на задержку всех.
//
// Число совпадает с `authzfilter.BatchParallelism`, и это НЕ одна и та же
// величина — не «унифицировать» их по совпадению цифры: там восьмёркой
// ограничены разделы, каждый из которых уже несёт целую страницу вопросов.
//
// Обе стороны — что прогоны не ждут друг друга и что их одновременность
// ограничена — держат `TestBatchCheck_ResolvesItsRunsConcurrently` и
// `TestBatchCheck_RunConcurrencyIsBounded`; что однородная партия стоит ОДИН
// вопрос — `TestBatchCheck_AUniformSliceIsOneQuestion` и
// `TestBatchCheck_AHundredCostsWhatOneCosts`.
const batchCheckParallelism = 8

// clusterAdminMemo memoizes the cluster-admin short-circuit verdict for a single
// subject across a Check/BatchCheck pass, so a batch from one subject (or a single
// request) issues the cluster:…#system_admin FGA Check AT MOST ONCE. The
// cluster-admin relation is subject-scoped (one cluster:cluster_kacho_root#
// system_admin tuple), so the verdict is identical for every object in the pass —
// caching it is correct and preserves fail-closed (the Check is still performed,
// just deduped).
//
// The single-flight is not decoration. A BatchCheck pass resolves its items
// concurrently (batchCheckParallelism), so this memo is read and written from
// several goroutines at once; and the resolution itself must be inside the guard,
// not merely the field writes. Guarding only the fields would let every worker that
// arrives before the first one finishes miss the memo and ask again — the batch
// would be race-free and would still issue one super-gate question per item, which
// is the very cost this type exists to remove.
//
// The guard is PER SUBJECT, and that is the whole point of the map. An earlier
// revision held one mutex across the resolution and claimed serialising "costs
// nothing that matters: at most one question per subject". The first half was
// false whenever the second half's premise did not hold: on a slice whose items
// name different subjects — a shape this method explicitly supports — the single
// lock was held across a network call for every item in turn, so the pool was
// defeated entirely and the pass ran at parallelism one. Keyed per subject, the
// claim is now true as written: same-subject workers wait for the one question
// that is being asked on their behalf, different subjects never wait for each
// other, and the per-object checks are never serialised.
type clusterAdminMemo struct {
	mu sync.Mutex
	by map[string]*clusterAdminVerdict
}

// clusterAdminVerdict — the single-flight slot for ONE subject.
//
// Хранит ИСХОД, а не булев ответ. Мемоизировать «нет» там, где хранилище не
// ответило, значило бы разослать неполадку по всей партии вердиктом «не
// положено» — и ровно один раз, зато всем её пунктам сразу.
type clusterAdminVerdict struct {
	once    sync.Once
	allowed bool
	err     error
}

// isClusterAdmin returns the (memoized) cluster-admin verdict for subject. The
// first call for a subject performs the flat super-gate Check; concurrent and
// subsequent calls for the SAME subject reuse it. Different subjects resolve
// independently and in parallel.
//
// ВОЗВРАЩАЕТ ТРИ ИСХОДА, А НЕ ДВА (задача #1045). `(false, nil)` — хранилище
// ответило «не администратор»; `(false, err)` — хранилище не ответило вовсе.
// Прежде булева обёртка сводила второе к первому, и это была ОБЩАЯ ДВЕРЬ: сюда
// приходит интерсептор каждой службы платформы и фильтр списка каждого соседа.
// Мигание хранилища прав приезжало к ним отказом в правах, а отказ в правах их
// дренаж классифицирует как ТЕРМИНАЛЬНЫЙ.
//
// Ошибка мемоизируется вместе с ответом намеренно: вопрос на проход один, и
// повторять его по пунктам партии значило бы платить за неполадку столько раз,
// сколько в ней позиций.
func (s *AuthorizeService) isClusterAdmin(ctx context.Context, m *clusterAdminMemo, subject string) (bool, error) {
	if m == nil {
		return authzguard.SubjectIsClusterAdminPlainE(ctx, s.clusterAdmin, subject)
	}
	m.mu.Lock()
	if m.by == nil {
		m.by = make(map[string]*clusterAdminVerdict, 1)
	}
	slot := m.by[subject]
	if slot == nil {
		slot = &clusterAdminVerdict{}
		m.by[subject] = slot
	}
	m.mu.Unlock()

	// Only the map lookup is under the shared lock; the question itself is under
	// this subject's own slot, so subjects do not block one another.
	slot.once.Do(func() {
		slot.allowed, slot.err = authzguard.SubjectIsClusterAdminPlainE(ctx, s.clusterAdmin, subject)
	})
	return slot.allowed, slot.err
}

// superGateUnavailable — неполадка надзора в тоне этой двери: соседи ветвятся по
// `iamerr.ErrUnavailable`, и повтор для них осмыслен.
func superGateUnavailable(err error) error {
	return fmt.Errorf("%w: authz unavailable: %w", iamerr.ErrUnavailable, err)
}

// Check — single-tuple authorization check (with Conditions + OPA overlay).
func (s *AuthorizeService) Check(ctx context.Context, req CheckRequest) (*CheckResult, error) {
	return s.check(ctx, req, nil)
}

// check is the Check implementation parameterized by an optional cluster-admin
// memo (shared across a BatchCheck pass; nil for a standalone Check).
//
// Возвраты именованы ради ОДНОГО свойства: теневой вопрос сводится на КАЖДОМ
// пути, а путей отсюда много (короткое замыкание администратора облака,
// структурный запасной путь, отказ). Сведение, приписанное к одному из них, снова
// оставило бы часть решений без сравнения — и именно ту часть, где решение
// принято дёшево. Заодно это покрывает и `BatchCheck`: он отвечает каждый свой
// пункт этой же функцией.
func (s *AuthorizeService) check(ctx context.Context, req CheckRequest, caMemo *clusterAdminMemo) (result *CheckResult, err error) {
	now := time.Now().UTC().Truncate(time.Second)
	result = &CheckResult{CheckedAt: now}

	p := planCheck(ctx, req, now)
	if p.invalid != nil {
		return result, p.invalid
	}
	if p.superGateDecides {
		// Вопроса об объекте нет — спросить форму «наугад» значило бы получить
		// честное «нет» о том, чего не спрашивали. Но решение принято, и оно
		// обязано попасть в знаменатель: надзор администратора облака —
		// авторитет на всём, и платит за него только отказ.
		admin, aerr := s.isClusterAdmin(ctx, caMemo, p.subject)
		if aerr != nil {
			// Вопрос остался без ответа. Отказом это не является: вернуть здесь
			// отказ значило бы объявить вердикт, которого никто не выносил.
			return result, superGateUnavailable(aerr)
		}
		if admin {
			result.Allowed = true
			return result, nil
		}
		result.DenyReasons = []string{p.denyReason}
		return result, nil
	}

	allowed, err := s.verdict(ctx, p.subject, caMemo, p.relation, p.object, p.condCtx)
	if err != nil {
		return result, err
	}
	result.Allowed = allowed
	if !allowed {
		result.DenyReasons = []string{denyReasonText(p.subject, p.relation, p.object, p.action,
			s.readSubjectRelations(ctx, p.subject, p.object))}
	}
	return result, nil
}

// checkPlan — всё, что решено о пункте ДО обращения к хранилищу.
//
// Существует ради ОДНОГО свойства: разбор пункта — валидация входа, разрешение
// отношения, подстановка синглтона кластера, неадресуемый объект — у одиночного
// вопроса и у партии обязан быть ОДИН. Второй разбор «для партии» был бы вторым
// местом об одном предмете, и разошлись бы они молча — в сторону, где партия
// отвечает не то же, что тот же вопрос, заданный по одному.
type checkPlan struct {
	subject    string
	relation   string
	objectType string
	objectID   string
	object     string
	action     string
	condCtx    map[string]any

	// invalid — вход не назван. Это ОШИБКА пункта, а не отказ: вызывающий обязан
	// отличать «спросил не то» от «доступа нет».
	invalid error
	// superGateDecides — вопроса к форме нет (отношение не разрешается либо объект
	// не адресуем), и решение принимает надзор администратора облака.
	superGateDecides bool
	// denyReason — текст отказа, когда надзор права не даёт.
	denyReason string
}

// planCheck разбирает пункт, не обращаясь к хранилищу.
//
// Часы — параметром: у партии они ОДНИ на весь проход, иначе пункты одной
// страницы получили бы разное «сейчас» при вычислении условий, и страница
// описывала бы состояние, которого не было ни в один момент.
func planCheck(ctx context.Context, req CheckRequest, now time.Time) checkPlan {
	p := checkPlan{subject: req.Subject, action: req.Action}

	// Input validation.
	if req.Subject == "" {
		p.invalid = fmt.Errorf("Illegal argument subject: required")
		return p
	}
	if req.Resource.Type == "" || req.Resource.ID == "" {
		p.invalid = fmt.Errorf("Illegal argument resource: required")
		return p
	}
	if req.Action == "" {
		p.invalid = fmt.Errorf("Illegal argument action: required")
		return p
	}
	// Explicit relation override. When the api-gateway
	// passes `required_relation` from the catalog, we honor it verbatim
	// instead of deriving from action verb — the catalog is the single
	// source of truth for what FGA relation gates each RPC. Verb-derived
	// fallback only applies when override is empty (legacy peer-service
	// callers still work).
	relation := strings.TrimSpace(req.RequiredRelation)
	if relation == "" {
		relation = resolveActionToRelation(req.Action)
	}
	if relation == "" {
		// Cluster-admin fallback: even an unresolvable relation is allowed for a
		// cluster-admin (the flat super-gate is authority on everything). Checked on
		// the deny path only — the common allow case never pays this round-trip.
		p.superGateDecides = true
		p.denyReason = fmt.Sprintf("action %q does not resolve to a known relation", req.Action)
		return p
	}
	// Cluster is a singleton (`cluster_kacho_root` — см. domain/cluster.go::
	// ClusterSingletonID). Per-RPC catalog entries для reference data
	// (compute.Region/Zone, etc.) задают
	// scope_extractor: {object_type: cluster, from_request_field: '*'} →
	// api-gateway / compute internal authz middleware шлют Resource.ID == "*".
	// Substitute на singleton id перед общим wildcard-reject (ниже), чтобы
	// FGA-cascade `define viewer: [user, user:*]` на cluster действительно
	// работал. (api-gateway тоже substitute'ит локально — этот fix покрывает
	// прямые service→IAM caller'ы compute/vpc.)
	if req.Resource.Type == "cluster" && req.Resource.ID == "*" {
		req.Resource.ID = domain.ClusterSingletonID
	}
	// A wildcard resource id ("*") reaches us from the api-gateway authz
	// middleware when an RPC's scope id could not be extracted from the
	// request (List/Search RPCs with no scope param). A typed wildcard is not an
	// object: there is no row to ask about, so there is no question to put. The
	// external engine refused it outright and the refusal surfaced as a misleading
	// 503; a refusal is not what the caller needs to hear either way. A non-scopable
	// resource has no resolvable authorization path, so we deny cleanly (-> gRPC
	// PermissionDenied 403) instead of erroring.
	if req.Resource.ID == "*" {
		// Объекта нет — вопроса форме E нет; решение всё равно названо (знаменатель).
		// Cluster-admin fallback: an unscopable resource has no per-object path,
		// but a cluster-admin is authority on everything. Deny path only.
		p.superGateDecides = true
		p.denyReason = "no path: unscoped resource"
		return p
	}

	p.relation = relation
	p.objectType = req.Resource.Type
	p.objectID = req.Resource.ID
	p.object = fmt.Sprintf("%s:%s", req.Resource.Type, req.Resource.ID)
	// Build the CEL condition-context: principal/connection attributes are
	// server-derived (forged client values stripped); see buildCondContext.
	p.condCtx = buildCondContext(ctx, req.Context, now)
	return p
}

// verdict — ОКОНЧАТЕЛЬНЫЙ вердикт края.
//
// Слагаемых ДВА, и было три. Ушёл структурный запасной путь: он пересдавал
// отказанный вопрос второй раз, приложив к нему закоммиченные строки iam как
// кортежи, действующие только на этот запрос, — потому что внешний движок знал
// только то, что доехало до него очередью. Форма читает эти строки ПЕРВЫМ же
// вопросом и поднимается по цепи областей до вершины сама, поэтому дополнять её
// тем же самым нечем.
//
// Оставшееся второе слагаемое — плоский надзор администратора облака. Он спрашивает
// о ДРУГОМ объекте (`cluster:<синглтон>#system_admin`) и потому не является ни
// запасным путём, ни послаблением. Платит за него только отказ: общий разрешающий
// случай возвращается выше и лишнего вопроса не делает.
func (s *AuthorizeService) verdict(
	ctx context.Context, subject string, caMemo *clusterAdminMemo,
	relation, object string, condCtx map[string]any,
) (bool, error) {
	if s.relations == nil {
		return false, fmt.Errorf("%w: authz unavailable", iamerr.ErrUnavailable)
	}
	allowed, err := s.relations.CheckWithContext(ctx, subject, relation, object, condCtx)
	if err != nil {
		return false, fmt.Errorf("%w: authz unavailable: %w", iamerr.ErrUnavailable, err)
	}
	if allowed {
		return true, nil
	}
	admin, aerr := s.isClusterAdmin(ctx, caMemo, subject)
	if aerr != nil {
		return false, superGateUnavailable(aerr)
	}
	return admin, nil
}

// formatDenyReason composes a human-readable deny reason for a Check that
// returned false. It best-effort reads the subject's existing direct
// relations on the same object via FGA ReadTuples and embeds them so the
// caller can see what they DO have vs what they NEEDED. Falls back to a
// minimal "no path" message when ReadTuples fails or returns nothing —
// the deny decision itself is never affected by a ReadTuples failure
// (we already know it's a deny; this is just diagnostics).
//
// Example outputs:
//
//	subject user:usr_abc lacks relation 'editor' on vpc_network:vpcn_xyz
//	  (action 'vpc.networks.update'); current direct relations: [viewer]
//	subject user:usr_def lacks relation 'admin' on cluster:cluster_kacho_root
//	  (action 'iam.cluster.grantAdmin'); no direct relations granted
//
// The format is intentionally one-line + structured-enough for log
// pattern matching; UI surfaces it verbatim under a "Why was I denied?"
// disclosure. (deny_reasons remains repeated string for wire-format
// compat — we use the first slot.)
func (s *AuthorizeService) formatDenyReason(ctx context.Context, subject, relation, object, action string) string {
	return denyReasonText(subject, relation, object, action,
		s.readSubjectRelations(ctx, subject, object))
}

// denyReasonText собирает текст отказа из УЖЕ ПРОЧИТАННОЙ диагностики.
//
// Отделено от чтения намеренно: диагностику для страницы читают ОДНИМ вопросом
// на всю партию, а текст собирают на каждый отказ. Слитые вместе, они заставляли
// бы партию платить по вопросу за пункт — то есть возвращать стоимость набора
// туда, откуда её только что убрали. Текст при этом остаётся ОДИН на обе полосы:
// разойтись им негде.
func denyReasonText(subject, relation, object, action string, relations []string) string {
	tail := "no direct relations granted"
	if len(relations) > 0 {
		tail = fmt.Sprintf("current direct relations: [%s]", strings.Join(relations, ", "))
	}
	actionPart := ""
	if action != "" {
		actionPart = fmt.Sprintf(" (action %q)", action)
	}
	return fmt.Sprintf("subject %s lacks relation %q on %s%s; %s",
		subject, relation, object, actionPart, tail)
}

// readSubjectRelationsMany — та же диагностика о СТРАНИЦЕ объектов одного типа,
// одним вопросом.
//
// Best-effort ровно в той же мере, что и пообъектная: отказ уже принят, и
// недоступная диагностика просто не добавит хвоста. Пустая карта означает «хвоста
// не будет ни у одного», и это НЕ отказ — тот уже вынесен.
func (s *AuthorizeService) readSubjectRelationsMany(ctx context.Context, subject, objectType string,
	objectIDs []string) map[string][]string {
	if s.relations == nil || subject == "" || objectType == "" || len(objectIDs) == 0 {
		return nil
	}
	relations, err := s.relations.DirectRelationsMany(ctx, subject, objectType, objectIDs, 16)
	if err != nil {
		return nil
	}
	return relations
}

// readSubjectRelations best-effort enumerates the (subject, *, object)
// direct tuples and returns the set of relation names (deduplicated,
// stable order). Returns nil on any error — the caller treats nil as
// "no direct relations granted".
//
// Bounded by a small page size (16) because the diagnostic only needs
// a hint, not a full audit; an oversized list would be noise.
func (s *AuthorizeService) readSubjectRelations(ctx context.Context, subject, object string) []string {
	if s.relations == nil || subject == "" || object == "" {
		return nil
	}
	objectType, objectID, ok := splitFGAObject(object)
	if !ok {
		return nil
	}
	relations, err := s.relations.DirectRelations(ctx, subject, objectType, objectID, 16)
	if err != nil {
		// Диагностика не вправе испортить ответ: отказ уже принят, и хвост текста
		// просто не появится — ровно как не появлялся, когда не отвечало чужое
		// хранилище кортежей.
		return nil
	}
	return relations
}

// CheckRelationRequest — input for `CheckRelation` — the FGA-native variant
// of `Check` used by the server-side per-RPC authz gate
// (`InternalIAMService.Check`).
//
// Unlike CheckRequest, the caller supplies an already-resolved FGA
// `Relation` (`viewer`/`editor`/`admin`/…) and an FGA `Object` string
// (`<type>:<id>`) — the gateway/service-side permission-map has already done
// the action→relation resolution.
type CheckRelationRequest struct {
	Subject  string // "user:usr_xxx" / "service_account:sva_xxx" / "group:grp_xxx#member"
	Relation string // pre-resolved FGA relation
	Object   string // FGA object string "<type>:<id>"
	// HigherConsistency — вызывающий требует чтения, которое НЕ отстаёт от его
	// собственной только что закоммиченной записи.
	//
	// ТРЕБОВАНИЕ ВЫПОЛНЯЕТСЯ ВСЕГДА, И ЭТО НЕ «ПОЛЕ, НА КОТОРОЕ НЕ СМОТРЯТ».
	// Просьба адресовалась ЧУЖОМУ хранилищу, у которого была своя копия и свои
	// кэши чтения: без неё оно отвечало со своей отстающей стороны. Реляционная
	// форма читает ведущую базу службы, поэтому read-after-write у неё держится
	// by construction — гарантия, которую поле просит, дана безусловно, а не
	// проигнорирована.
	//
	// Поле остаётся на контракте намеренно: оно называет ТРЕБОВАНИЕ вызывающего,
	// а не способ его исполнения. Появится путь чтения с реплики (§7 приёмки R7-3
	// держит его вне границ) — требование снова станет различающим, и различать
	// его будет тот, кто этот путь заведёт.
	HigherConsistency bool
}

// splitFGAObject splits "<type>:<id>" on the FIRST colon. Object ids may
// themselves contain colons (registry_repository:<reg>/<repo>:<tag>), so the
// remainder is the id verbatim.
func splitFGAObject(object string) (objectType, objectID string, ok bool) {
	i := strings.Index(object, ":")
	if i <= 0 || i == len(object)-1 {
		return "", "", false
	}
	return object[:i], object[i+1:], true
}

// CheckRelation — relation-native authorization check (FGA Check + OPA
// overlay). Used by the cluster-internal per-RPC authz gate
// (`InternalIAMService.Check`). Reuses the same FGA + OPA pipeline as
// `Check`, but skips the action→relation resolution step because the caller
// already supplies the resolved relation.
func (s *AuthorizeService) CheckRelation(ctx context.Context, req CheckRelationRequest) (result *CheckResult, err error) {
	now := time.Now().UTC().Truncate(time.Second)
	result = &CheckResult{CheckedAt: now}

	if req.Subject == "" {
		return result, fmt.Errorf("Illegal argument subject: required")
	}
	if req.Relation == "" {
		return result, fmt.Errorf("Illegal argument relation: required")
	}
	if req.Object == "" {
		return result, fmt.Errorf("Illegal argument object: required")
	}

	// Server forces current_time into the conditions context.
	condCtx := map[string]any{"current_time": now.Unix()}

	allowed, err := s.verdictForRelation(ctx, req, condCtx)
	if err != nil {
		return result, err
	}
	result.Allowed = allowed
	if !allowed {
		// CheckRelation is the gateway/internal path — same rich-deny format as the
		// public Check (no `action` available here, so the action segment is omitted).
		result.DenyReasons = []string{s.formatDenyReason(ctx, req.Subject, req.Relation, req.Object, "")}
	}
	return result, nil
}

// verdictForRelation — ОКОНЧАТЕЛЬНЫЙ вердикт ВНУТРЕННЕЙ двери.
//
// Та же пара слагаемых, что у публичной, и по тем же причинам (см. verdict).
// Дверь эта — та, через которую идёт КАЖДЫЙ запрос платформы: интерсептор каждой
// службы спрашивает `InternalIAMService.Check`, а он делегирует сюда, не в
// публичный `Check`.
func (s *AuthorizeService) verdictForRelation(
	ctx context.Context, req CheckRelationRequest, condCtx map[string]any,
) (bool, error) {
	if s.relations == nil {
		return false, fmt.Errorf("%w: authz unavailable", iamerr.ErrUnavailable)
	}
	// Просьбы «ответь не с реплики» здесь больше нет, и это не потеря свойства.
	// Она адресовалась чужому хранилищу, у которого своя копия отставала; форма
	// читает ведущую базу службы, поэтому read-after-write у неё выполняется by
	// construction. Поле запроса остаётся ИМЕНЕМ требования вызывающего.
	allowed, err := s.relations.CheckWithContext(ctx, req.Subject, req.Relation, req.Object, condCtx)
	if err != nil {
		return false, fmt.Errorf("%w: authz unavailable: %w", iamerr.ErrUnavailable, err)
	}
	if allowed {
		return true, nil
	}
	admin, aerr := authzguard.SubjectIsClusterAdminPlainE(ctx, s.clusterAdmin, req.Subject)
	if aerr != nil {
		return false, superGateUnavailable(aerr)
	}
	return admin, nil
}

// BatchCheck — партия разбирается ПРОГОНАМИ, результаты — в порядке запроса.
//
// # Что такое прогон и почему единица именно он
//
// Это дверь, в которую входит фильтр списка КАЖДОГО сервиса-соседа: vpc, compute,
// nlb, storage и registry читают страницу из СВОЕЙ базы, режут её на партии не
// более чем по сто идентификаторов (предел проверяется ниже) и отдают их сюда.
// Такая партия ОДНОРОДНА by construction — один субъект, один тип, одно отношение,
// одни доводы условий, различаются только идентификаторы.
//
// Предикат пообъектен, и это свойство вопроса. Число ОБРАЩЕНИЙ к хранилищу
// пообъектным быть не обязано — и до этой правки было им: партия из ста стоила
// ста вопросов о вердикте и до ста вопросов за хвостом текста отказа. Здесь
// стояло, что «один вопрос на пункт присущ предикату»; это было неверно, и
// собственный комментарий рядом называл остаток открытым.
//
// Теперь пункты партии сводятся в ПРОГОНЫ по ключу «субъект · отношение · тип ·
// доводы условий», и каждый прогон стоит:
//
//	один вопрос о вердикте всей своей страницы  +
//	один вопрос надзора администратора облака на СУБЪЕКТА (мемоизирован) +
//	один вопрос диагностики на все отказы прогона.
//
// Однородная партия любой длины — это ОДИН прогон, то есть постоянная цена.
// Разнородная партия платит по прогону на группу; групп не больше, чем пунктов,
// поэтому хуже прежнего не становится никогда.
//
// # Почему пул остался, хотя однородная партия — один вопрос
//
// Единица работы сменилась (прогон вместо пункта), а довод — нет: бюджет
// вызывающего принадлежит ЗАПРОСУ. Партия, чьи пункты называют РАЗНЫЕ субъекты
// (форма, которую метод поддерживает явно), даёт столько прогонов, сколько
// субъектов, и последовательный проход по ним стоил бы прогоны × время ответа
// хранилища. Предел `batchCheckParallelism` держит их одновременность
// ограниченной: неограниченный веер выложил бы всю страницу на хранилище разом, а
// одновременные списки других вызывающих умножились бы друг на друга.
//
// # Что НЕ изменилось, и это утверждается пробами
//
//   - ПОРЯДОК ЗАПРОСА. Ответ пишется в СВОЙ индекс, никогда не дописывается:
//     верный, но переставленный вердикт фильтрует страницу чужим ответом, и
//     заметить это вызывающий не может.
//   - ОТКАЗ ЦЕЛИКОМ на недоступности хранилища. Временный сбой — не пообъектный
//     запрет: он утёк бы сырым текстом транспорта на пользовательскую поверхность
//     и превратил бы перебой в постоянный 403. Первая такая ошибка прекращает
//     проход и отменяет остальные; пообъектная ошибка входа по-прежнему
//     вырождается в отказ с причиной и партию не роняет.
//   - ОДИН вопрос надзора НА СУБЪЕКТА (мемо — единая попытка, см. clusterAdminMemo).
//   - СОСТАВ ОТВЕТА, включая ТЕКСТ отказа: он собирается тем же
//     `denyReasonText` из той же диагностики, спрошенной иначе.
//
// # Часы — ОДНИ на проход
//
// Прежде каждый пункт брал своё «сейчас». Условия на записях вычисляются от него,
// поэтому пункты одной страницы могли получить разные доводы, а страница —
// описывать состояние, которого не было ни в один момент. Часы снимаются один раз
// и раздаются разбору всех пунктов.
func (s *AuthorizeService) BatchCheck(ctx context.Context, reqs []CheckRequest) ([]*CheckResult, error) {
	if len(reqs) > 100 {
		return nil, fmt.Errorf("Illegal argument checks: batch size %d > 100", len(reqs))
	}
	out := make([]*CheckResult, len(reqs))
	if len(reqs) == 0 {
		return out, nil
	}
	now := time.Now().UTC().Truncate(time.Second)
	// Share ONE cluster-admin memo across the batch: a same-subject batch (the
	// common shape) resolves the cluster:…#system_admin question at most once on
	// the deny path instead of once per item. The memo re-resolves when the
	// subject changes, so a mixed-subject batch stays correct.
	caMemo := &clusterAdminMemo{}

	// ── Фаза 1: разбор БЕЗ единого обращения к хранилищу.
	//
	// Здесь решается всё, что решается без вопроса: негодный вход, неразрешимое
	// отношение, неадресуемый объект. Остальное сводится в прогоны.
	plans := make([]checkPlan, len(reqs))
	runs := make(map[string]*batchRun, len(reqs))
	order := make([]*batchRun, 0, len(reqs))
	for i, req := range reqs {
		p := planCheck(ctx, req, now)
		plans[i] = p
		if p.invalid != nil {
			// Genuine per-item validation failure (e.g. "Illegal argument …",
			// deterministic + leak-free) surfaces as allowed=false + deny=[err];
			// the whole batch does NOT fail.
			out[i] = &CheckResult{Allowed: false, DenyReasons: []string{p.invalid.Error()}, CheckedAt: now}
			continue
		}
		key := runKeyOf(p)
		run := runs[key]
		if run == nil {
			run = &batchRun{
				subject:    p.subject,
				relation:   p.relation,
				objectType: p.objectType,
				condCtx:    p.condCtx,
				superGate:  p.superGateDecides,
			}
			runs[key] = run
			order = append(order, run)
		}
		run.items = append(run.items, i)
		if !p.superGateDecides {
			run.objects = append(run.objects, p.object)
		}
	}
	if len(order) == 0 {
		return out, nil
	}

	// ── Фаза 2: по вопросу на прогон, прогоны — параллельно с объявленным пределом.
	//
	// The first unavailable-class error aborts the pass; cancelling stops the
	// workers that have not asked yet rather than paying for answers already known
	// to be discarded.
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()

	workers := batchCheckParallelism
	if len(order) < workers {
		workers = len(order)
	}
	queue := make(chan *batchRun)

	var (
		mu      sync.Mutex
		firstEr error
		wg      sync.WaitGroup
	)
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for run := range queue {
				if err := s.resolveRun(cctx, run, caMemo, now, plans, out); err != nil {
					// An unavailable backend is NOT a per-item deny: mirror the
					// standalone Check sibling and fail the WHOLE batch with the
					// ErrUnavailable sentinel (handler → retryable gRPC Unavailable
					// with a fixed redacted message). Collapsing it into a
					// deny_reason would leak the raw resolver error onto a
					// user-facing surface AND mis-signal a transient outage as a
					// permanent 403 (security.md hardening-invariant #1).
					mu.Lock()
					if firstEr == nil {
						firstEr = err
						cancel()
					}
					mu.Unlock()
					return
				}
			}
		}()
	}
feed:
	for _, run := range order {
		select {
		case queue <- run:
		case <-cctx.Done():
			break feed // a worker already failed the batch closed; stop feeding
		}
	}
	close(queue)
	wg.Wait()

	if firstEr != nil {
		return nil, firstEr
	}
	// cancel() is called only after firstEr is set, so a done cctx with no recorded
	// error means the CALLER's context expired mid-batch. Report it rather than
	// handing back a partially-filled slice whose unresolved slots are nil.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// batchRun — ОДНОРОДНАЯ часть партии: один субъект, одно отношение, один тип,
// одни доводы условий. Ровно та форма, в какой хранилище отвечает одним вопросом.
//
// superGate помечает прогон, у которого вопроса к форме нет вовсе (отношение не
// разрешается либо объект не адресуем): решение по нему принимает надзор
// администратора облака, и оно одно на весь прогон, потому что субъект один.
type batchRun struct {
	subject    string
	relation   string
	objectType string
	condCtx    map[string]any
	superGate  bool

	items   []int    // позиции пунктов в исходной партии
	objects []string // «тип:идентификатор» тех же позиций, в том же порядке
}

// runKeyOf — ключ прогона.
//
// # Что входит в ключ и почему
//
// Прогон отвечается ОДНИМ вопросом, поэтому в него можно сводить только пункты,
// у которых вопрос и вправду один: субъект, отношение, тип объекта — и ДОВОДЫ
// УСЛОВИЙ. Последние не перестраховка: они вычисляются вместе с вердиктом, и
// ответ, полученный при одних доводах, не является ответом при других.
//
// Имена доводов сортируются: карта порядка обхода не обещает, и без сортировки
// одинаковые доводы давали бы разные ключи — то есть лишние прогоны, молча и
// по-разному от прохода к проходу.
//
// # Однозначными обязаны быть ДВЕ вещи, и это разные вещи
//
// Часть доводов приходит из тела запроса, то есть от арендатора
// (`structpb.Struct.AsMap()` отдаёт в том числе списки и отображения — см.
// разбор запроса в обработчике). Столкновение ключа означает здесь не неудобство,
// а подмену: два пункта сливаются в прогон, и второй отвечается доводами первого
// (`resolveRun` берёт доводы ПЕРВОГО пункта прогона).
//
// Столкнуть можно на двух разных уровнях, и закрывать их нужно порознь:
//
//  1. СКЛЕЙКА частей. Разделитель — какой угодно — арендатор кладёт внутрь
//     значения, и «имя=значение\0имя=значение» становится неотличимо от одного
//     значения, проглотившего соседа. Закрыто ДЛИНОЙ перед каждой частью:
//     кодировка становится однозначной by construction.
//  2. САМО ЗНАЧЕНИЕ. Здесь стояло, что длины достаточно и «подобрать
//     столкновение нечем». Это было неверно, и неверно ровно на том, что
//     контракт допускает явно: `%v` у составных величин неоднозначен, поэтому
//     `["prod","eu"]` и `["prod eu"]` печатаются ОДИНАКОВО, как и
//     `{"a":"b","c":"d"}` против `{"a":"b c:d"}`. Длина внешней склейки об этом
//     ничего не знает — она честно кодирует одну и ту же строку.
//
// Второе закрыто КАНОНИЧЕСКОЙ кодировкой значения (`json.Marshal`): у списка
// сохраняются границы элементов, у отображения — границы пар, а имена полей
// сортируются самой библиотекой, поэтому одинаковые отображения дают одинаковый
// текст независимо от порядка обхода карты.
//
// Тип значения пишется рядом со значением: `json.Marshal` печатает `int(1)` и
// `float64(1)` одинаково, а условие вправе их различать.
//
// Значение, которое канонически не кодируется (величина, не выразимая в JSON),
// получает ключ, УНИКАЛЬНЫЙ для своего пункта: пункт уезжает собственным
// прогоном. Это дороже и это верно — сливать можно лишь то, о чём доказано, что
// оно одно и то же.
func runKeyOf(p checkPlan) string {
	var b strings.Builder
	writePart := func(s string) { fmt.Fprintf(&b, "%d:%s", len(s), s) }

	if p.superGateDecides {
		// Прогон надзора: объект в решении не участвует, но ТЕКСТ отказа зависит
		// от причины, и смешивать причины в одном прогоне нельзя.
		writePart("super")
		writePart(p.subject)
		writePart(p.denyReason)
		return b.String()
	}
	writePart("ask")
	writePart(p.subject)
	writePart(p.relation)
	writePart(p.objectType)
	keys := make([]string, 0, len(p.condCtx))
	for k := range p.condCtx {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := p.condCtx[k]
		enc, err := json.Marshal(v)
		if err != nil {
			// Канонически не кодируется — значит доказать, что довод совпадает с
			// чужим, нечем. Пункт уезжает СВОИМ прогоном: ключ уникален по его
			// объекту. Fail-closed в сторону дороже-но-верно.
			writePart("uncanonical")
			writePart(p.object)
			return b.String()
		}
		writePart(k)
		writePart(fmt.Sprintf("%T", v))
		writePart(string(enc))
	}
	return b.String()
}

// resolveRun отвечает на один прогон и заполняет его позиции.
//
// Ошибка означает ТОЛЬКО недоступность хранилища и роняет партию целиком; всё
// остальное — вердикт, а вердикт всегда попадает в свою позицию.
func (s *AuthorizeService) resolveRun(ctx context.Context, run *batchRun, caMemo *clusterAdminMemo,
	now time.Time, plans []checkPlan, out []*CheckResult) error {
	if run.superGate {
		// Вопроса к форме нет; решение принимает надзор — один вопрос на прогон,
		// потому что субъект в прогоне один (и он же мемоизирован на весь проход).
		admin, aerr := s.isClusterAdmin(ctx, caMemo, run.subject)
		if aerr != nil {
			// Партия роняется ЦЕЛИКОМ: молча суженный набор разрешений — это
			// страница видимого, отданная соседу как истина.
			return superGateUnavailable(aerr)
		}
		for _, i := range run.items {
			if admin {
				out[i] = &CheckResult{Allowed: true, CheckedAt: now}
				continue
			}
			out[i] = &CheckResult{Allowed: false, DenyReasons: []string{plans[i].denyReason}, CheckedAt: now}
		}
		return nil
	}

	if s.relations == nil {
		return fmt.Errorf("%w: authz unavailable", iamerr.ErrUnavailable)
	}
	verdicts, err := s.relations.BatchCheckWithContext(ctx, run.subject, run.relation, run.objects, run.condCtx)
	if err != nil {
		return fmt.Errorf("%w: authz unavailable: %w", iamerr.ErrUnavailable, err)
	}
	if len(verdicts) != len(run.objects) {
		// Ответ не позиционен — сверять его со страницей не по тем местам значило
		// бы отфильтровать её чужим вердиктом. Это недоступность ответа, а не
		// пообъектный запрет.
		return fmt.Errorf("%w: authz unavailable: verdicts %d for %d objects",
			iamerr.ErrUnavailable, len(verdicts), len(run.objects))
	}

	// Отказы собираются, а не оформляются на месте: хвост текста берётся из
	// диагностики, которую прогон спрашивает ОДНИМ вопросом на все свои отказы.
	denied := make([]int, 0, len(run.items))
	deniedIDs := make([]string, 0, len(run.items))
	for k, i := range run.items {
		if verdicts[k] {
			out[i] = &CheckResult{Allowed: true, CheckedAt: now}
			continue
		}
		// Надзор администратора облака — авторитет на всём, и спрашивается ТОЛЬКО
		// на отказе: общий разрешающий случай лишнего вопроса не делает.
		admin, aerr := s.isClusterAdmin(ctx, caMemo, run.subject)
		if aerr != nil {
			return superGateUnavailable(aerr)
		}
		if admin {
			out[i] = &CheckResult{Allowed: true, CheckedAt: now}
			continue
		}
		denied = append(denied, i)
		deniedIDs = append(deniedIDs, plans[i].objectID)
	}
	if len(denied) == 0 {
		return nil
	}
	tails := s.readSubjectRelationsMany(ctx, run.subject, run.objectType, deniedIDs)
	for _, i := range denied {
		p := plans[i]
		out[i] = &CheckResult{
			Allowed:     false,
			DenyReasons: []string{denyReasonText(p.subject, p.relation, p.object, p.action, tails[p.objectID])},
			CheckedAt:   now,
		}
	}
	return nil
}

// ПЕРЕЧИСЛЕНИЯ ОБЪЕКТОВ ЗДЕСЬ БОЛЬШЕ НЕТ — снято с контракта (решение Р1, R7-3).
//
// Оно отвечало ОГРАНИЧЕННЫМ ПРЕФИКСОМ без продолжения: потолок ставила чужая
// сторона, признак усечения отдавался честно, а получить остаток было нельзя
// НИКАК. Значит объекты сверх потолка оставались недостижимы при живых правах —
// ровно то, что `security.md` §«Фильтрация» запрещает формулой «страница →
// проверка страницы, НИКОГДА перечисли вселенную → отфильтруй».
//
// Заменителя не введено намеренно. «Что мне видно» получают постраничным `List`
// ресурсной службы, который сужает СТРАНИЦУ пообъектной проверкой (`pkg/listnarrow`).

// ListSubjectsRequest — input.
type ListSubjectsRequest struct {
	ResourceType      string
	ResourceID        string
	Action            string
	PageSize          int
	PageToken         string
	SubjectTypeFilter string
}

// ListSubjectsResult — output.
type ListSubjectsResult struct {
	Subjects      []string
	NextPageToken string
}

// ListSubjects — inverse of ListObjects.
func (s *AuthorizeService) ListSubjects(ctx context.Context, req ListSubjectsRequest) (_ *ListSubjectsResult, err error) {
	if s.relations == nil {
		return nil, fmt.Errorf("%w: authz unavailable", iamerr.ErrUnavailable)
	}
	if req.PageSize > 1000 {
		return nil, fmt.Errorf("Illegal argument page_size %d > 1000", req.PageSize)
	}
	relation := resolveActionToRelation(req.Action)
	if relation == "" {
		return nil, fmt.Errorf("Illegal argument action %q", req.Action)
	}
	subs, next, err := s.relations.ListSubjects(ctx, req.ResourceType, req.ResourceID, relation, req.PageSize, req.PageToken)
	if err != nil {
		return nil, fmt.Errorf("authz listSubjects: %w", err)
	}
	// Страница с продолжением — не всё множество: сверять её с полным ответом формы
	// значило бы записать расхождением границу страницы.
	if req.SubjectTypeFilter != "" {
		filtered := subs[:0]
		prefix := req.SubjectTypeFilter + ":"
		for _, s := range subs {
			if strings.HasPrefix(s, prefix) {
				filtered = append(filtered, s)
			}
		}
		subs = filtered
	}
	return &ListSubjectsResult{Subjects: subs, NextPageToken: next}, nil
}

// ExpandRequest — input.
type ExpandRequest struct {
	ResourceType string
	ResourceID   string
	Relation     string
}

// ExpandResult — output.
type ExpandResult struct {
	Resource ResourceRef
	Relation string
	Tree     *authztypes.ExpandTree
}

// ExpandRelations — ИЗ ЧЕГО складывается право на объекте.
//
// Отвечает реляционная форма: основания права разворачиваются в набор субъектов,
// которые это право в итоге получают. Ответ ОДНОУРОВНЕВЫЙ, и это свойство
// источника, а не упрощение переходника: основание — плоская запись (факт ·
// выдача · членство), и глубины у него не бывает.
//
// Графовые рёбра сняты с контракта вместе с движком, который их производил
// (решение S6): поле, которое не заполняется никогда, обещает возможность,
// которой нет.
func (s *AuthorizeService) ExpandRelations(ctx context.Context, req ExpandRequest) (*ExpandResult, error) {
	if s.relations == nil {
		return nil, fmt.Errorf("%w: authz unavailable", iamerr.ErrUnavailable)
	}
	subjects, err := s.relations.Sources(ctx, req.ResourceType, req.ResourceID, req.Relation)
	if err != nil {
		return nil, fmt.Errorf("authz expand: %w", err)
	}
	return &ExpandResult{
		Resource: ResourceRef{Type: req.ResourceType, ID: req.ResourceID},
		Relation: req.Relation,
		Tree:     &authztypes.ExpandTree{Leaves: subjects},
	}, nil
}

// resolveActionToRelation — `<domain>.<resource>.<verb>` → FGA relation.
// Convention from kacho-corelib/authz: relation is `<resource>_<verb>` for
// verbs in {get,list,update,delete,create} mapped to {viewer,viewer,editor,
// admin,editor}. For domain-specific actions we fall back to the verb
// directly (`compute.instances.ssh` → `ssh`).
func resolveActionToRelation(action string) string {
	parts := strings.Split(action, ".")
	if len(parts) < 2 {
		return ""
	}
	// Lower-case the verb: action strings carry the RPC method name with its
	// first letter lowered but inner camelCase preserved (Get→get,
	// ListByScope→listByScope, AddCidrBlocks→addCidrBlocks). The case
	// labels below are all lower-case, so without this fold a multi-word verb
	// like "listByScope" would miss every case and fall through to the
	// unknown→deny branch — which regressed legitimate non-CRUD reads/mutations
	// (e.g. AccessBindingService.ListByScope → 403). Folding here keeps the
	// fail-closed posture for genuinely-unknown verbs while correctly mapping
	// the known multi-word ones.
	verb := strings.ToLower(parts[len(parts)-1])
	switch verb {
	case "get", "list":
		return "viewer"
	case "create", "update":
		return "editor"
	case "delete":
		return "admin"
	// Action verbs that are semantically editor-level mutations but are not
	// the canonical CRUD verbs. Mapping them to a real model relation avoids
	// an FGA 400 (unknown relation) on the Check.
	case "invite", "move", "start", "stop", "restart",
		"addmember", "removemember", "addmembers", "removemembers",
		"attachdisk", "detachdisk", "attachnetworkinterface",
		"detachnetworkinterface", "attachfilesystem", "detachfilesystem",
		"addlistener", "removelistener",
		"attachtargetgroup", "detachtargetgroup", "enablezones",
		"disablezones", "addtargets", "removetargets",
		"updaterule",
		"updaterules", "addcidrblocks", "removecidrblocks",
		// SAKey credential-mutation verbs — issuing/revoking a Service Account
		// OAuth key (SAKeyService.Issue/Revoke). Catalog gates these at editor;
		// the verb-fallback must agree so an action-only (no required_relation)
		// Check doesn't unknown→deny them (regressed SAKeyService.Issue → 403).
		"issue", "revoke":
		return "editor"
	case "listaccessbindings", "listoperations", "gettargetstates",
		"getserialportoutput", "getlatestbyfamily", "getbyvalue",
		"listbysubnet", "listsubnets", "listsecuritygroups",
		"listroutetables", "listmembers", "listsnapshotschedules",
		"listusedaddresses", "listbyscope", "listbysubject", "batchcheck",
		"check", "expandrelations", "listsubjects", "evaluate":
		return "viewer"
	}
	// Domain-specific known model relations pass through verbatim
	// (e.g. compute.instances.ssh → ssh, compute.instances.console → console).
	switch verb {
	case "ssh", "console", "admin", "editor", "viewer":
		return verb
	}
	// Unknown verb — fail-closed. Defaulting to "viewer" is over-permissive: a
	// read-only subject already holds `viewer`, so a typo'd or unrecognised
	// MUTATING verb would be wrongly ALLOWED. Returning "" signals the caller
	// to deny explicitly (Check: empty relation → deny; ListObjects/ListSubjects:
	// empty relation → InvalidArgument). New verbs must be added to a mapping
	// above before they can authorize.
	return ""
}
