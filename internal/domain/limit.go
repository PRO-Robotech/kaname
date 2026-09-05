// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

import (
	"fmt"
	"strings"
	"time"

	"go.uber.org/multierr"
)

// LimitID — id of a Limit. Hyphen canon `lim-<17>` (ids.PrefixLimitHyphen),
// immutable for the life of the resource and the only externally addressable
// identity (core rule #15).
type LimitID string

// LimitScope — where a ceiling is stated. Three arms, ordered by specificity:
// PROJECT beats ACCOUNT beats DEFAULT.
type LimitScope string

// LimitScope values. Mirrored by a DB CHECK.
const (
	// LimitScopeDefault — platform-wide fallback; exactly one row per kind.
	LimitScopeDefault LimitScope = "DEFAULT"
	// LimitScopeAccount — stated for one account.
	LimitScopeAccount LimitScope = "ACCOUNT"
	// LimitScopeProject — stated for one project; the most specific arm.
	LimitScopeProject LimitScope = "PROJECT"
)

// Specificity — how strongly this scope overrides the others. Higher wins.
//
// It is a METHOD rather than a comparison written at each resolve site: the
// precedence rule is one rule, and three places asserting it independently would
// disagree the first time a fourth scope appeared.
func (s LimitScope) Specificity() int {
	switch s {
	case LimitScopeProject:
		return 3
	case LimitScopeAccount:
		return 2
	case LimitScopeDefault:
		return 1
	default:
		return 0
	}
}

// Validate — the scope is one of the three named arms.
func (s LimitScope) Validate() error {
	if s.Specificity() == 0 {
		return fmt.Errorf("Illegal argument scope: must be DEFAULT, ACCOUNT or PROJECT")
	}
	return nil
}

// LimitKind — a dotted token naming what is being counted. Two forms, and only
// two:
//
//	`<domain>.<resource>`            — a resource counted in its carrier
//	`<domain>.<parent>.<child>`      — how many <child> fit in ONE <parent>
//
// Both forms name REAL types of the authorization model, and the three-part form
// names two of them. That is a gate rather than a convention: a ceiling stated on
// a name the platform does not know is a ceiling nobody can check and nobody can
// show the tenant (§7 п.9 of the acceptance).
type LimitKind string

// Service — the owner service this kind belongs to (`vpc.network` → `vpc`,
// `vpc.network.subnet` → `vpc`).
//
// Derived from the token rather than stored beside it: two fields naming one
// thing drift, and the dot is the same separator the platform's reference types
// already use.
func (k LimitKind) Service() string {
	if i := strings.IndexByte(string(k), '.'); i > 0 {
		return string(k)[:i]
	}
	return ""
}

// Parts splits the kind into its dotted segments.
func (k LimitKind) Parts() []string { return strings.Split(string(k), ".") }

// Nested reports whether this kind bounds children within ONE parent
// (`vpc.network.subnet`) rather than within the carrier as a whole.
func (k LimitKind) Nested() bool { return len(k.Parts()) == 3 }

// ParentKind — the two-part token of the parent a nested kind counts within;
// empty for a flat kind. `vpc.network.subnet` → `vpc.network`.
//
// This is the token that must resolve against the closed table, and it is
// returned rather than re-derived at each call site so the two halves of the
// three-part gate cannot disagree about where the split is.
func (k LimitKind) ParentKind() LimitKind {
	p := k.Parts()
	if len(p) != 3 {
		return ""
	}
	return LimitKind(p[0] + "." + p[1])
}

// ChildKind — the two-part token of the child a nested kind counts; empty for a
// flat kind. `vpc.network.subnet` → `vpc.subnet`.
//
// The child's domain is the kind's domain: a nested kind never crosses a service
// boundary, because the parent and the child are rows of one database and the
// count is an invariant of one schema (data-integrity §within-service).
func (k LimitKind) ChildKind() LimitKind {
	p := k.Parts()
	if len(p) != 3 {
		return ""
	}
	return LimitKind(p[0] + "." + p[2])
}

// LimitCarrier — the type of object a kind is counted IN.
//
// WHY IT IS DECLARED AND NOT DERIVED. The temptation is "two parts ⇒ counted in
// a project", and that rule is false on the first entry that already exists:
// `iam.project` has two parts and is counted in an ACCOUNT, because a project
// does not live inside a project. A guess here does not fail loudly — it counts
// the right rows against the wrong owner, and the tenant sees a ceiling that
// never moves. So the carrier travels beside the kind, and the pair is the unit
// of the catalogue.
type LimitCarrier string

// The carriers that are not resource kinds: the tenancy roots. Any other carrier
// is a two-part token of the closed table (`vpc.network`), naming the parent a
// nested kind is counted within.
const (
	// CarrierProject — counted per project. The common case.
	CarrierProject LimitCarrier = "project"
	// CarrierAccount — counted per account. Used by kinds that have no project
	// to live in: projects themselves, and the account-scoped iam subjects.
	CarrierAccount LimitCarrier = "account"
	// CarrierIdentity — counted per HUMAN, across every account they hold.
	//
	// # Why a third root had to exist
	//
	// A carrier must be EXTERNAL to the thing it counts, and for the account
	// neither of the two above is: an account cannot be counted inside an
	// account, and it has no project. That is not an implementation gap but the
	// shape of the tenancy: the account is its root, and the root has no parent
	// below the cluster.
	//
	// Counting per cluster was the obvious alternative and it is worse in the way
	// that matters: the refusal reaches the NEXT honest tenant rather than the one
	// who exhausted the shelf. The identity is the only thing that exists BEFORE
	// an account and outlives it, so it is the only carrier on which the refusal
	// lands on its cause.
	//
	// # What identifies it, and why not the user row
	//
	// The identity is the external login subject (`users.external_id`), NOT the
	// user row. A user row is a MEMBERSHIP: it is scoped to one account, and one
	// human legitimately holds one per account. Counting per user row would tie
	// the ceiling to the very thing that multiplies as soon as the account
	// coupling is removed — that is, it would hand out the bypass together with
	// the change it is meant to survive.
	CarrierIdentity LimitCarrier = "identity"
)

// Validate — the carrier names one of the tenancy roots, or is shaped like a
// two-part catalogue token.
//
// That the token RESOLVES against the authorization model is proved by
// authzmap's gate, not here: this package must not import the authz map (that
// package's gate already imports this one), and a second copy of the closed
// table here would be the two-places-one-subject class the corpus warns about.
func (c LimitCarrier) Validate() error {
	if c == "" {
		return fmt.Errorf("carrier: required")
	}
	if c == CarrierProject || c == CarrierAccount || c == CarrierIdentity {
		return nil
	}
	if parts := strings.Split(string(c), "."); len(parts) == 2 && parts[0] != "" && parts[1] != "" {
		return nil
	}
	return fmt.Errorf(
		"Illegal argument carrier: %s is neither project, account, identity, nor a <domain>.<resource> type", c)
}

// CountableKind — one catalogue record: WHAT is counted and WHERE it is counted.
type CountableKind struct {
	Kind    LimitKind
	Carrier LimitCarrier
}

// countableKinds — the CLOSED catalogue of kinds a ceiling may be stated on, in
// the order an answer lists them.
//
// WHY CLOSED. A ceiling stated on a kind nobody counts is a field that is
// accepted and never applied: the administrator sees success and the tenant sees
// no effect (api-conventions §«Принято-и-проигнорировано»). So membership is
// checked on the way in, by name.
//
// WHY THIS LIST AND NOT THE EXECUTOR'S VOCABULARY. The vpc arm has EIGHT members,
// not seven. The service's own architecture note derived the tenant's countable
// kinds from the closed dictionary of the data-plane intent projection — and that
// dictionary describes what the executor is told, not what the tenant pays for:
// `vpc.cidrGroup` carries a project, has its own public service and its own authz
// type, but is never projected, because it is a named list of prefixes rather
// than a data-plane entity. Deriving the catalogue from the authorization model
// gives eight; deriving it from the projection loses exactly that one.
//
// The list is guarded, not merely written: authzmap's
// TestLimitKindsAreKnownObjectTypes proves every entry names a real authz object
// type, and TestEveryTenantTypeIsCountable proves no grantable pair of ANY domain
// can be introduced without either a ceiling or a documented exclusion — which is
// the mechanism by which the eighth vpc kind was lost the first time.
//
// # Carriers are measured, not assumed
//
// Every carrier below was read off the schema that holds the rows, not inferred
// from the name: the iam subjects carry `account_id` and no project, compute's
// `instances` carries `project_id` (its migration 0009 renamed the column), and
// repository rows reach their project through their registry — a join inside one
// database, not a call to a neighbour.
var countableKinds = []CountableKind{
	// vpc — every row carries `project_id`.
	{"vpc.network", CarrierProject},
	{"vpc.subnet", CarrierProject},
	{"vpc.address", CarrierProject},
	{"vpc.networkInterface", CarrierProject},
	{"vpc.securityGroup", CarrierProject},
	{"vpc.routeTable", CarrierProject},
	{"vpc.gateway", CarrierProject},
	{"vpc.cidrGroup", CarrierProject},

	// vpc, nested — how many children fit in ONE parent. The danger the owner
	// named ("resources able to bring the infrastructure down") lives in the
	// nesting, not in the project total: one network with ten thousand subnets
	// is a different failure from ten thousand subnets spread across projects.
	// Declared here; counted by vpc in S3.
	{"vpc.network.subnet", "vpc.network"},
	{"vpc.network.routeTable", "vpc.network"},
	{"vpc.network.securityGroup", "vpc.network"},
	// Здесь стоял `vpc.subnet.networkInterface` — «сколько интерфейсов в одной
	// подсети». Снят вместе с посевом: решение по этой паре — НЕ ограничивать, а
	// вид без списания есть величина, которую администратор задаёт впустую.
	//
	// Причина решения содержательна, а не «руки не дошли»: число интерфейсов в
	// подсети ограничено её адресным пространством, и отказ по исчерпанию уже
	// реализован. Второй предел поверх конечного ресурса способен лишь отказать
	// раньше, чем кончатся адреса, — то есть отнять у арендатора часть уже
	// оплаченного им пространства.
	//
	// Плоский `vpc.networkInterface` (сколько их у ПРОЕКТА) остаётся ниже и
	// продолжает списываться: снята ось «в одной подсети», а не учёт вообще.

	// iam — the account is the tenancy root, and these have no project to live
	// in. `iam.project` is the entry that makes "two parts ⇒ project" false.
	//
	// The account itself is counted per IDENTITY, and it is the only entry whose
	// carrier is neither of the first two roots. Without it every ceiling inside
	// an account is bought back by the same self-service action that produced the
	// account: a second account is a second full set of ceilings, obtained by the
	// gesture that obtained the first. This entry is also the one that makes iam a
	// service that CHARGES, not only the one that states values — the accounts it
	// counts live in its own database, so the charge is in the same transaction as
	// the insert and needs no distributed transaction.
	{"iam.account", CarrierIdentity},
	{"iam.project", CarrierAccount},
	{"iam.user", CarrierAccount},
	{"iam.serviceAccount", CarrierAccount},
	{"iam.group", CarrierAccount},
	{"iam.role", CarrierAccount},
	// The binding's target is polymorphic and carries no tenancy column of its
	// own; iam reaches the account through its OWN mirror
	// (`resource_mirror.parent_account_id`), which owners already populate. No
	// new edge, and in particular not the `iam → owner` edge §7 п.3 forbids.
	{"iam.accessBinding", CarrierAccount},

	// Удостоверения принципала — сколько путей входа он держит одновременно
	// (задача #1191). Считаются ВСЕ, независимо от вида предъявления
	// (KEYPAIR · SECRET · FEDERATED · LEGACY) и от того, действует ли
	// удостоверение сейчас: слот освобождает ОТЗЫВ, а не истечение срока.
	//
	// Ребёнок обоих видов — `iam.credential`, ПОДЧИНЁННЫЙ РЕСУРС
	// (`credential_ceiling.go`): своего типа модели прав у удостоверения нет,
	// потому что право на него вычисляется от принципала.
	//
	// Носитель — САМ принципал, а не внешний субъект входа, и это отличается от
	// соседнего вида `iam.account` осознанно: счёт ведётся там, где живёт
	// внешний ключ строки удостоверения, приглашённый (у которого внешнего
	// субъекта ещё нет) остаётся под потолком, а у машины внешнего субъекта нет
	// вовсе — один принцип на оба ресурса вместо двух разных.
	{"iam.user.credential", "iam.user"},
	{"iam.serviceAccount.credential", "iam.serviceAccount"},

	// compute — `project_id` on every row.
	{"compute.instance", CarrierProject},
	{"compute.guestAccessKey", CarrierProject},
	{"compute.placementGroup", CarrierProject},

	// storage — `project_id` on every row.
	{"storage.volumes", CarrierProject},
	{"storage.snapshots", CarrierProject},
	{"storage.images", CarrierProject},

	// loadbalancer — `project_id` on every row, listeners included.
	{"loadbalancer.networkLoadBalancers", CarrierProject},
	{"loadbalancer.targetGroups", CarrierProject},
	{"loadbalancer.listeners", CarrierProject},

	// loadbalancer, nested — how many listeners fit in ONE balancer. Counted by
	// nlb in S4.
	//
	// The pair `targetGroups → targets` is NOT here and its absence is a
	// decision, not an oversight: `Target` is a row of `kacho_nlb.targets` but
	// not a grantable type (the model declares three nlb types and
	// `nlb_target` is not among them), so the token would fail this very
	// catalogue's gate. Weakening the gate for one convenient pair would open
	// it for ceilings on things the authorization model cannot name. The risk
	// ("too many targets in one group") stays OPEN and is carried in §6 of the
	// acceptance with the predicate that would close it.
	{"loadbalancer.networkLoadBalancers.listeners", "loadbalancer.networkLoadBalancers"},

	// registry — registries carry `project_id`; repository rows carry only
	// `registry_id` and reach the project by joining their registry.
	{"registry.registries", CarrierProject},
	{"registry.repositories", CarrierProject},

	// registry, nested — how many repositories fit in ONE registry. Counted by
	// registry in S4.
	{"registry.registries.repositories", "registry.registries"},
}

// CountableEntries returns a COPY of the closed catalogue, in catalogue order.
func CountableEntries() []CountableKind {
	out := make([]CountableKind, len(countableKinds))
	copy(out, countableKinds)
	return out
}

// CountableKinds returns just the kinds of the catalogue, in catalogue order.
func CountableKinds() []LimitKind {
	out := make([]LimitKind, 0, len(countableKinds))
	for _, e := range countableKinds {
		out = append(out, e.Kind)
	}
	return out
}

// CarrierOfKind returns the carrier a kind is counted in. The second result is
// false for a kind outside the catalogue — and the caller must not read a missing
// carrier as "project": that default is exactly the guess V2-2 forbids.
func CarrierOfKind(k LimitKind) (LimitCarrier, bool) {
	for _, e := range countableKinds {
		if e.Kind == k {
			return e.Carrier, true
		}
	}
	return "", false
}

// CountableKindsOfService returns the catalogue entries owned by one service, in
// catalogue order. An unknown service yields an empty slice — and the caller must
// treat that as "this service counts nothing", not as "every kind".
func CountableKindsOfService(service string) []LimitKind {
	out := make([]LimitKind, 0, len(countableKinds))
	for _, e := range countableKinds {
		if e.Kind.Service() == service {
			out = append(out, e.Kind)
		}
	}
	return out
}

// IsCountableKind reports membership in the closed catalogue.
func IsCountableKind(k LimitKind) bool {
	for _, c := range countableKinds {
		if c.Kind == k {
			return true
		}
	}
	return false
}

// Validate — membership in the closed catalogue, refused by the field's name.
//
// Membership is the only check needed: the catalogue admits two shapes and no
// others, and every entry in it is proved well-formed and type-resolvable by
// authzmap's gates. A token of four parts, or of two parts naming nothing, is
// simply not a member.
func (k LimitKind) Validate() error {
	if k == "" {
		return fmt.Errorf("kind: required")
	}
	if !IsCountableKind(k) {
		return fmt.Errorf("Illegal argument kind: %s is not a countable resource kind", k)
	}
	return nil
}

// Limit — the ceiling on how many resources of one kind a tenant may hold.
//
// The triple (Scope, ScopeID, Kind) IS the limit's identity among those in force;
// `Value` is the only mutable field. "Moving" a ceiling to another project or
// another kind is a different ceiling, created and withdrawn explicitly — an
// Update that could change the triple would silently transfer a tenant's headroom
// to a tenant who was never granted it.
type Limit struct {
	ID        LimitID
	CreatedAt time.Time

	Scope   LimitScope
	ScopeID string
	Kind    LimitKind
	Value   int64

	// WithdrawnAt — the moment the ceiling stopped applying. Zero → in force.
	//
	// A withdrawal is a tombstone rather than a deleted row because owner
	// services keep a PROJECTION of these values and refresh it by delta: a delta
	// that only ever reports writes can never drop a projection row, so a
	// withdrawn project override would keep overriding forever.
	WithdrawnAt time.Time

	// Revision — monotonic, assigned by the database. Advances on a change of
	// value or of withdrawal, and stands still when a write restates what was
	// already there.
	Revision int64
}

// Withdrawn reports whether the ceiling has been withdrawn.
func (l Limit) Withdrawn() bool { return !l.WithdrawnAt.IsZero() }

// Validate — self-validating domain entity.
//
// The scope/subject pairing is checked HERE as well as by a DB CHECK, and that is
// not a duplicate rule: the database makes the state inexpressible for every
// writer, and this makes the caller's answer name the FIELD they got wrong
// instead of a constraint they have never heard of.
func (l Limit) Validate() error {
	var errs error
	errs = multierr.Append(errs, l.Scope.Validate())
	errs = multierr.Append(errs, l.Kind.Validate())
	if l.Value < 0 {
		errs = multierr.Append(errs, fmt.Errorf("Illegal argument value: must not be negative"))
	}
	switch l.Scope {
	case LimitScopeDefault:
		if l.ScopeID != "" {
			errs = multierr.Append(errs,
				fmt.Errorf("Illegal argument scope_id: must be empty when scope is DEFAULT"))
		}
	case LimitScopeAccount, LimitScopeProject:
		if l.ScopeID == "" {
			errs = multierr.Append(errs,
				fmt.Errorf("scope_id: required when scope is %s", l.Scope))
		}
	}
	return errs
}

// LimitFilter — the three-valued narrowing a List accepts. Empty members mean "do
// not narrow by this"; the vocabulary is closed, so there is no filter grammar
// here and nothing to parse.
type LimitFilter struct {
	Scope   LimitScope
	ScopeID string
	Kind    LimitKind
}

// Validate — a narrowing value that is not a legal value of its dimension is
// refused by the field's NAME rather than silently matching nothing: a filter that
// quietly returns an empty page is indistinguishable from "there is nothing here".
func (f LimitFilter) Validate() error {
	var errs error
	if f.Scope != "" {
		errs = multierr.Append(errs, f.Scope.Validate())
	}
	if f.Kind != "" {
		errs = multierr.Append(errs, f.Kind.Validate())
	}
	return errs
}

// EffectiveLimit — one resolved ceiling plus the scope it was won at.
//
// The source travels with the value because an operator asking "why does this
// project stop at four" cannot otherwise tell a project override from an account
// one from the platform default without re-reading all three scopes by hand.
type EffectiveLimit struct {
	Kind  LimitKind
	Value int64
	// Carrier — ГДЕ этот вид считается: корень аренды (`project` / `account`)
	// либо двухчастный токен родительского типа.
	//
	// Едет вместе с величиной, потому что вывести его на стороне потребителя
	// НЕЛЬЗЯ: форма токена носителя не определяет (`iam.project` — двухчастный
	// вид, чей носитель не проект), а догадка здесь не отказывает громко — она
	// считает верные строки против неверного владельца, и потребление такой
	// строки не наполняется никогда.
	//
	// Пустым не бывает: вид вне каталога до этой структуры не доходит.
	Carrier       LimitCarrier
	SourceScope   LimitScope
	SourceScopeID string
}

// ResolveEffective folds the limits stated across the three scopes into one row
// per kind of the requested service.
//
// `stated` may contain rows of any scope in any order; only rows whose kind
// belongs to `service` participate. A kind with nothing stated at ANY scope is
// omitted from the answer — the caller must not read a missing row as "no
// ceiling": nothing was said, and inventing a ceiling here would be this
// function's guess rather than the platform's decision.
func ResolveEffective(service string, stated []Limit) []EffectiveLimit {
	winner := make(map[LimitKind]Limit, len(stated))
	for _, l := range stated {
		if l.Withdrawn() || l.Kind.Service() != service {
			continue
		}
		cur, seen := winner[l.Kind]
		if !seen || l.Scope.Specificity() > cur.Scope.Specificity() {
			winner[l.Kind] = l
		}
	}
	out := make([]EffectiveLimit, 0, len(winner))
	// Catalogue order, so two callers reading the same tenant see the same list
	// in the same order — a repeated field whose order is "whatever the map
	// yielded" is read as a fact about the tenant and is not one.
	for _, k := range CountableKindsOfService(service) {
		// Виды, считаемые В РОДИТЕЛЬСКОМ РЕСУРСЕ, отсюда НЕ вырезаются.
		//
		// Здесь недолго стоял такой фильтр, и он останавливал создание детей
		// целиком. Величину вложенного вида («сколько слушателей помещается в
		// ОДИН балансировщик») платформа назначает на корень аренды ровно так же,
		// как любую другую, — одной строкой умолчания; вырезав её, мы лишали
		// владельца типа единственного источника, из которого берётся снимок при
		// заведении родителя. Родитель заводился без строки учёта, и первый же
		// ребёнок получал `QUOTA_NOT_PROVISIONED` при потолке, названном
		// каталогом.
		//
		// Беда, ради которой фильтр вводился, была не в наличии этих видов в
		// ответе, а в том, что потребитель проставлял им носителя «проект»
		// константой и заводил строку учёта, которая не наполнится никогда
		// (списание идёт по настоящему носителю). Это закрывает поле носителя
		// ниже: оно едет вместе с величиной, и владелец типа разводит по нему две
		// полосы — учёт для корня аренды, умолчание вложенности для родителя.
		w, ok := winner[k]
		if !ok {
			continue
		}
		// Носитель берётся у КАТАЛОГА, а не у победившей строки предела: предел
		// назначается на область видимости, а считается вид всегда в одном и том
		// же носителе, каким бы образом величину ни выдали.
		carrier, known := CarrierOfKind(k)
		if !known {
			// Недостижимо: перечень выше и есть каталог этого домена. Ветка
			// оставлена, чтобы вид без носителя не уехал наружу с пустым полем,
			// которое потребитель прочитает как «проект».
			continue
		}
		out = append(out, EffectiveLimit{
			Kind:          k,
			Value:         w.Value,
			Carrier:       carrier,
			SourceScope:   w.Scope,
			SourceScopeID: w.ScopeID,
		})
	}
	return out
}
