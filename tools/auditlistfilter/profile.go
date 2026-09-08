// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package auditlistfilter states how kaname is laid out for the public-List
// gate. The analysis itself — and why it parses instead of grepping — lives in
// pkg/listfiltergate.
//
// # Why this exists
//
// It did not, until 2026-08. Every other service with a public listing surface had
// an analyser of this class; iam, which has the widest listing surface in the
// repository — 30 methods across 21 packages, more than compute, nlb, registry and
// storage combined (3+6+5+7=21) — had none. Not a weak one, not a stale one: none.
// The counts are the gate's own census re-measured on the tree this profile landed
// on; the branch this came from said 31 across 22, true until the tenant
// conditional-access surface was retired out from under it. And nothing
// was red, because the set of services to analyse was written by hand, in a CI loop
// and in whoever remembered to create a directory, and iam was in neither list.
//
// That is the shape of the defect the gates themselves are written against: a check
// is silent about what it never looked at. The remedy is not only this profile but
// pkg/listfiltergate/coverage_test.go, which derives the service list from the
// committed tree so an unanalysed service is a FINDING rather than a quiet gap.
//
// # This service's shape
//
// iam colocates transport and use-cases per resource, like vpc and nlb:
// internal/apps/kaname/api/<res> holds a `Handler` whose listing methods delegate to
// per-RPC use-cases in the same package. So the PACKAGE tells one resource from
// another, and the analyser's walk reaches the use-case.
//
// Two things differ from its neighbours and both shaped the declarations below.
//
// First, the vocabulary. iam does NOT have FilterVisibleIDs or FilterVisiblePage —
// those names exist only in compute and storage. Its per-object question to the
// model is internal/authzfilter.VisibleSet (batched) or .Visible (single), reached
// through package-local helpers with names like visibleAccountIDs and
// visibleBindingIDsOnPage. A profile copied from a neighbour would have named calls
// that do not exist here and failed every resource, which is the kind of red that
// gets a gate disabled rather than read.
//
// Second, the surface is genuinely heterogeneous — far more so than vpc's. iam lists
// its own authorization graph, its own operation histories, the members of a group,
// the keys of a service account, and the objects the authorization store itself can
// see. There is no single shape that fits, which is precisely why every method is
// declared and why all six shapes of the vocabulary appear below.
//
// # What is NOT proven here, stated so nobody reads more into a pass
//
// access_binding.ListByRole narrows per row, but not by a batched VisibleSet: it asks
// grant-authority about each row's SCOPE. Since #2054 it asks through a per-request
// memo (pageAuthority.grantAuthorityVerdict) — the super-gate once per request, the
// scope once per DISTINCT scope — because page_size reaches 1000 and the un-memoised
// form spent two store questions per row. The memo changes no verdict; it removes the
// repeat. So grantAuthorityVerdict is accepted as a filter call alongside
// requireGrantAuthority, which the single-object verbs still use.
//
// This caveat said "by evaluating requireGrantAuthority inside the loop" until
// 2026-09-06, and #2054 had made that false three weeks after it was written: the loop
// evaluates the memo, and the analyser walks calls on the RECEIVER and its fields but
// not on a local variable, so nothing along ListByRole reached any declared filter. The
// gate went red — correctly, on its own terms — while the narrowing was fully present
// and locked by four tests. A profile is a claim about the tree and expires with it.
//
// What the pass still does NOT prove, said so nobody reads more into it: the analyser
// cannot tell a call inside a per-row loop from a single call before it. For this one
// method the pass means "the per-object question is asked", not "it is asked for every
// row". The stronger statement is a test's job — TestListByRole_StrangerSeesNothing and
// TestListByRole_FilteringKeepsExactlyTheAuthorisedRows in
// services/iam/internal/apps/kaname/api/access_binding — not this gate's, and pretending
// otherwise would be exactly the form-without-substance this class is about.
//
// Likewise, the three EdgeGate methods delegate their check to the per-RPC
// authorization at the edge. The gate verifies that the delegation is real — the RPC
// carries a required_relation and a scope_extractor on the declared field, and where
// the scope is the cluster singleton, that the relation is not one a wildcard tuple
// satisfies. It does not verify that the edge is deployed, which is the boot guard's
// subject.
package auditlistfilter

import "github.com/PRO-Robotech/kacho/pkg/listfiltergate"

// subjectGate is the shape of a listing whose containing object is checked in the
// use-case before the page is read.
func subjectGate(call string) listfiltergate.Listing {
	return listfiltergate.Listing{Shape: listfiltergate.ParentGate, Gate: call}
}

// edgeGate is the shape of a listing settled by the per-RPC authorization at the
// edge; the proto file and request field are what the gate verifies against.
func edgeGate(file, field string) listfiltergate.Listing {
	return listfiltergate.Listing{
		Shape:       listfiltergate.EdgeGate,
		ProtoFile:   "kaname/cloud/iam/v1/" + file,
		ParentField: field,
	}
}

var (
	rowFilter     = listfiltergate.Listing{Shape: listfiltergate.RowFilter}
	subjectScoped = listfiltergate.Listing{Shape: listfiltergate.SubjectScoped}
)

// Profile describes kaname to the analyser.
var Profile = listfiltergate.Profile{
	Service:    "iam",
	AnchorRoot: "internal/apps/kaname/api",
	// One package per resource, all declaring the same transport type.
	PerPackage:     true,
	ReceiverSuffix: "Handler",

	// ExtraReceivers — второй транспортный тип того же ресурса. Сегодня он один:
	// `limit.PublicHandler`, административная поверхность пределов на публичном
	// слушателе (ADM-1 S1, #878).
	//
	// ПОЧЕМУ ОБЪЯВЛЕНИЕ, А НЕ ПЕРЕИМЕНОВАНИЕ. Гейт опознаёт транспорт по ТИПУ и
	// без этой строки честно сказал: «объявление публичного List не привязано ни
	// к какому ресурсу — его страница остаётся несуженной, пока гейт отчитывается
	// об исправности». Это ровно тот вид молчания, ради которого гейт и заведён,
	// поэтому закрывать его следует объявлением намерения, а не подгонкой имени
	// под предикат.
	ExtraReceivers: []string{"PublicHandler"},

	// iam's per-object question to the model. VisibleSet is the batched form every
	// page filter reaches; Visible is the single-object form. The two grant-authority
	// names are the per-row form of access_binding: requireGrantAuthority asks it once
	// for a single object, grantAuthorityVerdict asks it per row out of a per-request
	// memo (#2054). See the caveat in the package comment.
	//
	// НАЗВАНО ИМЕНЕМ ПО СУЩЕСТВУ, А НЕ ХВОСТОМ СЕЛЕКТОРА. Метод зовётся через
	// локальную переменную, поэтому анализатор записывает голое имя — и голым именем
	// `verdict` в iam уже назван другой предмет (`internal/service/authorize_service.go`
	// вычисляет им одно разрешение). Профиль, назвавший сужателем `verdict`, проверял бы
	// написание; поэтому предмет переименован, а не перечень расширен под него.
	//
	// СКОЛЬКО ЛИСТИНГОВ ДЕРЖИТ КАЖДОЕ ИМЯ — замерено, а не предположено (2026-09-06,
	// предикат: снять имя из этого перечня и прогнать гейт): VisibleSet — 9,
	// grantAuthorityVerdict — 1 (ListByRole), requireGrantAuthority — 0, Visible — 0.
	// Два последних НЕ мусор и не снимаются: это законные формы того же пообъектного
	// вопроса, у которых сегодня нет носителя. Перечень сужателей — словарь СВОЙСТВА,
	// а не ведомость послаблений: запись без носителя ничего не прощает, а её снятие
	// покраснело бы на верном коде в день, когда простую форму напишут снова. Что она
	// работоспособна, а не только объявлена, держит законный близнец инъекции
	// TestGate_RowFilterMustStillAskThePerObjectQuestion — он сужает именно ею.
	Filters: []string{"VisibleSet", "Visible", "requireGrantAuthority", "grantAuthorityVerdict"},
	// The hand-written FLOOR only. Оба имени — чужой словарь: `ListAllowedIDs`
	// не объявлен в iam нигде, а `ListObjects` был поверхностью снятого хранилища
	// отношений (стадия S6, эпик #747) и объявления тоже больше не имеет. Пол
	// держится именно ими: пол, съёживающийся вместе со снятой деривацией, полом
	// не является — имя, которое нельзя вывести, обязано быть выписано.
	Banned: []string{"ListAllowedIDs", "ListObjects"},
	// Where the ban actually comes FROM. iam asks the authorization question through
	// exactly two declared surfaces, and both are named here so their method sets
	// derive the ban instead of someone remembering to extend a list.
	//
	// The second one is why #651 exists. `ListObjects` and `ListAllowedIDs` name the
	// store's enumeration, and for a while that was the whole ban — while a THIRD
	// form sat in iam's own database: relverdict resolves verdicts a page at a time
	// over iam's own tables, cursor by object id, default page 500. The gate could
	// not see it, because a name it was never told about is a name it cannot refuse.
	// Naming the TYPE instead of the call means the next method of that type is
	// banned the day it is written.
	//
	// Being the service's own tables does not exempt the form. `security.md` refuses
	// "enumerate the universe → filter" because the answer has a ceiling and the page
	// is taken from the enumeration rather than judged after it is read; iam's tables
	// have a ceiling too, it is just written in a different file. relverdict is
	// legitimate where it is used today — the shadow comparison, which is not a
	// listing — and would be exactly the old defect inside one.
	EnumerationSources: []listfiltergate.EnumerationSource{
		{Dir: "internal/clients", Type: "RelationQueries"},
		{Dir: "internal/repo/kaname/pg/relverdict", Type: "Asker"},
	},
	// "listOp.Execute" is the delegation to shared.ListOperationsUseCase, which is
	// where the narrowing actually happens. It has to be named this way because the
	// use-case lives in a DIFFERENT package (internal/apps/kaname/shared) and the
	// analyser's walk deliberately does not leave the package it is judging.
	//
	// Naming a field is against this gate's own doctrine — identify by declared type,
	// never by a mutable label — so two things make it safe. It fails in the SAFE
	// direction: rename the field and the gate goes red, it does not go quiet. And
	// the thing being delegated TO is verified separately, by
	// shared_operations_test.go in this package, so "the shared use-case narrows by
	// the caller" is an assertion rather than an assumption. Without that test this
	// entry would just be moving the unchecked claim one package over.
	//
	// "identityOfAuthenticatedCaller" — quota reading of an identity. Unlike the
	// delegation above, this one needs no companion test: the function lives in the
	// SAME package as the method it narrows, so the analyser walks into it and sees
	// the whole of it. Its signature is the evidence — it takes ctx and nothing
	// else, so there is no request field through which a caller could name someone
	// else's identity, and the narrowing cannot be widened without changing the
	// signature the gate reads.
	SubjectScopers: []string{"ListForCaller", "listOp.Execute", "identityOfAuthenticatedCaller"},

	ProtoFiles: []string{
		"kaname/cloud/iam/v1/internal_cluster_service.proto",
		"kaname/cloud/iam/v1/membership_service.proto",
		"kaname/cloud/iam/v1/sa_key_service.proto",
		"kaname/cloud/iam/v1/user_token_service.proto",
	},
	FGAModel: "kaname/cloud/iam/v1/fga_model.fga",

	Listings: map[string]listfiltergate.Listing{
		// ---- pages narrowed per object, in the service ----
		"access_binding.List":        rowFilter,
		"access_binding.ListByScope": rowFilter,
		// ListByScope and ListByAccount ask requireGrantAuthority first and WIDEN to
		// the unfiltered page when it answers yes; when it answers no they fall
		// through to the per-row filter. So the row filter is the floor, and that is
		// what is declared.
		"access_binding.ListByAccount": rowFilter,
		"access_binding.ListByRole":    rowFilter,
		"account.List":                 rowFilter,
		"group.List":                   rowFilter,
		"project.List":                 rowFilter,
		"role.List":                    rowFilter,
		"service_account.List":         rowFilter,
		"user.List":                    rowFilter,

		// ---- operation histories, narrowed by the caller in the context ----
		"access_binding.ListOperations":  subjectScoped,
		"account.ListOperations":         subjectScoped,
		"group.ListOperations":           subjectScoped,
		"project.ListOperations":         subjectScoped,
		"role.ListOperations":            subjectScoped,
		"service_account.ListOperations": subjectScoped,
		"user.ListOperations":            subjectScoped,
		// Квоты личности: страница целиком принадлежит вызывающему, потому что
		// личность берётся из проверенного принципала, а поля, которым её можно было
		// бы назвать, в запросе НЕ СУЩЕСТВУЕТ. Пообъектный фильтр здесь утверждал бы
		// сужение, которому нечего сужать — форма проверки без содержания; сужение
		// уже сделано формой запроса, и это сильнее.
		"identityquota.List": subjectScoped,

		// ListSubjectPrivileges допускает по ДОМАШНЕМУ аккаунту субъекта, а строки
		// ответа называют области выдач — в том числе в чужих аккаунтах. Допуск
		// поэтому полнотой защиты не является, и объявлен здесь именно РЯДНЫЙ
		// фильтр: полоса распорядителя аккаунта проходит пообъектный вопрос, полосы
		// собственного чтения и надзора облака его не требуют (#1354).
		"access_binding.ListSubjectPrivileges": rowFilter,

		// ListBySubject отвечает на ТОТ ЖЕ вопрос, что и ListSubjectPrivileges, и
		// с #1352 решает допуск ТЕМ ЖЕ предикатом. Раньше здесь стоял охраняющий
		// объект: вызывающий обязан был БЫТЬ субъектом, поэтому сужать было
		// нечего. Теперь чтение допускает и распорядителя аккаунта, чьи строки
		// называют области выдач — в том числе в чужих аккаунтах, — и полнотой
		// защиты допуск быть перестал. Объявлен РЯДНЫЙ фильтр: полоса
		// распорядителя проходит пообъектный вопрос, полосы собственного чтения и
		// надзора облака его не требуют.
		"access_binding.ListBySubject": rowFilter,

		// ---- one containing object, checked before the page is read ----
		"access_binding.ListAssignableRoles": subjectGate("requireGrantAuthority"),
		// ListAllOperations and ListIamOperations both gate first and then call the
		// UNSCOPED operations repo — the one carrying an explicit IDOR warning — so
		// the gate preceding the read is the whole of their protection, and a
		// declaration that stopped verifying it would be worth nothing.
		"account.ListAllOperations":             subjectGate("requireAccountViewAuthority"),
		"internal_operations.ListIamOperations": subjectGate("requireClusterSystemAdmin"),
		"group.ListMembers":                     subjectGate("AllowsVerb"),
		"session_revocations.ListByUser":        subjectGate("authorizeListByUser"),

		// ---- the store's answer IS the response ----
		//
		// This RPC EXPOSES the enumeration itself: ListSubjects answers "who may act
		// on this resource". The enumerate-then-narrow ban is about narrowing YOUR OWN
		// page by asking for an enumeration; here the enumeration is what the caller
		// came for, so the ban is inapplicable by construction, not waived. What
		// protects it is the gate on the resource the caller named.
		//
		// ListSubjects was declared ParentGate until #651, and that was an
		// under-declaration nothing could reveal: the ban held two names, neither of
		// them `ListSubjects`, so the wrong shape cost nothing and stayed.
		//
		// Второй записи здесь больше нет: перечисление ОБЪЕКТОВ снято с контракта
		// стадией S6 (эпик #747). Объявление, пережившее свой RPC, делает вид, что
		// профиль покрывает поверхность, которой нет.
		"authorize.ListSubjects": {Shape: listfiltergate.StoreQuery, Gate: "authorizeCaller"},

		// ---- settled by the per-RPC authorization at the edge ----
		//
		// ListAdmins scopes from "*" — the cluster singleton — which narrows only
		// because it is gated on system_admin, a relation the model does NOT open to
		// a wildcard subject. Had it been gated on cluster#viewer, which IS opened to
		// `user:*` so every tenant can read the global catalog, the check would mean
		// "authenticated" and narrow nothing. The gate reads the model and tells the
		// two apart rather than assuming either.
		"cluster.ListAdmins": edgeGate("internal_cluster_service.proto", "*"),
		// conditions.List stood here and is GONE with its subject: the tenant-facing
		// conditional-access surface was retired — proto, api/conditions package and
		// repo all removed — so this declaration has nothing left to describe. The
		// gate would say so itself (a declaration with no method is a finding, and
		// an unreadable ProtoFile is another), but leaving it to be discovered at
		// the first run would mean shipping a stated claim of protection over a
		// surface that does not exist.
		// sa_keys.List and user_tokens.List narrow their SQL by an id taken from the
		// REQUEST BODY, so nothing in the service checks the caller against it. What
		// does is the per-RPC scope extractor on that same field, which is why the
		// declaration names the field and the gate verifies it in the proto.
		"sa_keys.List":     edgeGate("sa_key_service.proto", "service_account_id"),
		"user_tokens.List": edgeGate("user_token_service.proto", "user_id"),
		// membership.List сужает свой SQL аккаунтом из ПУТИ, и никакая проверка
		// внутри сервиса вызывающего против этого аккаунта не сверяет — это
		// решение, а не пропуск: у запроса есть ОДИН объект, про который можно
		// задать ОДИН вопрос, и задаёт его край. Пообъектный фильтр здесь
		// утверждал бы сужение, которому нечего сужать: строки уже отобраны тем
		// же аккаунтом, а право на него проверено ДО вызова.
		//
		// Поэтому объявление называет ПОЛЕ, и гейт сверяет по контракту, что
		// на нём действительно стоят `required_relation` и `scope_extractor`.
		// Отношение — `viewer` @ `account`; подстановочным кортежем оно НЕ
		// выполнимо (тип объявляет `[user, service_account, group#member] or
		// editor`, члена `user:*` в нём нет), поэтому оно сужает, а не означает
		// «аутентифицирован».
		"membership.List": edgeGate("membership_service.proto", "account_id"),

		// ---- reference data every authenticated caller may read ----
		"permission_catalog.ListPermissionCatalog": {
			Shape: listfiltergate.ClusterScoped,
			Reason: "the permission catalog is the platform's own static list of RPCs and the " +
				"relations they require — global reference data with no per-object grants to " +
				"narrow to, and the caller must be authenticated to reach it. The exclusion " +
				"expires with its method: retire the RPC and this entry becomes a finding.",
		},

		// ---- admin-only internal surface ----
		"limit.List": {
			Shape: listfiltergate.ClusterScoped,
			Reason: "a resource-count ceiling is a CLUSTER-level administrative record: the row " +
				"carries a scope (DEFAULT/ACCOUNT/PROJECT) but no owner to grant against, so " +
				"there is no per-object grant to narrow the page to — RowFilter here would state " +
				"a check whose subject does not exist. What bounds the caller instead is the " +
				"surface: the RPC lives ONLY on InternalLimitService, is registered ONLY on the " +
				"cluster-internal listener (ban #6), and its catalog entry demands `system_admin` " +
				"on `cluster` — a relation defined `[user, service_account]` with NO `user:*` " +
				"member, so unlike `viewer` it is not satisfiable by a wildcard tuple and does " +
				"narrow. The exclusion expires with its subject twice over: retire the RPC and " +
				"this entry becomes a finding, and give the ceiling a per-object owner and the " +
				"reason above stops being true — at which point this must become RowFilter.",
		},
		"limit.ListChangedSince": {
			Shape: listfiltergate.ClusterScoped,
			Reason: "the incremental read owner services poll to refresh their ceiling cache. Its " +
				"caller is a MACHINE, not a tenant: the catalog entry demands `quota_reader` on " +
				"`cluster`, defined `[service_account, group#member] or system_admin` — no " +
				"`user:*` member, so it is not satisfiable by a wildcard tuple. The grant is held " +
				"by a GROUP rather than by enumerated subjects, so revoking one owner service is " +
				"one membership row (data-integrity.md B18). Narrowing this page per object would " +
				"be wrong, not merely absent: an owner service polls ceilings for every scope it " +
				"enforces, and a page filtered to what the MACHINE can see would silently drop " +
				"tenants whose limits it must apply. The exclusion expires with the RPC.",
		},
		"module.List": {
			Shape: listfiltergate.ClusterScoped,
			Reason: "the module catalog is the platform's own registry of modules, their " +
				"resources and verbs — the rows the rights model itself is keyed on. It carries " +
				"no project_id, account_id or owner column, so there is no per-object grant to " +
				"narrow the page to: RowFilter here would state a check whose subject does not " +
				"exist. What bounds the caller is the surface instead: the RPC lives ONLY on " +
				"InternalModuleService, is registered ONLY on the cluster-internal listener " +
				"(ban #6, pinned by register_module_internal_only_test.go), and its catalog entry " +
				"demands `system_admin` on `cluster` — a relation defined `[user, service_account]` " +
				"with NO `user:*` member, so unlike `viewer` it is not satisfiable by a wildcard " +
				"tuple. The same relation is re-checked in the handler as its first statement " +
				"(authz_order_test.go pins that order), because the internal listener carries no " +
				"authorization interceptor of its own. Add an owner column to the catalog rows and " +
				"the reason above stops being true — at which point this must become RowFilter. " +
				"The exclusion expires with its method: retire the RPC and this entry becomes a finding.",
		},
		"interactive_client.List": {
			Shape: listfiltergate.ClusterScoped,
			Reason: "an interactive-login client is a CLUSTER-level OAuth2 client registration: " +
				"the table carries no project_id, account_id or owner column, so there is no " +
				"per-object grant to narrow the page to — RowFilter here would state a check " +
				"whose subject does not exist. What bounds the caller instead is the surface " +
				"itself: the RPC lives ONLY on InternalInteractiveClientService, is registered " +
				"ONLY on the cluster-internal listener, and its catalog entry demands " +
				"`system_admin` on `cluster` — a relation defined `[user, service_account]` with " +
				"NO `user:*` member, so unlike `viewer` it is not satisfiable by a wildcard tuple " +
				"and does narrow. The exclusion expires with its subject twice over: retire the " +
				"RPC and this entry becomes a finding, and give the resource an owner column and " +
				"the reason above stops being true — at which point this must become RowFilter.",
		},
	},
}
