// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package listvisibility_test

// surfaces_test.go — the SEVEN list surfaces of iam, described once so every
// scenario of the acceptance can be instantiated across all of them
// (§0.2, §5.0).
//
// Seven is a measured number, not a guess: it is the count of non-test files
// calling `authzfilter.VisibleSet`, minus the gate profile and the documentation
// entry. Fixing one list closes the finding and leaves the class — and the class
// returns SILENTLY, because an empty page reads as "you have nothing", not as a
// refusal. So the table below is the point of this package: a probe written once
// runs seven times.

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/clients"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho-iam/internal/testsupport/catalogfixture"

	abapp "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/access_binding"
	accountapp "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/account"
	groupapp "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/group"
	projectapp "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/project"
	roleapp "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/role"
	saapp "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/service_account"
	userapp "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/user"

	repoab "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/access_binding"
	repoaccount "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/account"
	repogroup "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/group"
	repoproject "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/project"
	reporole "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/role"
	reposa "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/service_account"
	repouser "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/user"
)

// listArgs — everything a probe may vary about one list call.
type listArgs struct {
	pageSize  int32
	pageToken string
	// queries overrides the relation-store port. Zero value means "the live
	// store"; a probe injecting an outage puts its wrapper here.
	queries clients.RelationQueries
	// store overrides the RelationStore port (the one carrying the cluster-admin
	// subject question). Only the access-binding surface consumes it today.
	store clients.RelationStore
	// unwired hands the use-case a NIL relation port — the "the deployment forgot
	// to configure the relation store" state, which is not the same thing as "the
	// store is down" and is answered differently by different surfaces today.
	unwired bool
}

// surface is one of the seven list RPCs, described by what it takes to reproduce
// the threshold on it and how to run it.
type surface struct {
	name string
	// fgaType — the object type in the authorization model; the relation tuple a
	// probe writes is `<fgaType>:<id>`.
	fgaType string
	// pageRelation — the relation that makes an object a member of a page of this
	// type (`authzfilter.RelationsFor`). Six types answer `v_get`; `iam_role`'s
	// read carries no catalog relation and its page predicate is the union with
	// `viewer`, so a probe seeding visibility there must seed a relation of that
	// union — `v_list`.
	pageRelation string

	// seedForeign creates n objects the caller must NOT see, oldest first.
	seedForeign func(t *testing.T, e *env, n int) []string
	// seedOwn creates the ONE object the caller must see, after all foreign ones,
	// and returns its id. Visibility itself is granted by the caller of the
	// helper, not here, so the same seed serves the grant path and the
	// structural paths.
	seedOwn func(t *testing.T, e *env) string
	// floorVisible — ids visible for a reason OTHER than a relation tuple: the
	// code floors named in §3.3 (the caller's own user row; the system role
	// catalog). Nil where the surface has no floor.
	floorVisible func(t *testing.T, e *env) []string

	// linkOwnToHierarchy writes the STRUCTURAL parent pointer of the object
	// seedOwn produced — the tuple production writes on Create and the one the
	// cascade of §3.1 travels: `<type>:<id>#account@account:<acc>` for the five
	// account-scoped types, `#cluster@cluster:<root>` for an account.
	//
	// Without it a cloud administrator resolves nothing by derivation, and a probe
	// about his authority would be measuring only the code short-circuit — which is
	// exactly the reading the acceptance says must be established by fixture and
	// not assumed (§3.1: "the premise the fixture must carry EXPLICITLY").
	linkOwnToHierarchy func(t *testing.T, e *env, id string)

	// list runs the production use-case and returns the ids it yields.
	list func(t *testing.T, e *env, ctx context.Context, a listArgs) ([]string, string, error)
	// get runs the production single-object read of the same type — the other
	// half of C5 ("on the page ⟺ readable by id").
	get func(t *testing.T, e *env, ctx context.Context, id string) error
}

// queriesOr returns the injected port when a probe supplied one, else the live
// store. Keeping the choice in one place means an injection probe cannot
// accidentally exercise a different wiring than the positive control beside it.
func queriesOr(e *env, a listArgs) clients.RelationQueries {
	if a.unwired {
		return nil
	}
	if a.queries != nil {
		return a.queries
	}
	return e.gates
}

// grantOwn makes `id` visible to the caller THE WAY PRODUCTION DOES — on BOTH
// sides of the grant.
//
// A grant is a ROW in iam's own database; the relation tuple is its
// MATERIALIZATION. A probe writing only the tuple describes a state the product
// never reaches, and it does so in the one direction that matters here: the
// candidate selection of a narrowed page reads the ROWS, so a grant with no row
// names no candidate.
//
// On five of the seven surfaces the object under test lives in an account the
// caller owns, so it is a candidate by that route and the missing row never
// showed. On `account` it is not — the fixture there gives the object to the
// FOREIGN user on purpose, precisely so that visibility has to come from the
// grant — and the gap becomes the whole answer. Writing both legs everywhere
// keeps the fixture describing production uniformly instead of surface by
// surface.
//
// Роль выдачи ПРОЕЦИРУЕТ ровно тот глагол, которым эта поверхность делает объект
// членом страницы (`pageRelation` без приставки). Прежде здесь стояли ДВЕ строки —
// произвольная системная роль ради самой строки выдачи и отдельный глагольный
// кортеж, называвший отношение. Второй половины больше нет: своя база глагольных
// строк не производит, отношение ВЫВОДИТСЯ из проекции роли. Поэтому «какая роль»
// перестало быть безразличным — теперь именно она и говорит, какое отношение
// вызывающий получит.
func grantOwn(t *testing.T, e *env, s surface, id string) {
	t.Helper()
	e.grantVerb(t, "user", string(e.callerUser), s.fgaType, id, verbOf(s.pageRelation))
}

// verbOf снимает приставку отношения-глагола: роль раздаёт ГЛАГОЛЫ, приставку
// знает компилятор модели. Второе место, где она пишется, разошлось бы с первым
// молча — и разошлось бы там, где расхождение читается как «права нет».
func verbOf(relation string) string {
	return strings.TrimPrefix(relation, "v_")
}

func storeOr(e *env, a listArgs) clients.RelationStore {
	if a.unwired {
		return nil
	}
	if a.store != nil {
		return a.store
	}
	return e.gates
}

func allSurfaces() []surface {
	return []surface{
		projectSurface(),
		accountSurface(),
		userSurface(),
		groupSurface(),
		serviceAccountSurface(),
		roleSurface(),
		accessBindingSurface(),
	}
}

func projectSurface() surface {
	return surface{
		name: "project", fgaType: "project", pageRelation: "v_get",
		seedForeign: func(t *testing.T, e *env, n int) []string {
			out := make([]string, 0, n)
			for i := 0; i < n; i++ {
				out = append(out, e.seedProject(t, e.foreignAcc, projectName(i)))
			}
			return out
		},
		seedOwn: func(t *testing.T, e *env) string {
			return e.seedProject(t, e.callerAcc, "prj-own")
		},
		linkOwnToHierarchy: func(t *testing.T, e *env, id string) {
			// У проекта указатель на аккаунт берётся ИЗ ЖУРНАЛА — оттуда же, откуда
			// его берёт цепь областей: его со-коммитит `Project.Create`, а миграции
			// проектов не сеют.
			e.factThroughJournal(t, "project", id, "account", "account:"+string(e.callerAcc))
		},
		list: func(t *testing.T, e *env, ctx context.Context, a listArgs) ([]string, string, error) {
			uc := projectapp.NewListProjectsUseCase(e.repo).WithRelationStore(queriesOr(e, a))
			rows, next, err := uc.Execute(ctx, repoproject.ListFilter{PageSize: a.pageSize, PageToken: a.pageToken})
			ids := make([]string, 0, len(rows))
			for _, r := range rows {
				ids = append(ids, string(r.ID))
			}
			return ids, next, err
		},
		get: func(t *testing.T, e *env, ctx context.Context, id string) error {
			uc := projectapp.NewGetProjectUseCase(e.repo).WithRelationStore(e.gates)
			_, err := uc.Execute(ctx, domain.ProjectID(id))
			return err
		},
	}
}

func accountSurface() surface {
	return surface{
		name: "account", fgaType: "account", pageRelation: "v_get",
		seedForeign: func(t *testing.T, e *env, n int) []string {
			// КАЖДЫЙ ЗАПОЛНИТЕЛЬ — СВОЕЙ ЛИЧНОСТИ, и это не косметика.
			//
			// Число аккаунтов на одну личность ограничено потолком продукта (5),
			// поэтому прежняя редакция, сеявшая всех заполнителей одному
			// `foreignUser`, упиралась в него на шестом: фикстура требовала от
			// платформы того, чего платформа не позволяет, — то есть была
			// СНИСХОДИТЕЛЬНЕЕ продукта в одну сторону и невыполнима в другую.
			//
			// Предмет пробы от этого не меняется: заполнителям важно лишь занять
			// страницу впереди своего объекта. Владение своим объектом остаётся за
			// `foreignUser` ровно потому, что видимость обязана приходить от гранта,
			// а не от владения (см. seedOwn ниже).
			out := make([]string, 0, n)
			for i := 0; i < n; i++ {
				owner, _ := e.seedUserWithAccount(t, fmt.Sprintf("fgn%d", i))
				out = append(out, e.seedAccount(t, owner, "fgn"))
			}
			return out
		},
		seedOwn: func(t *testing.T, e *env) string {
			// Owned by the FOREIGN user on purpose: visibility must come from the
			// grant under test, not from ownership, or the probe would pass on a
			// build where the grant path is broken.
			return e.seedAccount(t, e.foreignUser, "own")
		},
		linkOwnToHierarchy: func(t *testing.T, e *env, id string) {
			// Предок АККАУНТА — кластер, и он выводится из схемы (accounts ×
			// clusters): аккаунты сеются в том числе миграциями, указателя в
			// журнале у них нет. Писать его здесь значило бы завести второй
			// источник одного звена.
			_ = id
		},
		list: func(t *testing.T, e *env, ctx context.Context, a listArgs) ([]string, string, error) {
			uc := accountapp.NewListAccountsUseCase(e.repo).WithRelationStore(queriesOr(e, a))
			rows, next, err := uc.Execute(ctx, repoaccount.ListFilter{PageSize: a.pageSize, PageToken: a.pageToken})
			ids := make([]string, 0, len(rows))
			for _, r := range rows {
				ids = append(ids, string(r.ID))
			}
			return ids, next, err
		},
		get: func(t *testing.T, e *env, ctx context.Context, id string) error {
			uc := accountapp.NewGetAccountUseCase(e.repo).WithRelationStore(e.gates)
			_, err := uc.Execute(ctx, domain.AccountID(id))
			return err
		},
	}
}

func userSurface() surface {
	return surface{
		name: "user", fgaType: "iam_user", pageRelation: "v_get",
		seedForeign: func(t *testing.T, e *env, n int) []string {
			out := make([]string, 0, n)
			for i := 0; i < n; i++ {
				out = append(out, e.seedUser(t, e.foreignAcc, "fgn"))
			}
			return out
		},
		seedOwn: func(t *testing.T, e *env) string {
			return e.seedUser(t, e.callerAcc, "own")
		},
		linkOwnToHierarchy: func(t *testing.T, e *env, id string) {
			// Собственные типы iam звена НЕ пишут: цепь областей выводит его из
			// КОЛОНКИ ИХ ЖЕ СТРОКИ — `account_id` у пользователя, группы, учётки и
			// роли аккаунта, `project_id` у роли проекта, пара
			// `resource_type`/`resource_id` у привязки. Строка И ЕСТЬ объект,
			// колонка неизменяема, а журнал по этим типам наблюдаемо неполон
			// (миграции сеют такие строки и указателя не пишут). Второй источник
			// одного звена здесь был бы двумя местами об одном предмете.
			_ = id
		},
		// The caller's own row is visible without any tuple — a code floor keyed
		// on the caller's id (§3.3). It is not the object under test, but it IS
		// part of the answer, so the expected set has to name it.
		floorVisible: func(t *testing.T, e *env) []string {
			return []string{string(e.callerUser)}
		},
		list: func(t *testing.T, e *env, ctx context.Context, a listArgs) ([]string, string, error) {
			uc := userapp.NewListUsersUseCase(e.repo).WithRelationStore(queriesOr(e, a))
			rows, next, err := uc.Execute(ctx, repouser.ListFilter{PageSize: a.pageSize, PageToken: a.pageToken})
			ids := make([]string, 0, len(rows))
			for _, r := range rows {
				ids = append(ids, string(r.ID))
			}
			return ids, next, err
		},
		get: func(t *testing.T, e *env, ctx context.Context, id string) error {
			uc := userapp.NewGetUserUseCase(e.repo).WithRelationStore(e.gates)
			_, err := uc.Execute(ctx, domain.UserID(id))
			return err
		},
	}
}

func groupSurface() surface {
	return surface{
		name: "group", fgaType: "iam_group", pageRelation: "v_get",
		seedForeign: func(t *testing.T, e *env, n int) []string {
			out := make([]string, 0, n)
			for i := 0; i < n; i++ {
				out = append(out, e.seedGroup(t, e.foreignAcc, groupName(i)))
			}
			return out
		},
		seedOwn: func(t *testing.T, e *env) string {
			return e.seedGroup(t, e.callerAcc, "grp-own")
		},
		linkOwnToHierarchy: func(t *testing.T, e *env, id string) {
			// Собственные типы iam звена НЕ пишут: цепь областей выводит его из
			// КОЛОНКИ ИХ ЖЕ СТРОКИ — `account_id` у пользователя, группы, учётки и
			// роли аккаунта, `project_id` у роли проекта, пара
			// `resource_type`/`resource_id` у привязки. Строка И ЕСТЬ объект,
			// колонка неизменяема, а журнал по этим типам наблюдаемо неполон
			// (миграции сеют такие строки и указателя не пишут). Второй источник
			// одного звена здесь был бы двумя местами об одном предмете.
			_ = id
		},
		list: func(t *testing.T, e *env, ctx context.Context, a listArgs) ([]string, string, error) {
			uc := groupapp.NewListGroupsUseCase(e.repo).WithRelationStore(queriesOr(e, a))
			rows, next, err := uc.Execute(ctx, repogroup.ListFilter{PageSize: a.pageSize, PageToken: a.pageToken})
			ids := make([]string, 0, len(rows))
			for _, r := range rows {
				ids = append(ids, string(r.ID))
			}
			return ids, next, err
		},
		get: func(t *testing.T, e *env, ctx context.Context, id string) error {
			uc := groupapp.NewGetGroupUseCase(e.repo).WithRelationStore(e.gates)
			_, err := uc.Execute(ctx, domain.GroupID(id))
			return err
		},
	}
}

func serviceAccountSurface() surface {
	return surface{
		name: "service_account", fgaType: "iam_service_account", pageRelation: "v_get",
		seedForeign: func(t *testing.T, e *env, n int) []string {
			out := make([]string, 0, n)
			for i := 0; i < n; i++ {
				out = append(out, e.seedServiceAccount(t, e.foreignAcc, svcAccountName(i)))
			}
			return out
		},
		seedOwn: func(t *testing.T, e *env) string {
			return e.seedServiceAccount(t, e.callerAcc, "sva-own")
		},
		linkOwnToHierarchy: func(t *testing.T, e *env, id string) {
			// Собственные типы iam звена НЕ пишут: цепь областей выводит его из
			// КОЛОНКИ ИХ ЖЕ СТРОКИ — `account_id` у пользователя, группы, учётки и
			// роли аккаунта, `project_id` у роли проекта, пара
			// `resource_type`/`resource_id` у привязки. Строка И ЕСТЬ объект,
			// колонка неизменяема, а журнал по этим типам наблюдаемо неполон
			// (миграции сеют такие строки и указателя не пишут). Второй источник
			// одного звена здесь был бы двумя местами об одном предмете.
			_ = id
		},
		list: func(t *testing.T, e *env, ctx context.Context, a listArgs) ([]string, string, error) {
			uc := saapp.NewListServiceAccountsUseCase(e.repo).WithRelationStore(queriesOr(e, a))
			rows, next, err := uc.Execute(ctx, reposa.ListFilter{PageSize: a.pageSize, PageToken: a.pageToken})
			ids := make([]string, 0, len(rows))
			for _, r := range rows {
				ids = append(ids, string(r.ID))
			}
			return ids, next, err
		},
		get: func(t *testing.T, e *env, ctx context.Context, id string) error {
			uc := saapp.NewGetServiceAccountUseCase(e.repo).WithRelationStore(e.gates)
			_, err := uc.Execute(ctx, domain.ServiceAccountID(id))
			return err
		},
	}
}

func roleSurface() surface {
	return surface{
		// `iam_role` is the one type whose page predicate is a UNION (`viewer ∪
		// v_list`) rather than `v_get`: its single-object read carries no catalog
		// relation. A probe seeding `v_get` here would seed a relation nothing
		// reads, and would then report the product broken.
		name: "role", fgaType: "iam_role", pageRelation: "v_list",
		seedForeign: func(t *testing.T, e *env, n int) []string {
			out := make([]string, 0, n)
			for i := 0; i < n; i++ {
				out = append(out, e.seedCustomRole(t, e.foreignAcc, roleName(i)))
			}
			return out
		},
		seedOwn: func(t *testing.T, e *env) string {
			return e.seedCustomRole(t, e.callerAcc, "rol_own")
		},
		linkOwnToHierarchy: func(t *testing.T, e *env, id string) {
			// Собственные типы iam звена НЕ пишут: цепь областей выводит его из
			// КОЛОНКИ ИХ ЖЕ СТРОКИ — `account_id` у пользователя, группы, учётки и
			// роли аккаунта, `project_id` у роли проекта, пара
			// `resource_type`/`resource_id` у привязки. Строка И ЕСТЬ объект,
			// колонка неизменяема, а журнал по этим типам наблюдаемо неполон
			// (миграции сеют такие строки и указателя не пишут). Второй источник
			// одного звена здесь был бы двумя местами об одном предмете.
			_ = id
		},
		// The system catalog is a floor: `is_system` bypasses the filter entirely,
		// so those rows belong in the answer for every caller.
		floorVisible: func(t *testing.T, e *env) []string { return e.systemRoleIDs(t) },
		list: func(t *testing.T, e *env, ctx context.Context, a listArgs) ([]string, string, error) {
			uc := roleapp.NewListRolesUseCase(e.repo, catalogfixture.Source()).WithRelationStore(queriesOr(e, a))
			rows, next, err := uc.Execute(ctx, reporole.ListFilter{PageSize: a.pageSize, PageToken: a.pageToken})
			ids := make([]string, 0, len(rows))
			for _, r := range rows {
				ids = append(ids, string(r.ID))
			}
			return ids, next, err
		},
		get: func(t *testing.T, e *env, ctx context.Context, id string) error {
			uc := roleapp.NewGetRoleUseCase(e.repo, catalogfixture.Source()).WithRelationStore(e.gates)
			_, err := uc.Execute(ctx, domain.RoleID(id))
			return err
		},
	}
}

func accessBindingSurface() surface {
	return surface{
		name: "access_binding", fgaType: "iam_access_binding", pageRelation: "v_get",
		seedForeign: func(t *testing.T, e *env, n int) []string {
			role := e.anySystemRoleID(t)
			out := make([]string, 0, n)
			for i := 0; i < n; i++ {
				prj := e.seedProject(t, e.foreignAcc, projectName(1000+i))
				out = append(out, e.seedAccessBinding(t, e.foreignUser, role, "project", prj))
			}
			return out
		},
		seedOwn: func(t *testing.T, e *env) string {
			role := e.anySystemRoleID(t)
			prj := e.seedProject(t, e.callerAcc, "prj-acb-own")
			return e.seedAccessBinding(t, e.callerUser, role, "project", prj)
		},
		linkOwnToHierarchy: func(t *testing.T, e *env, id string) {
			// A binding carries exactly ONE parent pointer, named after its own
			// scope. This fixture's binding is account-scoped in the hierarchy sense
			// (its project lives in the caller's account), so the pointer is
			// `account`.
			// Собственные типы iam звена НЕ пишут: цепь областей выводит его из
			// КОЛОНКИ ИХ ЖЕ СТРОКИ — `account_id` у пользователя, группы, учётки и
			// роли аккаунта, `project_id` у роли проекта, пара
			// `resource_type`/`resource_id` у привязки. Строка И ЕСТЬ объект,
			// колонка неизменяема, а журнал по этим типам наблюдаемо неполон
			// (миграции сеют такие строки и указателя не пишут). Второй источник
			// одного звена здесь был бы двумя местами об одном предмете.
			_ = id
		},
		list: func(t *testing.T, e *env, ctx context.Context, a listArgs) ([]string, string, error) {
			uc := abapp.NewListUseCase(e.repo).
				WithRelationQueries(queriesOr(e, a)).
				WithRelationStore(storeOr(e, a))
			page, err := uc.Execute(ctx, repoab.ListFilter{PageSize: a.pageSize, PageToken: a.pageToken})
			ids := make([]string, 0, len(page.Bindings))
			for _, r := range page.Bindings {
				ids = append(ids, string(r.ID))
			}
			return ids, page.NextPageToken, err
		},
		get: func(t *testing.T, e *env, ctx context.Context, id string) error {
			uc := abapp.NewGetAccessBindingUseCase(e.repo).WithRelationQueries(e.gates)
			_, err := uc.Execute(ctx, domain.AccessBindingID(id))
			return err
		},
	}
}
