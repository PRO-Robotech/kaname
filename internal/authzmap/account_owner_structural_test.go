// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzmap_test

// account_owner_structural_test.go — исход и структура уточнения «Владелец —
// СТРУКТУРНЫЙ источник прав на СВОЁМ аккаунте» (.claude/rules/security.md,
// 2026-07-27).
//
// Аккаунт — собственная область пользователя, и заводится он самообслуживанием:
// свежеаутентифицированный человек создаёт свой аккаунт сам. Значит удаление
// обязано быть таким же надёжным, как создание, — а оно таким не было. Право
// удаления приезжало ПРИВЯЗКОЙ роли владельца, материализуемой на объект
// реконсайлером; пока конвейер не догнал, только что созданный аккаунт нельзя
// было удалить единственному человеку, которому он принадлежит. У администратора
// облака право при этом каскадное и работает всегда — асимметрия без основания:
// и то и другое суть «власть, которая не вправе зависеть от очереди».
//
// Модель показывала пробел и с другой стороны: `account.admin` выводится
// `or owner`, то есть владелец И ЕСТЬ администратор аккаунта, — тогда как глаголы
// уровня администратора не читали вовсе (`v_delete: […] or super_admin`). Быть
// администратором собственного аккаунта не давало ничего.
//
// ПОЧЕМУ `owner` НАПРЯМУЮ, А НЕ «пусть глаголы читают уровень администратора».
// Провести глаголы через `admin` было бы более широкой правкой и она неверна:
// `account.admin` принимает и ПРЯМЫХ субъектов (`[user, service_account,
// group#member]`), то есть ДЕЛЕГИРОВАННОГО администратора аккаунта. Он тогда
// сносил бы сам объект аккаунта, что записанная картина запрещает дословно —
// «администратор аккаунта — каскадом внутрь аккаунта, но не на сам аккаунт
// (делегированный управляющий не сносит тенантность — это остаётся за владельцем
// и облаком)». TestAccountOwner_VerbsReadOwnerNotTheAdminTier держит это
// структурно: позднейшее `or admin` в тех строках прошло бы каждую разрешающую
// проверку ниже и тихо вручило бы делегированному управляющему сам аккаунт.
//
// ГДЕ БЕРЁТСЯ ИСХОД. Прежде поведенческая половина грузила заготовку модели из
// карты чарта в поднятый контейнером движок отношений. Ни движка, ни карты, ни
// подчарта в дереве нет; исход теперь считает форма вердикта поверх собственной
// базы iam, а вывод отношений она берёт из той же канонической модели, которую
// разбирает структурная половина этого файла. Утверждения не сужены: план
// `account.v_*`, скомпилированный из модели, даёт ровно прямой факт, `owner` на
// самом объекте и `system_admin` на кластере — и НЕ даёт `admin`.

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/authzmap"
)

const (
	aoAccA = "acc-aoownera"
	aoAccB = "acc-aoownerb"
	aoPrjA = "prj-aoownera"
	aoAbnA = "abn-aoownera"

	aoOwnerA    = "user:usr-aoownera"   // создал аккаунт A, держит account:A#owner
	aoOwnerB    = "user:usr-aoownerb"   // создал аккаунт B — соседний арендатор
	aoDelegAdmA = "user:usr-aodelegadm" // ДЕЛЕГИРОВАННЫЙ администратор A (не владелец)
	aoStranger  = "user:usr-aostranger" // ни одной строки нигде
)

var (
	aoAccAObj = saObject{"account", aoAccA}
	aoAccBObj = saObject{"account", aoAccB}
	aoPrjAObj = saObject{"project", aoPrjA}
	aoAbnAObj = saObject{"iam_access_binding", aoAbnA}
)

// aoVerbs — глагольные отношения, которые объявляет тип `account`, прочитанные
// из той же по-типовой таблицы, которой пользуется эмиттер. Литерал не может
// следовать за своим предметом: здесь стоял `v_create`, которого тип `account`
// больше не объявляет (создание аккаунта — не операция НАД аккаунтом), и каждое
// утверждение ниже продолжало бы требовать отношение, снятое с модели.
var aoVerbs = authzmap.VerbRelationsOfType("account")

// aoSeedFreshAccount кладёт РОВНО то, что со-коммитит `Account.Create` в своей
// транзакции (apps/kacho/api/account/create.go::ownerTuples), и НИЧЕГО больше:
//
//	user:<owner> #owner @ account:<A>  — самовыдача владельца.
//
// Указатель аккаунта на кластер здесь НЕ пишется: цепь областей выводит его из
// схемы (accounts × clusters). Ни одной глагольной строки на аккаунте, ни
// привязки роли владельца — это выход реконсайлера, и весь смысл в том, что
// владелец не обязан его ждать.
func aoSeedFreshAccount(t *testing.T, ctx context.Context, tx pgx.Tx, account, owner string) {
	t.Helper()
	ownerID := strings.TrimPrefix(owner, "user:")
	saExec(t, ctx, tx,
		`INSERT INTO kacho_iam.accounts (id, name, owner_user_id) VALUES ($1, $2, $3)`,
		account, "account-"+account, ownerID)
	saUser(t, ctx, tx, ownerID, account)
	saPointer(t, ctx, tx, "account", account, "owner", owner)
}

// TestAccountOwner_DeletesFreshAccountBeforeAnyMaterialization — сама правка на
// наблюдаемом уровне: владелец создаёт аккаунт и удаляет его НЕМЕДЛЕННО, при
// том что конвейер материализации не произвёл ещё ничего. До уточнения это
// отказ (глаголы аккаунта читали лишь прямые множества и кластерный уровень),
// после — разрешение by construction.
func TestAccountOwner_DeletesFreshAccountBeforeAnyMaterialization(t *testing.T) {
	withIAMTx(t, func(ctx context.Context, tx pgx.Tx) {
		aoSeedFreshAccount(t, ctx, tx, aoAccA, aoOwnerA)

		require.Truef(t, saAllows(t, ctx, tx, aoOwnerA, "v_delete", aoAccAObj),
			"владелец ТОЛЬКО ЧТО созданного аккаунта обязан суметь удалить его при НУЛЕВОЙ "+
				"материализации — аккаунт заводится самообслуживанием, поэтому его снос не "+
				"вправе зависеть от того, дренировал ли реконсайлер привязку владельца")

		for _, v := range aoVerbs {
			require.Truef(t, saAllows(t, ctx, tx, aoOwnerA, v, aoAccAObj),
				"владелец обязан разрешать %s на своём объекте аккаунта без материализации", v)
		}

		// Уровни, на которые гейтит каталог прав, уже выводились из `owner`
		// (`define admin: … or owner`) — закреплено, чтобы уточнение не читалось
		// как их замена.
		for _, rel := range saTiers {
			require.Truef(t, saAllows(t, ctx, tx, aoOwnerA, rel, aoAccAObj),
				"владелец обязан по-прежнему разрешать уровень %s на своём аккаунте", rel)
		}
	})
}

// TestAccountOwner_ScopeIsExactlyHisOwnAccount — половина, которая важнее самой
// правки: всё, чего уточнение раздавать НЕ ДОЛЖНО. Делегированный администратор
// аккаунта управляет тем, что ВНУТРИ, и не сносит сам аккаунт; владелец
// соседнего арендатора не достаёт сюда ничего; субъект без единой строки не
// достаёт нигде ничего.
func TestAccountOwner_ScopeIsExactlyHisOwnAccount(t *testing.T) {
	withIAMTx(t, func(ctx context.Context, tx pgx.Tx) {
		aoSeedFreshAccount(t, ctx, tx, aoAccA, aoOwnerA)
		aoSeedFreshAccount(t, ctx, tx, aoAccB, aoOwnerB)

		// Содержимое аккаунта A. Проект указывает на аккаунт через журнал, как
		// его туда кладёт создание проекта; привязка — своей парой колонок.
		saExec(t, ctx, tx,
			`INSERT INTO kacho_iam.projects (id, account_id, name) VALUES ($1, $2, 'project-a')`,
			aoPrjA, aoAccA)
		saPointer(t, ctx, tx, "project", aoPrjA, "account", "account:"+aoAccA)
		saExec(t, ctx, tx,
			`INSERT INTO kacho_iam.roles (id, account_id, name, permissions)
			 VALUES ('rol-aoinert', $1, 'inert', '["iam.project.*.get"]'::jsonb)`, aoAccA)
		saExec(t, ctx, tx,
			`INSERT INTO kacho_iam.access_bindings
			   (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
			 VALUES ($1, 'user', $2, 'rol-aoinert', 'project', $3, 'ACTIVE')`,
			aoAbnA, strings.TrimPrefix(aoOwnerA, "user:"), aoPrjA)
		saExec(t, ctx, tx,
			`INSERT INTO kacho_iam.access_binding_subjects (binding_id, subject_type, subject_id)
			 VALUES ($1, 'user', $2)`, aoAbnA, strings.TrimPrefix(aoOwnerA, "user:"))

		// ДЕЛЕГИРОВАННЫЙ администратор аккаунта: прямое отношение `admin`, без владения.
		saUser(t, ctx, tx, strings.TrimPrefix(aoDelegAdmA, "user:"), aoAccA)
		saPointer(t, ctx, tx, "account", aoAccA, "admin", aoDelegAdmA)

		// (1) Он НЕ достаёт сам ОБЪЕКТ аккаунта — тенантность не его, чтобы её
		//     сносить. Ровно это сломала бы проводка глаголов через уровень `admin`.
		for _, v := range aoVerbs {
			require.Falsef(t, saAllows(t, ctx, tx, aoDelegAdmA, v, aoAccAObj),
				"ДЕЛЕГИРОВАННЫЙ администратор аккаунта не вправе разрешать %s на самом объекте "+
					"аккаунта — его власть идёт ВНУТРИ аккаунта, аккаунт есть её граница", v)
		}

		// (2) …тогда как его каскад ВНУТРЬ не тронут (правка трёх уровней стоит).
		for _, v := range saVerbsOf(t, aoPrjAObj) {
			require.Truef(t, saAllows(t, ctx, tx, aoDelegAdmA, v, aoPrjAObj),
				"делегированный администратор аккаунта обязан по-прежнему разрешать %s внутри "+
					"своего аккаунта (проект) — уточнение не вправе сузить каскад уровня 3", v)
		}
		for _, v := range saVerbsOf(t, aoAbnAObj) {
			require.Truef(t, saAllows(t, ctx, tx, aoDelegAdmA, v, aoAbnAObj),
				"делегированный администратор аккаунта обязан по-прежнему разрешать %s на "+
					"выдаче внутри своего аккаунта", v)
		}

		// (3) Владелец ДРУГОГО аккаунта здесь обычный посторонний — `owner`
		//     пообъектное отношение, между аккаунтами оно не путешествует.
		for _, v := range aoVerbs {
			require.Falsef(t, saAllows(t, ctx, tx, aoOwnerB, v, aoAccAObj),
				"владелец аккаунта B не вправе разрешать %s на аккаунте A", v)
			require.Falsef(t, saAllows(t, ctx, tx, aoOwnerA, v, aoAccBObj),
				"владелец аккаунта A не вправе разрешать %s на аккаунте B", v)
		}
		for _, v := range saVerbsOf(t, aoPrjAObj) {
			require.Falsef(t, saAllows(t, ctx, tx, aoOwnerB, v, aoPrjAObj),
				"владелец аккаунта B не вправе разрешать %s внутри аккаунта A", v)
		}
		for _, rel := range saTiers {
			require.Falsef(t, saAllows(t, ctx, tx, aoOwnerB, rel, aoAccAObj),
				"владелец аккаунта B не вправе разрешать уровень %s на аккаунте A", rel)
		}

		// (4) Обычный арендатор без единой строки не достаёт ничего.
		for _, o := range []saObject{aoAccAObj, aoPrjAObj, aoAbnAObj} {
			for _, v := range saVerbsOf(t, o) {
				require.Falsef(t, saAllows(t, ctx, tx, aoStranger, v, o),
					"субъект без единой строки не вправе разрешать %s на %s:%s", v, o.Type, o.ID)
			}
		}

		// (5) Владение остаётся фактом личности: уточнение делает `owner`
		//     ИСТОЧНИКОМ глаголов и не вправе делать кого-либо владельцем.
		require.False(t, saAllows(t, ctx, tx, aoDelegAdmA, "owner", aoAccAObj),
			"делегированный администратор аккаунта не становится владельцем")
	})
}

// TestAccountOwner_VerbsReadOwnerNotTheAdminTier — структурная половина,
// прочитанная с канонической модели: осознанный выбор между двумя возможными
// правками, сделанный неудобным для случайного отката.
//
// Каждый глагол на `account` обязан выводиться из `owner` (в этом уточнение), а
// его дизъюнкты обязаны быть ровно {owner, super_admin} — никогда `admin`.
// `or admin` там оставил бы каждую разрешающую проверку выше зелёной и тихо
// выдал бы ДЕЛЕГИРОВАННОМУ администратору сам объект аккаунта, противореча
// «администратор аккаунта — … не на сам аккаунт».
func TestAccountOwner_VerbsReadOwnerNotTheAdminTier(t *testing.T) {
	body := typeBody(t, modelDSL(t), "account")

	for _, v := range aoVerbs {
		re := regexp.MustCompile(`(?m)^\s*define ` + v + `:\s*(.*)$`)
		m := re.FindStringSubmatch(body)
		require.Lenf(t, m, 2, "account must define %s. body:\n%s", v, body)

		disjuncts := strings.Split(m[1], " or ")
		require.Greaterf(t, len(disjuncts), 1, "account.%s has no derivation at all: %q", v, m[1])

		require.Truef(t, strings.HasPrefix(strings.TrimSpace(disjuncts[0]), "["),
			"account.%s must keep its DIRECT userset (materialized tenant grants stay flat): %q", v, m[1])

		derived := map[string]bool{}
		for _, d := range disjuncts[1:] {
			derived[strings.TrimSpace(d)] = true
		}
		require.Truef(t, derived["owner"],
			"account.%s must derive from `owner` — the account is created by self-service and "+
				"tearing it down must not wait for the reconciler. rhs: %q", v, m[1])
		require.Truef(t, derived["super_admin"],
			"account.%s must keep `super_admin` (levels 1-2 reach every account). rhs: %q", v, m[1])
		require.Lenf(t, derived, 2,
			"account.%s must derive from `owner` and `super_admin` and NOTHING else — in "+
				"particular not from `admin`, which accepts DIRECT subjects and would hand the "+
				"DELEGATED account administrator the account object itself. rhs: %q", v, m[1])
	}
}

// TestAccountOwner_RefinementIsConfinedToTheAccountType — уточнение касается
// объекта аккаунта и только его. `project` (и всё ниже) остаётся плоским: его
// глаголы вправе выводиться из `super_admin` и ни из чего больше, поэтому ни
// собственный уровень, ни понятие владения не могут просочиться туда по одному
// типу за раз.
func TestAccountOwner_RefinementIsConfinedToTheAccountType(t *testing.T) {
	body := typeBody(t, modelDSL(t), "project")

	for _, v := range aoVerbs {
		re := regexp.MustCompile(`(?m)^\s*define ` + v + `:\s*(.*)$`)
		m := re.FindStringSubmatch(body)
		require.Lenf(t, m, 2, "project must define %s. body:\n%s", v, body)

		disjuncts := strings.Split(m[1], " or ")
		derived := map[string]bool{}
		for _, d := range disjuncts[1:] {
			derived[strings.TrimSpace(d)] = true
		}
		require.Equalf(t, map[string]bool{"super_admin": true}, derived,
			"project.%s must derive from `super_admin` alone — project scope and below stay "+
				"flat, access is materialized per object (anti-over-grant, data-integrity.md). "+
				"rhs: %q", v, m[1])
	}
}
