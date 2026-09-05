// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzmap_test

// super_admin_cascade_test.go — исход директивы владельца «Три уровня
// супер-доступа — КАСКАДОМ, ниже — плоско по выдаче» (.claude/rules/security.md).
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЗДЕСЬ ПРОВЕРЯЕТСЯ
//
// Модель — плоский индекс: доступ арендатора материализуется выдачей на объект.
// Для арендных ролей это так и остаётся. Для трёх верхних уровней — намеренно
// НЕТ, потому что материализация ломает ровно тот сценарий, ради которого они
// существуют: при отставшем или сломанном конвейере человек, обязанный всё
// починить, сам оказывается без прав. Эти три разрешаются в момент вопроса:
//
//  1. администратор облака — cluster:cluster_kacho_root#system_admin, достаёт до всего;
//  2. учётка первичной установки — то же отношение (её сеет старт), то есть тот
//     же источник; отдельного носителя нет;
//  3. администратор аккаунта — account:<id>#admin, достаёт ВНУТРЬ своего аккаунта.
//
// Инцидент, который здесь заперт (2026-07-26): каждый глагол на
// iam_access_binding был прямым множеством без единого `or`, поэтому
// администратор кластера видел все выдачи, а снять мог только свои — 652 отказа
// против 32 успехов за прогон. По-человечески: сотрудник выдал коллеге доступ и
// уволился, отозвать некому.
//
// ─────────────────────────────────────────────────────────────────────────────
// ГДЕ БЕРЁТСЯ ИСХОД (изменилось при снятии внешнего движка отношений)
//
// Прежде эти пробы поднимали движок контейнером, грузили в него заготовку модели
// из карты чарта и спрашивали его. Ни движка, ни карты, ни подчарта в дереве
// нет. Исход теперь считает форма вердикта поверх СОБСТВЕННОЙ базы iam
// (`internal/repo/kacho/pg/relverdict`), а вывод отношений она берёт из той же
// модели, что разбирают структурные пробы этого пакета.
//
// Утверждения при этом НЕ ослаблены. План вывода, скомпилированный из модели,
// даёт для листового глагола ровно те источники, которые директива и называет, —
// прямой факт на объекте, `admin`/`owner` на аккаунте-предке и `system_admin` на
// кластере, — и НЕ даёт собственного `admin` проекта. Поэтому каждое «достаёт» и
// каждое «не достаёт» ниже проверяется тем же вопросом, каким его задаёт продукт.
//
// Ни одна проба не кладёт глагольную строку на целевой объект: всякое разрешение
// ниже обязано прийти каскадом, всякий отказ — пережить каскад.

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg/relverdict"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"
)

// Мир каскада. Идентификаторы короткие и говорящие: в тексте отказа они и есть
// адрес.
const (
	saClusterID = "cluster_kacho_root"

	saAccA = "acc-cascadea"
	saAccB = "acc-cascadeb"
	saPrjA = "prj-cascadea"
	saPrjB = "prj-cascadeb"

	saBindingA = "abn-cascadea"
	saBindingB = "abn-cascadeb"

	saNetworkA  = "net-cascadea"
	saVolumeA   = "vol-cascadea"
	saSnapshotA = "snp-cascadea"
	saImageA    = "img-cascadea"
	saLbA       = "nlb-cascadea"
	saListenerA = "lst-cascadea"
	saRegistryA = "reg-cascadea"
	saRepoA     = "reg-cascadea/app"
	saUserA     = "usr-cascadetarget"
	saGroupA    = "grp-cascadea"

	// Владельцы СТРОК аккаунтов: колонка владельца обязательна, а субъектами
	// проб эти двое не являются.
	saOwnerRowA = "usr-cascaderowa"
	saOwnerRowB = "usr-cascaderowb"

	subjCloudAdmin  = "user:usr-cascadecloud"           // уровень 1
	subjBootstrapSA = "service_account:sva-cascadeboot" // уровень 2 — то же отношение
	subjAccAdminA   = "user:usr-cascadeaccadmin"        // уровень 3 — admin на аккаунте A
	subjAccOwnerA   = "user:usr-cascadeaccowner"        // уровень 3 — через owner
	subjProjAdminA  = "user:usr-cascadeprojadmin"       // НЕ уровень: администратор проекта
	subjStranger    = "user:usr-cascadestranger"        // ни одной строки нигде
)

// saObject — объект мира: тип модели прав и его идентификатор.
type saObject struct {
	Type string
	ID   string
}

var (
	saAccountAObj = saObject{"account", saAccA}
	saAccountBObj = saObject{"account", saAccB}
	saProjectAObj = saObject{"project", saPrjA}
	saProjectBObj = saObject{"project", saPrjB}
	saBindingAObj = saObject{"iam_access_binding", saBindingA}
	saBindingBObj = saObject{"iam_access_binding", saBindingB}
	saNetworkAObj = saObject{"vpc_network", saNetworkA}
	saVolumeAObj  = saObject{"storage_volume", saVolumeA}
	saSnapshotObj = saObject{"storage_snapshot", saSnapshotA}
	saImageObj    = saObject{"storage_image", saImageA}
	saLbAObj      = saObject{"nlb_network_load_balancer", saLbA}
	saListenerObj = saObject{"nlb_listener", saListenerA}
	saRegistryObj = saObject{"registry_registry", saRegistryA}
	saRepoObj     = saObject{"registry_repository", saRepoA}
	saUserAObj    = saObject{"iam_user", saUserA}
	saGroupAObj   = saObject{"iam_group", saGroupA}
)

// saVerbsOf — глагольные отношения, которые объявляет ТИП ЭТОГО объекта,
// прочитанные из той же по-типовой таблицы, которой пользуется эмиттер.
//
// Здесь стоял литерал из пяти имён, введённый как «закрытый CRUD-набор, который
// объявляет каждый глаголоносный тип». Это утверждение переставало быть верным
// дважды: когда `nlb_target_group` взял два глагола членства, которых литерал не
// называл, и когда `v_create` был снят со всех типов, кроме `registry_registry`.
// Дублированный набор не может следовать за своим предметом — вывод набора и
// делает утверждение о каскаде исчерпывающим by construction.
func saVerbsOf(t *testing.T, o saObject) []string {
	t.Helper()
	verbs := authzmap.VerbRelationsOfType(o.Type)
	require.NotEmptyf(t, verbs, "тип %q не объявляет ни одного глагольного отношения — "+
		"утверждение о каскаде над ним было бы бессодержательным", o.Type)
	return verbs
}

// saTiers — уровневые отношения, на которые гейтит каталог прав. Каскад,
// покрывший только глаголы, оставил бы эти RPC отказанными.
var saTiers = []string{"viewer", "editor", "admin"}

// ── харнесс ──────────────────────────────────────────────────────────────────

// withIAMTx — база iam этой пробы и одна ОТКАТЫВАЕМАЯ транзакция поверх неё.
//
// Транзакция, а не просто база: ссылка «аккаунт ↔ его владелец» круговая и
// разрешается отложенным внешним ключом, который проверяется на COMMIT'е, — то
// есть посев законен ровно внутри незакоммиченной транзакции. Ровно так же сеет
// свои пробы и сама форма вердикта.
func withIAMTx(t *testing.T, fn func(ctx context.Context, tx pgx.Tx)) {
	t.Helper()
	if testing.Short() {
		t.Skip("нужна живая база (-short)")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, pgtest.NewDB(t))
	require.NoError(t, err, "пул")
	t.Cleanup(pool.Close)
	tx, err := pool.Begin(ctx)
	require.NoError(t, err, "транзакция")
	defer func() { _ = tx.Rollback(ctx) }()
	fn(ctx, tx)
}

func withCascadeWorld(t *testing.T, fn func(ctx context.Context, tx pgx.Tx)) {
	t.Helper()
	withIAMTx(t, func(ctx context.Context, tx pgx.Tx) {
		seedSuperAdminWorld(t, ctx, tx)
		fn(ctx, tx)
	})
}

func saExec(t *testing.T, ctx context.Context, tx pgx.Tx, sql string, args ...any) {
	t.Helper()
	_, err := tx.Exec(ctx, sql, args...)
	require.NoErrorf(t, err, "посев (%s)", sql)
}

// saUser кладёт настоящую строку пользователя. Настоящую, а не имя в кортеже:
// страж вставки выдачи проверяет существование субъекта, и фикстура, его
// обошедшая, была бы снисходительнее продукта.
func saUser(t *testing.T, ctx context.Context, tx pgx.Tx, id, account string) {
	t.Helper()
	saExec(t, ctx, tx,
		`INSERT INTO kacho_iam.users (id, external_id, email, account_id, invite_status)
		 VALUES ($1, $2, $3, $4, 'ACTIVE')`,
		id, "ext-"+id, id+"@kacho.local", account)
}

// saPointer кладёт отношение ЧЕРЕЗ ЖУРНАЛ — тем же путём, каким его кладёт
// продукт: строка намерения, из которой триггер складывает прямой факт.
// Фикстура, пишущая состояние в обход журнала, строила бы факт, которого
// продукт произвести не может.
func saPointer(t *testing.T, ctx context.Context, tx pgx.Tx, objectType, objectID, relation, subject string) {
	t.Helper()
	saExec(t, ctx, tx,
		`INSERT INTO kacho_iam.fga_outbox (event_type, payload, created_at)
		 VALUES ('fga.tuple.write',
		         jsonb_build_object('user', $1::text, 'relation', $2::text,
		                            'object', $3::text || ':' || $4::text),
		         now())`,
		subject, relation, objectType, objectID)
	var landed int
	require.NoError(t, tx.QueryRow(ctx,
		`SELECT count(*)::int FROM kacho_iam.relation_fact
		  WHERE object_type = $1 AND object_id = $2 AND relation = $3 AND subject = $4`,
		objectType, objectID, relation, subject).Scan(&landed), "перепись проекции журнала")
	require.Equalf(t, 1, landed,
		"строка журнала %s:%s --%s--> %s не спроецировалась в прямой факт: фикстура ничего "+
			"не посеяла, и проба судила бы пустое состояние", objectType, objectID, relation, subject)
}

// saEdge кладёт присланное владельцем ресурса звено цепи областей — ровно то,
// что шлёт регистрация ресурса у владельца прав.
func saEdge(t *testing.T, ctx context.Context, tx pgx.Tx, objectType, objectID, parentType, parentID string) {
	t.Helper()
	saExec(t, ctx, tx,
		`INSERT INTO kacho_iam.resource_parent_edge
		   (object_type, object_id, parent_type, parent_id, depth)
		 VALUES ($1, $2, $3, $4, 1)`, objectType, objectID, parentType, parentID)
}

// seedSuperAdminWorld строит двухаккаунтную иерархию, о которой говорит
// директива, — и НИ ОДНОЙ глагольной строки на целевых объектах.
//
// Цепь областей набирается тем же способом, каким её набирает продукт: чужие
// ресурсы шлют звено сами, предок ПРОЕКТА берётся из проекции журнала, предок
// АККАУНТА и предки пяти собственных типов iam выводятся представлением из
// схемы — поэтому пользователю, группе и привязке звено здесь не пишется, оно
// следует из их собственных строк.
func seedSuperAdminWorld(t *testing.T, ctx context.Context, tx pgx.Tx) {
	t.Helper()

	// Аккаунты и владельцы их строк. Порядок несущий: аккаунт вставляется первым
	// и ссылается на ещё не существующего владельца — ключ отложенный.
	for _, p := range [][2]string{{saAccA, saOwnerRowA}, {saAccB, saOwnerRowB}} {
		saExec(t, ctx, tx,
			`INSERT INTO kacho_iam.accounts (id, name, owner_user_id) VALUES ($1, $2, $3)`,
			p[0], "account-"+p[0], p[1])
		saUser(t, ctx, tx, p[1], p[0])
	}

	// Субъекты проб.
	for _, s := range []string{subjCloudAdmin, subjAccAdminA, subjAccOwnerA, subjProjAdminA} {
		saUser(t, ctx, tx, strings.TrimPrefix(s, "user:"), saAccA)
	}
	saExec(t, ctx, tx,
		`INSERT INTO kacho_iam.service_accounts (id, account_id, name, enabled)
		 VALUES ($1, $2, 'bootstrap', true)`,
		strings.TrimPrefix(subjBootstrapSA, "service_account:"), saAccA)

	// Цели внутри аккаунта A. Их звено цепи выводится представлением из их же
	// колонки account_id — писать его руками значило бы завести второй источник.
	saUser(t, ctx, tx, saUserA, saAccA)
	saExec(t, ctx, tx,
		`INSERT INTO kacho_iam.groups (id, account_id, name) VALUES ($1, $2, 'devs')`,
		saGroupA, saAccA)

	// Проекты. Указатель на аккаунт — В ЖУРНАЛ: его туда со-коммитит создание
	// проекта, и оттуда же его берёт цепь областей.
	for _, p := range [][2]string{{saPrjA, saAccA}, {saPrjB, saAccB}} {
		saExec(t, ctx, tx,
			`INSERT INTO kacho_iam.projects (id, account_id, name) VALUES ($1, $2, $3)`,
			p[0], p[1], "project-"+p[0])
		saPointer(t, ctx, tx, "project", p[0], "account", "account:"+p[1])
	}

	// Привязки — как ОБЪЕКТЫ проб (то, что администратор облака обязан снять), а
	// не как выдачи: роль под ними не несёт проекции глаголов (`role_verb`),
	// поэтому прав они не дают никому. Область привязки и есть её звено цепи —
	// оно выводится представлением из пары колонок её строки.
	//
	// Роль заводится СВОЯ В КАЖДОМ аккаунте, и это не оформление: продукт
	// отвергает привязку роли одного аккаунта в области другого
	// (`role … is not assignable on project:…`). Фикстура, обошедшая это одной
	// общей ролью, была бы снисходительнее продукта — и красное на посеве
	// показало это прежде, чем проба успела что-либо утверждать.
	for _, r := range [][3]string{
		{"rol-cascadeinerta", saAccA, saOwnerRowA},
		{"rol-cascadeinertb", saAccB, saOwnerRowB},
	} {
		saExec(t, ctx, tx,
			`INSERT INTO kacho_iam.roles (id, account_id, name, permissions)
			 VALUES ($1, $2, $3, '["iam.project.*.get"]'::jsonb)`, r[0], r[1], "inert_"+strings.ReplaceAll(r[1], "-", "_"))
	}
	for _, b := range [][4]string{
		{saBindingA, saPrjA, "rol-cascadeinerta", saOwnerRowA},
		{saBindingB, saPrjB, "rol-cascadeinertb", saOwnerRowB},
	} {
		saExec(t, ctx, tx,
			`INSERT INTO kacho_iam.access_bindings
			   (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
			 VALUES ($1, 'user', $2, $3, 'project', $4, 'ACTIVE')`,
			b[0], b[3], b[2], b[1])
		saExec(t, ctx, tx,
			`INSERT INTO kacho_iam.access_binding_subjects (binding_id, subject_type, subject_id)
			 VALUES ($1, 'user', $2)`, b[0], b[3])
	}

	// Листья аккаунта A — так, как их регистрируют их собственные модули.
	saEdge(t, ctx, tx, "vpc_network", saNetworkA, "project", saPrjA)
	saEdge(t, ctx, tx, "storage_volume", saVolumeA, "project", saPrjA)
	saEdge(t, ctx, tx, "storage_snapshot", saSnapshotA, "project", saPrjA)
	saEdge(t, ctx, tx, "storage_image", saImageA, "project", saPrjA)
	saEdge(t, ctx, tx, "nlb_network_load_balancer", saLbA, "project", saPrjA)
	saEdge(t, ctx, tx, "nlb_listener", saListenerA, "project", saPrjA)
	saEdge(t, ctx, tx, "registry_registry", saRegistryA, "project", saPrjA)
	saEdge(t, ctx, tx, "registry_repository", saRepoA, "registry_registry", saRegistryA)

	// Уровни 1 и 2 — один источник: отношение администратора облака на кластере.
	saPointer(t, ctx, tx, "cluster", saClusterID, "system_admin", subjCloudAdmin)
	saPointer(t, ctx, tx, "cluster", saClusterID, "system_admin", subjBootstrapSA)

	// Уровень 3 — только в аккаунте A: администратор и владелец.
	saPointer(t, ctx, tx, "account", saAccA, "admin", subjAccAdminA)
	saPointer(t, ctx, tx, "account", saAccA, "owner", subjAccOwnerA)

	// НЕ уровень: администратор проекта. Проект и ниже остаются плоскими — это
	// проба на превышение выдачи.
	saPointer(t, ctx, tx, "project", saPrjA, "admin", subjProjAdminA)
}

// saAsk — вопрос о доступе В ТОЙ ЖЕ ФОРМЕ, в какой его задаёт продукт.
//
// Ошибка формы означает «ответа нет» и разбирается отдельно от отказа: вернув на
// неё `Deny`, проба выдала бы незнание за законный отказ — и деньевые
// утверждения ниже зеленели бы на сломанном запросе.
func saAsk(t *testing.T, ctx context.Context, tx pgx.Tx, subject, relation string, o saObject) relverdict.Verdict {
	t.Helper()
	got, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
		Subject: subject, ObjectType: o.Type, ObjectID: o.ID, Relation: relation,
	})
	require.NoErrorf(t, err, "вопрос %s о %s:%s субъектом %s", relation, o.Type, o.ID, subject)
	return got
}

func saAllows(t *testing.T, ctx context.Context, tx pgx.Tx, subject, relation string, o saObject) bool {
	t.Helper()
	return saAsk(t, ctx, tx, subject, relation, o) == relverdict.Allow
}

// ── пробы ────────────────────────────────────────────────────────────────────

// TestSuperAdminCascade_CloudAdminRevokesForeignBinding — сам инцидент на
// наблюдаемом уровне: администратор облака снимает выдачу, которую не делал, в
// аккаунте, где у него нет ни одной строки на объекте.
func TestSuperAdminCascade_CloudAdminRevokesForeignBinding(t *testing.T) {
	withCascadeWorld(t, func(ctx context.Context, tx pgx.Tx) {
		require.Truef(t, saAllows(t, ctx, tx, subjCloudAdmin, "v_delete", saBindingAObj),
			"администратор облака обязан снять чужую выдачу (iam_access_binding v_delete) — "+
				"это инцидент 2026-07-26: 652 отказа против 32 успехов, сотрудник уволился, "+
				"а доступ его коллеги отозвать некому")

		for _, v := range saVerbsOf(t, saBindingAObj) {
			require.Truef(t, saAllows(t, ctx, tx, subjCloudAdmin, v, saBindingAObj),
				"администратор облака обязан разрешать %s на чужой выдаче", v)
			require.Truef(t, saAllows(t, ctx, tx, subjBootstrapSA, v, saBindingAObj),
				"учётка первичной установки обязана разрешать %s внутри облака", v)
		}

		require.True(t, saAllows(t, ctx, tx, subjAccAdminA, "v_delete", saBindingAObj),
			"администратор аккаунта обязан снимать выдачу внутри своего аккаунта")
		require.True(t, saAllows(t, ctx, tx, subjAccOwnerA, "v_delete", saBindingAObj),
			"владелец аккаунта — его администратор (account.admin выводится `or owner`)")
	})
}

// TestSuperAdminCascade_ReachesEveryVerbBearingType — каскад стоит чего-то,
// только если покрывает всю поверхность, а не тот один тип, на котором инцидент
// заметили. Каждый тип достаётся по тому указателю, который он реально
// объявляет: листья проекта — через проект, собственные объекты iam — через
// аккаунт, репозиторий — через свой реестр (проектного указателя у него нет).
func TestSuperAdminCascade_ReachesEveryVerbBearingType(t *testing.T) {
	withCascadeWorld(t, func(ctx context.Context, tx pgx.Tx) {
		objects := []saObject{
			saProjectAObj, saNetworkAObj, saVolumeAObj, saSnapshotObj, saImageObj,
			saLbAObj, saListenerObj, saRegistryObj, saRepoObj, saBindingAObj,
			saUserAObj, saGroupAObj,
		}
		for _, o := range objects {
			for _, v := range saVerbsOf(t, o) {
				require.Truef(t, saAllows(t, ctx, tx, subjCloudAdmin, v, o),
					"администратор облака обязан разрешать %s на %s:%s", v, o.Type, o.ID)
				require.Truef(t, saAllows(t, ctx, tx, subjAccAdminA, v, o),
					"администратор аккаунта A обязан разрешать %s на %s:%s (внутри своего аккаунта)",
					v, o.Type, o.ID)
			}
			for _, rel := range saTiers {
				require.Truef(t, saAllows(t, ctx, tx, subjCloudAdmin, rel, o),
					"администратор облака обязан разрешать уровень %s на %s:%s", rel, o.Type, o.ID)
			}
		}

		// Сам объект аккаунта: аккаунтами управляет администратор облака.
		for _, v := range saVerbsOf(t, saAccountAObj) {
			require.Truef(t, saAllows(t, ctx, tx, subjCloudAdmin, v, saAccountAObj),
				"администратор облака обязан разрешать %s на объекте аккаунта", v)
		}
	})
}

// TestSuperAdminCascade_DoesNotLeakBelowThreeLevels — регрессия, которая важнее
// самой правки: каскад обязан остановиться на аккаунте. Администратор ПРОЕКТА —
// обычный арендатор, его доступ к содержимому своего проекта остаётся
// материализованным выдачей, а не выведенным. Позеленей это по выводу — граница
// превышения выдачи, записанная в data-integrity.md, исчезнет.
func TestSuperAdminCascade_DoesNotLeakBelowThreeLevels(t *testing.T) {
	withCascadeWorld(t, func(ctx context.Context, tx pgx.Tx) {
		contents := []saObject{
			saNetworkAObj, saVolumeAObj, saSnapshotObj, saImageObj, saLbAObj,
			saListenerObj, saRegistryObj, saRepoObj, saBindingAObj,
		}
		for _, o := range contents {
			for _, v := range saVerbsOf(t, o) {
				require.Falsef(t, saAllows(t, ctx, tx, subjProjAdminA, v, o),
					"администратор ПРОЕКТА не вправе достать %s на %s:%s выводом — проект и "+
						"ниже остаются плоскими, доступ материализуется выдачей на объект",
					v, o.Type, o.ID)
			}
			for _, rel := range saTiers {
				require.Falsef(t, saAllows(t, ctx, tx, subjProjAdminA, rel, o),
					"администратор ПРОЕКТА не вправе достать уровень %s на %s:%s выводом",
					rel, o.Type, o.ID)
			}
		}

		// И обычный арендатор без единой строки не достаёт ничего. Положительный
		// контроль стоит в пробах выше: без него «ничего не достаёт» зеленело бы
		// и на форме, которая не находит вообще ничего.
		for _, o := range append(contents, saAccountAObj, saProjectAObj, saUserAObj, saGroupAObj) {
			for _, v := range saVerbsOf(t, o) {
				require.Falsef(t, saAllows(t, ctx, tx, subjStranger, v, o),
					"субъект без единой строки не вправе разрешать %s на %s:%s", v, o.Type, o.ID)
			}
		}
	})
}

// TestSuperAdminCascade_StopsAtTheAccountBoundary — уровень 3 ограничен своим
// аккаунтом. Иначе каскад вручил бы администратору одного арендатора всё облако,
// то есть ровно обратное тому, ради чего он заведён.
func TestSuperAdminCascade_StopsAtTheAccountBoundary(t *testing.T) {
	withCascadeWorld(t, func(ctx context.Context, tx pgx.Tx) {
		foreign := []saObject{saAccountBObj, saProjectBObj, saBindingBObj}
		for _, o := range foreign {
			for _, v := range saVerbsOf(t, o) {
				require.Falsef(t, saAllows(t, ctx, tx, subjAccAdminA, v, o),
					"администратор аккаунта A не вправе достать %s на %s:%s в аккаунте B", v, o.Type, o.ID)
				require.Falsef(t, saAllows(t, ctx, tx, subjAccOwnerA, v, o),
					"владелец аккаунта A не вправе достать %s на %s:%s в аккаунте B", v, o.Type, o.ID)
			}
			for _, rel := range saTiers {
				require.Falsef(t, saAllows(t, ctx, tx, subjAccAdminA, rel, o),
					"администратор аккаунта A не вправе достать уровень %s на %s:%s в аккаунте B",
					rel, o.Type, o.ID)
			}
		}

		// Уровни 1-2 облачные by construction — аккаунт B тоже их.
		for _, v := range saVerbsOf(t, saBindingBObj) {
			require.Truef(t, saAllows(t, ctx, tx, subjCloudAdmin, v, saBindingBObj),
				"администратор облака перешагивает аккаунты — %s на выдаче в аккаунте B", v)
		}

		// Администратор аккаунта НЕ получает собственных глаголов объекта
		// аккаунта: его власть — «всё ВНУТРИ аккаунта», а сам аккаунт есть
		// граница этой области, а не то, что внутри неё. Достают только уровни 1-2.
		require.False(t, saAllows(t, ctx, tx, subjAccAdminA, "v_delete", saAccountAObj),
			"администратор аккаунта не вправе снести сам объект аккаунта — каскад идёт "+
				"ВНУТРЬ аккаунта, аккаунт — его граница")
	})
}

// TestSuperAdminCascade_DoesNotTouchNonCrudRelations — каскад покрывает
// поверхность CRUD (глаголы и три уровня, на которые гейтит каталог прав) и
// НИЧЕГО больше. Исключённые здесь отношения — намеренные контракты наименьших
// прав, которые прочтение «может всё» тихо растворило бы: announce_writer
// принадлежит одной лишь плоскости данных, member — факт членства, owner — факт
// личности.
func TestSuperAdminCascade_DoesNotTouchNonCrudRelations(t *testing.T) {
	withCascadeWorld(t, func(ctx context.Context, tx pgx.Tx) {
		require.False(t, saAllows(t, ctx, tx, subjCloudAdmin, "announce_writer", saLbAObj),
			"announce_writer принадлежит плоскости данных — состояние объявления не вправе "+
				"подделать ни один человеческий принципал, включая администратора облака")
		require.False(t, saAllows(t, ctx, tx, subjCloudAdmin, "member", saGroupAObj),
			"членство — факт о субъекте, а не право: каскад не вправе сделать администратора "+
				"облака членом каждой группы")
		require.False(t, saAllows(t, ctx, tx, subjCloudAdmin, "owner", saRegistryObj),
			"владение — факт личности: каскад не вправе переписать, кто владеет ресурсом")
		require.False(t, saAllows(t, ctx, tx, subjAccAdminA, "owner", saRegistryObj),
			"владение — факт личности: администратор аккаунта не становится владельцем")
	})
}

// TestSuperAdminCascade_ProjectIsNotACascadeSource — структурная половина
// доказательства утечки, прочитанная с канонической модели: источник каскада у
// `project` — его АККАУНТ и КЛАСТЕР, никогда не собственный `admin`. Одиночное
// `or admin`, просочившееся в эту строку, тихо превратило бы каждого
// администратора проекта в супер-администратора над содержимым его проекта, а
// поведенческая проба выше осталась бы зелёной по разрешающим случаям, молча
// потеряв деньевые.
func TestSuperAdminCascade_ProjectIsNotACascadeSource(t *testing.T) {
	dsl := modelDSL(t)

	body := typeBody(t, dsl, "project")
	line := regexp.MustCompile(`(?m)^\s*define super_admin:\s*(.*)$`).FindStringSubmatch(body)
	require.Lenf(t, line, 2, "project must define super_admin — the cascade carrier. body:\n%s", body)

	rhs := line[1]
	require.Contains(t, rhs, "from account",
		"project's cascade must come from its account (level 3)")
	require.Contains(t, rhs, "from cluster",
		"project's cascade must come from the cluster (levels 1-2)")

	// Каждый дизъюнкт обязан быть выводом по указателю на предка — `<rel> from
	// account|cluster`. Голый `admin` / `editor` / `viewer` / `[…]` был бы
	// СОБСТВЕННЫМ уровнем проекта, то есть ровно той утечкой, которую это
	// запрещает.
	overParent := regexp.MustCompile(`^\w+ from (account|cluster)$`)
	for _, d := range strings.Split(rhs, " or ") {
		d = strings.TrimSpace(d)
		require.Truef(t, overParent.MatchString(d),
			"project's cascade disjunct %q is not a derivation over a parent pointer — "+
				"the project's own tier must NEVER be a cascade source (anti-over-grant "+
				"boundary, data-integrity.md). full rhs: %q", d, rhs)
	}

	// Симметрично: каждый листовой тип каскадит от super_admin СВОЕГО предка и
	// потому наследует то же исключение. Лист, читающий `admin from project`,
	// открыл бы утечку заново по одному типу за раз.
	for _, leaf := range []string{
		"vpc_network", "vpc_subnet", "compute_instance", "storage_volume",
		"nlb_network_load_balancer", "nlb_listener", "registry_registry",
	} {
		lb := typeBody(t, dsl, leaf)
		m := regexp.MustCompile(`(?m)^\s*define super_admin:\s*(.*)$`).FindStringSubmatch(lb)
		require.Lenf(t, m, 2, "%s must define super_admin. body:\n%s", leaf, lb)
		require.Equalf(t, "super_admin from project", m[1],
			"%s must cascade from its project's super_admin (which excludes the project's "+
				"own tier), never from `admin from project`", leaf)
	}
}
