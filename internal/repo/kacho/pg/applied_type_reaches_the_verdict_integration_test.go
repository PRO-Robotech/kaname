// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// applied_type_reaches_the_verdict_integration_test.go — ПОСЛЕДНЯЯ МИЛЯ пункта 1
// DoD эпика #1027 (задача продукта #1968): от применения манифеста до ответа
// ВЕРДИКТА прав, на живой базе, одной пробой.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ЭТА ПРОБА, ЕСЛИ ЗВЕНЬЯ ДОКАЗАНЫ ПОРОЗНЬ
//
// Доказано две вещи, обе с инъекцией: тип, заведённый в работающем процессе,
// доезжает до ПРОЕКЦИИ (`catalog.TestIAMCT2_14_AppliedTypeReachesTheProjection`)
// и доезжает через настоящий применитель
// (`TestIAMCT2_14_AppliedAfterStartReachesTheProjection`). Обе останавливаются на
// `role_verb`. Что проекцию читает ВЕРДИКТ, было установлено ЧТЕНИЕМ запроса, а
// не прогоном.
//
// В этой линии дважды находили разрыв, невидимый ни с одной стороны по
// отдельности: обе половины исправны, каждая проверена своими пробами, а вопрос,
// который задаёт одна, — не тот, на который отвечает другая. Ни одна проба
// половины покраснеть не может by construction. Исключить это умеет только
// проба, идущая СКВОЗЬ ОБЕ стороны, — она и есть предмет файла.
//
// ─────────────────────────────────────────────────────────────────────────────
// ДВА ПРЕДМЕТА, И ИХ НЕЛЬЗЯ ПУТАТЬ
//
// «Новый тип» имеет ДВА смысла, и сквозной путь у них РАЗНЫЙ:
//
//	СТРОКА КАТАЛОГА заведена применением в работающем процессе, а блок типа
//	модели прав пришёл со сборкой   → `TestDoD1_...CarriesTheGrantToTheVerdict`
//
//	ТИП НЕ ЗНАЕТ И СБОРКА — ни блока модели, ни словаря; блок приносит
//	КОМПОЗИЦИЯ из доставленных манифестов
//	                → `TestDoD1_...ReachesTheVerdictThroughTheComposedModel`
//
// Сходятся ОБА, и утверждаются здесь целиком. Здесь стояло «второй НЕ сходится:
// проекция полна, вердикт пуст» — верно на своей ревизии и снято вместе со своим
// основанием, а не обойдено: модель процесса перестала быть вшитым каноном
// (`installComposedModel` на старте, #1969), а харнесс перестал измерять
// собственную обстановку вместо продукта (`harness_composed_model_test.go`).
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО УТВЕРЖДАЕТСЯ, А ЧТО НЕТ
//
// Утверждается ВЕРДИКТ (`relverdict.Ask`), а не строка таблицы: строки уже
// утверждают пробы выше, и повторять их значило бы завести два места об одном
// предмете.
//
// ─────────────────────────────────────────────────────────────────────────────
// РОЛЬ ЗАВОДИТСЯ USE-CASE'ОМ, А НЕ ПИСАТЕЛЯМИ РЕПОЗИТОРИЯ (kacho#1999)
//
// Здесь стояло «роль заводится ТЕМИ ЖЕ тремя писателями и в том же порядке,
// каким её заводит use-case создания роли». Про ПИСАТЕЛЕЙ это было верно и про
// ПРОВЕРКИ — неверно: между входом use-case и первым писателем стоят синхронные
// гейты, которых у пути писателей нет BY CONSTRUCTION. Один из них — гейт
// грантуемого токена (`validateRuleCatalog`) — отвергал ровно тот тип, ради
// которого проба и написана (#1993), а проба оставалась ЗЕЛЁНОЙ: она утверждала
// про свою половину цепи и не могла увидеть звена, стоящего раньше её точки
// входа. Класс — не «проба неверна», а «проверка была верной и МИМО».
//
// Цена измерена, а не предположена: на инъекции, возвращающей источник гейта к
// словарю сборки (дефект до #1993), проба звена краснеет тремя утверждениями, а
// ДОФИКСОВАЯ проба цепи выходит успехом. Теперь роль заводится ТЕМ ЖЕ ПУТЁМ,
// что у арендатора, — `role.CreateRoleUseCase.Execute` — и на той же инъекции
// краснеет.
//
// Отсюда же и переучёт фикстуры: идентификатор аккаунта проходит синхронную
// проверку формы (`shared.ValidateResourceID`), поэтому обвязка чеканит его
// `ids.NewID`, а не пишет короткий литерал. Роль ПЕРЕОБЪЯВЛЯЕТСЯ той же
// стороной, какой это делает арендатор, — `role.UpdateRoleUseCase` с теми же
// правилами: у существующей роли второго законного пути пересчитать проекции
// нет.
//
// ЧЕГО ПРОБА НЕ ПОКРЫВАЕТ, сказано прямо: транспорт (RPC), стража прав
// вызывающего на крае (пообъектная проверка `v_create@iam_role` идёт ДО того,
// как iam будет вызван) и материализацию кортежей. Операция ИСПОЛНЯЕТСЯ и её
// терминальный исход утверждается: id роли приходит метаданными, назначенными
// ДО асинхронного шага, поэтому читать его, не прочитав `error`, значит
// адресоваться к возможному фантому. Их полосы свои, и утверждать о них здесь
// значило бы заявлять шире сделанного. Подставлены ВХОДЫ, а не звенья цепи:
// арендаторская обвязка и строка выдачи кладутся оператором вставки, тогда как
// каталог, снимок, проекция и вердикт ПРОИЗВОДЯТСЯ. Вопрос задаётся форме `Ask`
// (`relverdict/query.go`); `List` и `Expand` соединяют ту же `role_verb` и здесь
// не спрашиваются.
//
// ─────────────────────────────────────────────────────────────────────────────
// ДВА КОНТРОЛЯ, БЕЗ КОТОРЫХ УТВЕРЖДЕНИЕ ПУСТО
//
// Пара «снято → отказ, заведено → разрешение» порознь выполнима двумя способами,
// не имеющими к предмету отношения, и оба измерены инъекцией, а не выведены:
//
//  1. ЖИВОЙ СОСЕД. Отказ в снятом состоянии выполним цепью вердикта, отвечающей
//     отказом ВСЕМУ. Инъекция — переселение проекций, расширенное со снятого
//     РЕСУРСА до всего МОДУЛЯ: дофиксовая проба остаётся зелёной и печатает
//     «сквозной путь СОШЁЛСЯ», дополненная краснеет и называет соседа;
//  2. ПРИПИСЫВАЕМОСТЬ. Непустая проекция после заведения выполнима снимком,
//     который снятия не заметил вовсе. Инъекция — `Snapshot.Refresh`, отвечающий
//     успехом и не подменяющий факт: дофиксовая проба зелена и печатает то же
//     «СОШЁЛСЯ» на снимке, ни разу не обновившемся; дополненная краснеет на
//     утверждении о потере.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	"github.com/PRO-Robotech/kacho/pkg/ids"
	"github.com/PRO-Robotech/kacho/pkg/operations"

	roleapp "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/role"
	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/seed"
	"github.com/PRO-Robotech/kacho-iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho-iam/internal/authzmodel"
	"github.com/PRO-Robotech/kacho-iam/internal/catalog"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho-iam/internal/manifest"
	kachorepo "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho"
	kachopg "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg/relverdict"
)

// Предмет ПЕРВОЙ пробы: ресурс ПОСТАВЛЯЕМОГО модуля. Блок его типа пришёл со
// сборкой, а СТРОКА каталога снимается и заводится заново применением манифеста
// в работающем процессе — то есть ровно тем путём, каким её заводит клиент.
const (
	verdictShippedModule = "vpc"
	verdictShippedRes    = "cidrGroup"
	verdictShippedDotted = verdictShippedModule + "." + verdictShippedRes
	verdictShippedModel  = "vpc_cidr_group"
)

// Предмет ЖИВОГО СОСЕДА: ресурс ТОГО ЖЕ модуля, которого снятие не касается.
//
// Он нужен как положительный контроль В СНЯТОМ СОСТОЯНИИ, и это не украшение:
// без него «после снятия — отказ» выполнимо цепью вердикта, отвечающей отказом
// ВСЕМУ, — то есть шаг снятия зеленел бы на сломанном целиком пути, и отличить
// это от исправной работы было бы нечем. Сосед поставляемый, живой на всём
// протяжении пробы, и спрашивается ТЕМ ЖЕ путём.
const (
	verdictNeighbourRes    = "network"
	verdictNeighbourDotted = verdictShippedModule + "." + verdictNeighbourRes
	verdictNeighbourModel  = "vpc_network"
)

// Предмет ВТОРОЙ пробы: тип, которого сборка не знает ни одним словарём. Модуль
// синтетический и не член платформенного набора — тот же, на котором стоят
// сценарии применителя.
const (
	verdictAppliedRes    = "alpha"
	verdictAppliedDotted = applierProbeModule + "." + verdictAppliedRes
	verdictAppliedModel  = applierProbeModule + "_" + verdictAppliedRes
)

// verdictProbeVerbs — глаголы синтетического ресурса. Совпадают с набором
// поставляемого соседа намеренно: две пробы обязаны отличаться РОВНО тем, что
// проверяется (знает ли тип сборка), а не ещё и составом глаголов.
var verdictProbeVerbs = []string{"get", "list", "update", "delete"}

// verdictAppliedResource — ЕДИНСТВЕННОЕ объявление синтетического ресурса.
//
// Одно на обе стороны намеренно: харнесс собирает из него БЛОК МОДЕЛИ процесса
// (`testmain_test.go`), а проба применяет его же к КАТАЛОГУ. Два объявления
// одного предмета разошлись бы молча — модель знала бы один набор действий,
// каталог другой, — и вердикт отвечал бы отказом по действию, которое роль
// честно раздала. Различить это от «права не выдали» нечем.
//
// Указатель области объявлен здесь и только здесь: применителю он безразличен
// (`modulecatalog.RowsOf` читает имя, тип объекта и действия), а рендер блока без
// него отказывает (`modelrender.ErrParentEmpty`) — то есть поле нужно ровно той
// стороне, ради которой объявление и сведено в одно место.
func verdictAppliedResource() manifest.Resource {
	r := probeResource(verdictAppliedRes, verdictProbeVerbs...)
	r.Parents = []manifest.Parent{{Name: "project", Type: "project"}}
	return r
}

// verdictTenant — арендаторская обвязка: аккаунт, пользователь, проект и две
// служебные учётки (одна получает выдачу, вторая — отрицание).
//
// Строки настоящие, а не подставные: выдача ссылается на учётку внешним ключом, а
// вердикт идёт по цепи областей (`resource_parent_edge`). Фикстура, обходящая
// ключ, доказывала бы работу запроса на данных, которых в проде не бывает.
type verdictTenant struct {
	accountID string
	userID    string
	projectID string
	granted   string
	bare      string
}

func seedVerdictTenant(t *testing.T, ctx context.Context, pool *pgxpool.Pool) verdictTenant {
	t.Helper()
	// Идентификаторы аккаунта и пользователя ЧЕКАНЯТСЯ, а не пишутся литералом:
	// путь создания роли судит форму `account_id` синхронно
	// (`shared.ValidateResourceID` — префикс плюс длина), и короткий литерал
	// отвергался бы полосой формы, к предмету пробы отношения не имеющей.
	tn := verdictTenant{
		accountID: ids.NewID(domain.PrefixAccount),
		userID:    ids.NewID(domain.PrefixUser),
		projectID: "prj-dod1",
		granted:   "sva-dod1-granted",
		bare:      "sva-dod1-bare",
	}
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	exec := func(sql string, args ...any) {
		t.Helper()
		_, eerr := tx.Exec(ctx, sql, args...)
		require.NoError(t, eerr, "посев обвязки: %s", sql)
	}
	exec(`INSERT INTO users (id, account_id, external_id, email, display_name, invite_status)
	      VALUES ($1, $2, $3, $4, $5, 'ACTIVE')`,
		tn.userID, tn.accountID, "ext-"+tn.userID, "u-dod1@example.com", "DoD1")
	exec(`INSERT INTO accounts (id, name, owner_user_id, labels)
	      VALUES ($1, 'dod1-acc', $2, '{}'::jsonb)`, tn.accountID, tn.userID)
	exec(`INSERT INTO projects (id, account_id, name, labels)
	      VALUES ($1, $2, 'dod1-prj', '{}'::jsonb)`, tn.projectID, tn.accountID)
	for _, sa := range []string{tn.granted, tn.bare} {
		exec(`INSERT INTO kacho_iam.service_accounts (id, account_id, name)
		      VALUES ($1, $2, $3)`, sa, tn.accountID, sa)
	}
	require.NoError(t, tx.Commit(ctx))
	return tn
}

// probeRules — правило роли пробы. Одно объявление на создание и на правку:
// два разошлись бы молча, и переобъявление писало бы не то, что заведение.
func probeRules(module, resource string) domain.Rules {
	return domain.Rules{{Module: module, Resources: []string{resource}, Verbs: []string{"*"}}}
}

// declarerCtx — контекст ВЫЗЫВАЮЩЕГО, а не служебный: use-case отвергает
// анонима первым же оператором (`authzguard.RequireAuthenticated`), и подать
// сюда пустой контекст значило бы получить отказ полосы, к предмету пробы
// отношения не имеющей.
func declarerCtx(ctx context.Context, userID string) context.Context {
	return operations.WithPrincipal(ctx, operations.Principal{
		Type: "user", ID: userID, DisplayName: "DoD-1",
	})
}

// awaitOperation дожидается терминального состояния операции и возвращает её.
//
// Ждать обязательно: `Execute` отдаёт операцию ПРИНЯТОЙ, а запись идёт
// асинхронным исполнителем. Ждать по времени нельзя — `operations.Wait`
// дожидается СОБЫТИЯ, а не срока.
func awaitOperation(t *testing.T, ctx context.Context, ops operations.Repo, opID string) *operations.Operation {
	t.Helper()
	waitCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(waitCtx), "исполнитель операций не завершил очередь")
	got, err := ops.Get(ctx, opID)
	require.NoErrorf(t, err, "операция %s не прочитана — это «не выполнилось», а не отказ", opID)
	require.Truef(t, got.Done, "операция %s не терминальна", opID)
	return got
}

// declareRole заводит роль ТЕМ ЖЕ ПУТЁМ, каким её заводит арендатор, —
// use-case создания (`role.CreateRoleUseCase`), а не тремя писателями
// репозитория (kacho#1999).
//
// Разница не в наборе писателей: их use-case зовёт те же и в том же порядке.
// Разница в ТОМ, ЧТО СТОИТ ДО НИХ — синхронные гейты входа, среди которых гейт
// грантуемого токена. У пути писателей их нет by construction, поэтому первое
// звено цепи оставалось неизмеренным этой пробой.
//
// Возвращается ЧЕКАНЕННЫЙ id роли: назначает его use-case, и принять его от
// вызывающего значило бы вернуть путь, минующий чеканку. Пары проекции
// вычисляются снимком каталога и служат переписью — сама запись идёт внутри
// use-case.
func declareRole(t *testing.T, ctx context.Context, pool *pgxpool.Pool, repo kachorepo.Repository,
	cat catalog.Source, accountID, userID, module, resource string) (string, []domain.RoleVerb) {
	t.Helper()

	rules := probeRules(module, resource)
	pairs := cat.Facts().RoleVerbsFromSelectors(rules.MaterializingSelectors())

	ops := operations.NewRepo(pool, "kacho_iam")
	uc := roleapp.NewCreateRoleUseCase(repo, ops, cat)
	op, err := uc.Execute(declarerCtx(ctx, userID), domain.Role{
		AccountID:   domain.AccountID(accountID),
		Name:        domain.RoleName(strings.ToLower("dod1_" + module + "_" + resource)),
		Description: "DoD-1 through the use-case",
		Rules:       rules,
	})
	require.NoErrorf(t, err, "use-case создания роли отверг правило над %s.%s СИНХРОННО — "+
		"первое звено цепи «клиент завёл тип манифестом → получил права» разомкнуто, и "+
		"ниже чинить нечего: роли нет", module, resource)
	require.NotNil(t, op, "Execute вернул nil Operation без ошибки — исход создания не определён")

	done := awaitOperation(t, ctx, ops, op.ID)
	// Исход операции читается ДО метаданных: id роли назначается ПРИНЯТИЕМ, до
	// записи, поэтому на упавшей операции он указывает на несуществующую строку.
	require.Nilf(t, done.Error, "операция создания роли над %s.%s завершилась отказом: %v",
		module, resource, done.Error)

	var meta iamv1.CreateRoleMetadata
	require.NoError(t, done.Metadata.UnmarshalTo(&meta), "метаданные операции создания роли")
	require.NotEmpty(t, meta.GetRoleId(), "операция создания роли не назвала id роли")

	var exists bool
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM roles WHERE id = $1)`, meta.GetRoleId()).Scan(&exists))
	require.Truef(t, exists, "операция успешна, а строки роли %s нет — метаданные назвали фантом",
		meta.GetRoleId())
	return meta.GetRoleId(), pairs
}

// redeclareRole ПЕРЕОБЪЯВЛЯЕТ правила уже существующей роли — тем же путём,
// каким это делает арендатор (`role.UpdateRoleUseCase`).
//
// Второго законного пути пересчитать проекции у существующей роли нет: снятие
// строки каталога вырезало элемент селектора и пары проекции, и вернуть их
// может только правка правил. Гейт грантуемого токена стоит и здесь — паритет
// создания и правки несущий: приняв роль над заведённым типом и отвергнув её
// правку, платформа сделала бы роль неисправимой.
func redeclareRole(t *testing.T, ctx context.Context, pool *pgxpool.Pool, repo kachorepo.Repository,
	cat catalog.Source, roleID, userID, module, resource string) []domain.RoleVerb {
	t.Helper()

	rules := probeRules(module, resource)
	pairs := cat.Facts().RoleVerbsFromSelectors(rules.MaterializingSelectors())

	ops := operations.NewRepo(pool, "kacho_iam")
	uc := roleapp.NewUpdateRoleUseCase(repo, ops, cat)
	op, err := uc.Execute(declarerCtx(ctx, userID), roleapp.UpdateRoleInput{
		ID:         domain.RoleID(roleID),
		Rules:      rules,
		UpdateMask: []string{"rules"},
	})
	require.NoErrorf(t, err, "use-case правки роли отверг правило над %s.%s СИНХРОННО — "+
		"роль над заведённым типом стала неисправимой", module, resource)
	require.NotNil(t, op, "Execute правки вернул nil Operation без ошибки")

	done := awaitOperation(t, ctx, ops, op.ID)
	require.Nilf(t, done.Error, "операция правки роли над %s.%s завершилась отказом: %v",
		module, resource, done.Error)
	return pairs
}

// snapshotProjectionOf — пары проекции по снимку, БЕЗ записи.
//
// Читающий близнец `declareRole`, и он нужен именно в СНЯТОМ состоянии: писать
// пару по снятому типу нельзя — её отвергнет внешний ключ `role_verb_type_fk`, и
// отказ пришёл бы ЧУЖОЙ полосой вместо утверждения этой пробы. Спрашивается ровно
// то, что кладёт писатель, и теми же селекторами.
func snapshotProjectionOf(facts *catalog.Facts, module, resource string) []domain.RoleVerb {
	rules := domain.Rules{{Module: module, Resources: []string{resource}, Verbs: []string{"*"}}}
	return facts.RoleVerbsFromSelectors(rules.MaterializingSelectors())
}

// grantOnProject выдаёт роль субъекту на проект и кладёт объект под этот проект.
func grantOnProject(t *testing.T, ctx context.Context, pool *pgxpool.Pool,
	tn verdictTenant, bindingID, roleID, objectModelType, objectID string) {
	t.Helper()
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	exec := func(sql string, args ...any) {
		t.Helper()
		_, eerr := tx.Exec(ctx, sql, args...)
		require.NoError(t, eerr, "выдача: %s", sql)
	}
	exec(`INSERT INTO kacho_iam.resource_parent_edge
	        (object_type, object_id, parent_type, parent_id, depth)
	      VALUES ($1, $2, 'project', $3, 1)
	      ON CONFLICT DO NOTHING`, objectModelType, objectID, tn.projectID)
	exec(`INSERT INTO kacho_iam.access_bindings
	        (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
	      VALUES ($1, 'service_account', $2, $3, 'project', $4, 'ACTIVE')
	      ON CONFLICT DO NOTHING`,
		bindingID, tn.granted, roleID, tn.projectID)
	exec(`INSERT INTO kacho_iam.access_binding_subjects (binding_id, subject_type, subject_id)
	      VALUES ($1, 'service_account', $2) ON CONFLICT DO NOTHING`, bindingID, tn.granted)
	require.NoError(t, tx.Commit(ctx))
}

// askVerdict задаёт вопрос форме E в СВОЕЙ читающей транзакции и возвращает все
// три составляющие ответа.
//
// Ошибка возвращается, а не гасится: у вердикта ТРИ исхода, и «не вычислено»
// (`Unknown` + ошибка) не есть «нет прав». Проба, приводящая их к булеву, потеряла
// бы ровно то различие, ради которого различимость и утверждается.
func askVerdict(t *testing.T, ctx context.Context, pool *pgxpool.Pool,
	subject, modelType, objectID, relation string) (relverdict.Verdict, relverdict.Grounds, error) {
	t.Helper()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	return relverdict.Ask(ctx, tx, relverdict.Query{
		Subject: "service_account:" + subject, ObjectType: modelType,
		ObjectID: objectID, Relation: relation,
	})
}

// shippedManifest — поставляемый манифест модуля, разобранный из дерева.
//
// `drop` называет ресурс, который из него вынимается: снятие строки каталога
// выражается ОТСУТСТВИЕМ ресурса в объявлении, а не отдельным глаголом (см. шапку
// применителя, п. 1).
func shippedManifest(t *testing.T, module, drop string) *manifest.Manifest {
	t.Helper()
	// `../../../../..` от этого пакета — каталог `services` монорепо.
	body, err := os.ReadFile(filepath.Clean( // #nosec G304 -- путь собран из констант пробы
		filepath.Join("../../../../..", module, "manifest.yaml")))
	require.NoError(t, err, "прочитать манифест модуля %s", module)
	m, err := manifest.Load(body)
	require.NoError(t, err, "разобрать манифест модуля %s", module)
	if drop == "" {
		return m
	}
	kept := make([]manifest.Resource, 0, len(m.Resources))
	for _, r := range m.Resources {
		if r.Name == drop {
			continue
		}
		kept = append(kept, r)
	}
	require.Lenf(t, kept, len(m.Resources)-1,
		"ресурс %q в манифесте модуля %s не найден — вынимать нечего, и сценарий снятия "+
			"стал бы вакуумным", drop, module)
	m.Resources = kept
	return m
}

// verbsOf — глаголы пар проекции, для переписи в выводе.
func verbsOf(pairs []domain.RoleVerb) []string {
	out := make([]string, 0, len(pairs))
	for _, p := range pairs {
		out = append(out, p.Verb)
	}
	return out
}

// TestDoD1_RuntimeAppliedCatalogRowCarriesTheGrantToTheVerdict — ПЕРВЫЙ предмет:
// строка каталога, снятая и заведённая заново применением манифеста В РАБОТАЮЩЕМ
// ПРОЦЕССЕ, доводит выдачу до НЕНУЛЕВОГО вердикта.
//
// Утверждаются ОБА направления, и это несущее: порознь каждое выполнимо путём,
// который не даёт права НИКОГДА (тогда «снятие прекращает» верно тривиально) либо
// даёт его ВСЕГДА (тогда «заведение восстанавливает» верно тривиально).
//
//	заведено (посев)      → Allow      исходное состояние, положительный контроль
//	снято применением     → Deny       и НЕ по незнанию типа: модель его знает
//	заведено применением  → Allow      снова, после пересчёта проекции по снимку
//	субъект без выдачи    → Deny       отрицание
//	типа нет вовсе        → Deny + «тип не объявлен»  ноль отличим от «не вычислено»
func TestDoD1_RuntimeAppliedCatalogRowCarriesTheGrantToTheVerdict(t *testing.T) {
	ctx, pool := catalogPool(t)
	catRepo := kachopg.NewCatalogRepo(pool)
	repo := kachopg.New(pool, nil)
	applier := applierOver(t, pool)

	census, err := seed.AssertCatalogParity(ctx, catRepo, seed.ImageAnchor())
	require.NoError(t, err, "страж паритета каталога")
	snap, err := catalog.NewSnapshot(census.Live, catRepo, nil, nil)
	require.NoError(t, err, "снимок каталога")

	mods, res, verbs := liveCatalogCounts(t, ctx, pool)
	t.Logf("перепись каталога: модулей %d, ресурсов %d, действий %d", mods, res, verbs)

	tn := seedVerdictTenant(t, ctx, pool)

	// ── (1) ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: путь работает ──────────────────────────
	roleID, pairs := declareRole(t, ctx, pool, repo, snap,
		tn.accountID, tn.userID, verdictShippedModule, verdictShippedRes)
	require.NotEmptyf(t, pairs,
		"проекция по %q пуста ещё до всякого применения — путь не работает НИ ДЛЯ КОГО, "+
			"и всё, что ниже, было бы беспредметно", verdictShippedDotted)
	grantOnProject(t, ctx, pool, tn, "acb-dod1", roleID, verdictShippedModel, "cg-dod1")
	t.Logf("исходно: тип %q → пар проекции %d, глаголы %v",
		verdictShippedDotted, len(pairs), verbsOf(pairs))

	// ── (1а) ЖИВОЙ СОСЕД: заводится СЕЙЧАС, спрашивается в СНЯТОМ состоянии ──
	//
	// Здесь утверждается только то, что путь соседа работает ДО снятия. Без
	// этого утверждения контроль ниже был бы двусмыслен: его краснота означала бы
	// и «снятие унесло соседа», и «сосед не работал никогда».
	neighbourRoleID, npairs := declareRole(t, ctx, pool, repo, snap,
		tn.accountID, tn.userID, verdictShippedModule, verdictNeighbourRes)
	require.NotEmptyf(t, npairs,
		"проекция по соседу %q пуста ещё до снятия — контроль живого соседа стал бы "+
			"беспредметным", verdictNeighbourDotted)
	grantOnProject(t, ctx, pool, tn, "acb-dod1-nb", neighbourRoleID, verdictNeighbourModel, "net-dod1")

	nGot, nGrounds, nErr := askVerdict(t, ctx, pool, tn.granted, verdictNeighbourModel, "net-dod1", "v_get")
	require.NoError(t, nErr, "вердикт по соседу не вычислен — это «не выполнилось», а не отказ")
	require.Equalf(t, relverdict.Allow, nGot,
		"сосед %q не даёт allow ДО всякого снятия (тип не объявлен моделью: %t) — контроль, "+
			"который не может быть верен, не отличает ничего",
		verdictNeighbourDotted, nGrounds.TypeNotDeclared)
	t.Logf("живой сосед: тип %q → пар проекции %d, вердикт до снятия = %v",
		verdictNeighbourDotted, len(npairs), nGot)

	got, grounds, aerr := askVerdict(t, ctx, pool, tn.granted, verdictShippedModel, "cg-dod1", "v_get")
	require.NoErrorf(t, aerr, "вердикт не вычислен — это «не выполнилось», а не отказ")
	require.Equalf(t, relverdict.Allow, got,
		"выдача не доехала до вердикта ещё на посеянной строке (тип не объявлен моделью: %t) — "+
			"дальнейшее о применении ничего не утверждало бы", grounds.TypeNotDeclared)

	// ── (2) СНЯТИЕ ПРИМЕНЕНИЕМ: вердикт прекращается ───────────────────────
	rep, err := applier.Apply(ctx, shippedManifest(t, verdictShippedModule, verdictShippedRes))
	require.NoError(t, err, "применение манифеста БЕЗ ресурса %q", verdictShippedRes)
	require.Truef(t, rep.Changed(), "снятие каталог не изменило (%s) — снимать было нечего", rep)
	t.Logf("снятие: %s", rep)
	require.NoError(t, snap.Refresh(ctx), "обновление снимка каталога")

	// ПРИПИСЫВАЕМОСТЬ шага (3), и без неё он не утверждает своего предмета:
	// непустая проекция после заведения получилась бы и у снимка, снятия не
	// заметившего вовсе. Тогда «заведено ПРИМЕНЕНИЕМ» доказывалось бы состоянием,
	// которое просто ни разу не менялось, и отставший снимок был бы неотличим от
	// исправной работы.
	require.Emptyf(t, snapshotProjectionOf(snap.Facts(), verdictShippedModule, verdictShippedRes),
		"снимок не потерял снятый тип %q: пары шага заведения тогда не приписываются "+
			"применению — их дал бы и снимок, ни разу не обновившийся", verdictShippedDotted)
	// ЗЕРКАЛО к утверждению выше: сосед в снимке остался. Без него «потеряно»
	// зеленело бы и на снимке, потерявшем ВСЁ, то есть на другой поломке.
	require.NotEmptyf(t, snapshotProjectionOf(snap.Facts(), verdictShippedModule, verdictNeighbourRes),
		"снимок после снятия %q потерял и живого соседа %q — утверждение о потере выше "+
			"зеленело бы на снимке, потерявшем всё",
		verdictShippedDotted, verdictNeighbourDotted)

	got, grounds, aerr = askVerdict(t, ctx, pool, tn.granted, verdictShippedModel, "cg-dod1", "v_get")
	require.NoError(t, aerr, "вердикт после снятия не вычислен — «не выполнилось», а не отказ")
	require.Equalf(t, relverdict.Deny, got,
		"строка каталога снята, а выдача продолжает действовать: снятие ресурса не доезжает "+
			"до вердикта (тип не объявлен моделью: %t)", grounds.TypeNotDeclared)
	// Ноль по ПРАВУ, а не по незнанию типа: блок типа модели на месте, снята
	// именно строка каталога. Без этого утверждения «Deny» выше зеленел бы и в
	// том случае, когда вердикт перестал понимать вопрос.
	require.Falsef(t, grounds.TypeNotDeclared,
		"отказ после снятия строки дан по основанию «типа нет в словаре модели» — это другой "+
			"отказ: модель типа %q знает, снята СТРОКА КАТАЛОГА, и различать их обязательно",
		verdictShippedModel)
	t.Logf("после снятия: исход=%v, тип не объявлен моделью=%t", got, grounds.TypeNotDeclared)

	// ЖИВОЙ СОСЕД В СНЯТОМ СОСТОЯНИИ — отказ выше сказан ИМЕННО о снятой строке.
	// Утверждение `TypeNotDeclared == false` выше говорит, что вердикт ПОНЯЛ
	// вопрос; оно не говорит, что вердикт кому-нибудь ещё отвечает «да» в этот
	// самый момент. Разные вопросы, и второй закрывается только соседом.
	nGot, nGrounds, nErr = askVerdict(t, ctx, pool, tn.granted, verdictNeighbourModel, "net-dod1", "v_get")
	require.NoError(t, nErr, "вердикт по соседу после снятия не вычислен")
	require.Equalf(t, relverdict.Allow, nGot,
		"снятие ресурса %q унесло с собой живого соседа %q (вердикт %v, тип не объявлен "+
			"моделью: %t): отказ выше тогда сказан не о снятой строке, а о цепи вердикта, "+
			"отвечающей отказом ВСЕМУ",
		verdictShippedDotted, verdictNeighbourDotted, nGot, nGrounds.TypeNotDeclared)
	t.Logf("живой сосед в снятом состоянии: %q → %v — отказ выше принадлежит снятой строке",
		verdictNeighbourDotted, nGot)

	// ── (3) ЗАВЕДЕНИЕ ПРИМЕНЕНИЕМ: вердикт восстанавливается ───────────────
	rep, err = applier.Apply(ctx, shippedManifest(t, verdictShippedModule, ""))
	require.NoError(t, err, "применение ПОЛНОГО манифеста модуля %q", verdictShippedModule)
	require.Truef(t, rep.Changed(), "заведение каталог не изменило (%s) — заводить было нечего", rep)
	t.Logf("заведение: %s", rep)
	require.NoError(t, snap.Refresh(ctx), "обновление снимка каталога")

	pairs = redeclareRole(t, ctx, pool, repo, snap,
		roleID, tn.userID, verdictShippedModule, verdictShippedRes)
	require.NotEmptyf(t, pairs,
		"строка заведена применением, а проекция по %q пуста: роль создалась бы без отказа, "+
			"и арендатор не получил бы НИЧЕГО", verdictShippedDotted)
	t.Logf("после заведения: тип %q → пар проекции %d, глаголы %v",
		verdictShippedDotted, len(pairs), verbsOf(pairs))

	got, grounds, aerr = askVerdict(t, ctx, pool, tn.granted, verdictShippedModel, "cg-dod1", "v_get")
	require.NoError(t, aerr, "вердикт после заведения не вычислен — «не выполнилось», а не отказ")
	require.Equalf(t, relverdict.Allow, got,
		"СКВОЗНОЙ ПУТЬ НЕ СОШЁЛСЯ: строка заведена применением (%s), пар проекции %d "+
			"(глаголы %v), выдача на месте — а вердикт даёт %v (тип не объявлен моделью: %t)",
		rep, len(pairs), verbsOf(pairs), got, grounds.TypeNotDeclared)
	t.Logf("сквозной путь СОШЁЛСЯ: применение → роль → выдача → вердикт = %v", got)

	// ── (4) ОТРИЦАНИЕ: субъект без выдачи права не получает ────────────────
	bare, bareGrounds, bareErr := askVerdict(t, ctx, pool, tn.bare, verdictShippedModel, "cg-dod1", "v_get")
	require.NoError(t, bareErr, "вердикт по субъекту без выдачи не вычислен")
	require.Equalf(t, relverdict.Deny, bare,
		"субъект БЕЗ выдачи получил %v (тип не объявлен моделью: %t) — утверждение «ненулевой "+
			"ответ» выше зеленело бы на вердикте, отвечающем «да» всем", bare, bareGrounds.TypeNotDeclared)

	// ── (5) НОЛЬ ОТЛИЧИМ ОТ «НЕ ВЫЧИСЛЕНО» ────────────────────────────────
	//
	// Отказ по ПРАВУ (п. 2 и 4) и отказ по НЕЗНАНИЮ ТИПА — разные ответы, и
	// вердикт обязан их различать: иначе опечатка в имени типа читается как «прав
	// не выдали» и ищется в правах (`relverdict.Asker.undeclaredType`).
	nosuch, nosuchGrounds, nosuchErr := askVerdict(t, ctx, pool,
		tn.granted, applierProbeModule+"_neverdeclared", "x-1", "v_get")
	require.NoError(t, nosuchErr, "вопрос о несуществующем типе обязан быть ОТВЕТОМ, а не ошибкой")
	require.Equal(t, relverdict.Deny, nosuch, "несуществующий тип обязан давать отказ")
	require.Truef(t, nosuchGrounds.TypeNotDeclared,
		"отказ по несуществующему типу не назвал своего основания — тогда «нет прав» и "+
			"«такого типа не бывает» отвечают одинаково, и различить их нечем")
	t.Logf("различимость нолей: по праву → Deny/тип объявлен; по незнанию типа → Deny/тип НЕ объявлен")
}

// TestDoD1_TypeUnknownToTheBuildReachesTheVerdictThroughTheComposedModel —
// ВТОРОЙ предмет: тип, объявленный ТОЛЬКО доставкой, доезжает до вердикта.
//
// # Что здесь установлено
//
// Тип, которого сборка не знает НИ ОДНИМ словарём, доезжает до ПРОЕКЦИИ (это
// закрыл #1816) И до ВЕРДИКТА (#1969). Второе звено — модель ПРОЦЕССА: она
// собирается из доставленных манифестов (`modelcompose.Compose`), судится
// допуском (`authzmodel.Admit`) и ставится (`authzmodel.Install`) до первого
// своего читателя; `relverdict` строит план вывода у `authzmodel.Shared()`, то
// есть у неё же.
//
// # Здесь стояла ГРАНИЦА — она снята, а не обойдена
//
// Прежняя редакция утверждала обратное: «модель вшита сборкой, применение
// манифеста блока не приносит», — и была верна на своей ревизии. Сегодня она
// ложна для процесса: композиция провязана в композиционном корне
// (`cmd/kacho-iam/serve.go` → `installComposedModel`, между чтением доставки и
// первым читателем модели). Ложной она оставалась ТОЛЬКО в этом харнессе —
// потому что харнесс модель не ставил вовсе, и `Shared()` отдавал вшитый канон.
// То есть проба измеряла не продукт, а собственную обстановку.
//
// Харнесс ставит модель ТЕМ ЖЕ путём и в том же порядке, каким её ставит старт
// (`testmain_test.go`, `installHarnessComposedModel`), и берёт её из ТОГО ЖЕ
// объявления ресурса, которое эта проба применяет к каталогу
// (`verdictAppliedResource`). Два объявления одного предмета разошлись бы молча:
// модель знала бы один набор действий, каталог другой, и вердикт отвечал бы
// отказом по действию, которое роль честно раздала.
//
// # Что утверждается
//
//  1. ПРОЕКЦИЯ ПОЛНА — предмет #1816: пустая проекция вернула бы состояние «роль
//     создалась, арендатор не получил ничего»;
//  2. ВЕРДИКТ РАЗРЕШАЕТ по выданному праву — предмет #1969, последняя миля
//     пункта 1 DoD эпика #1027;
//  3. ДВА ОТРИЦАНИЯ рядом, и каждое закрывает свой способ зазеленеть впустую:
//     субъект БЕЗ выдачи получает отказ (иначе п. 2 выполним вердиктом,
//     отвечающим «да» всем), а тип, которого не объявляет НИКТО — ни канон, ни
//     доставка, — получает отказ С НАЗВАННЫМ ОСНОВАНИЕМ (иначе п. 2 выполним
//     моделью, объявляющей типом что угодно).
//
// # Приёмка
//
// Сценарии `IAM-MB-1-06` (тип нового модуля доезжает до вердикта — дословный
// предикат снятия #1969) и `IAM-MB-1-08` (тип, которого не объявляет НИКТО, —
// отказ с основанием) приёмки
// `services/iam/docs/engineering/acceptance/model-composes-at-boot-from-delivered-manifests.md`.
// Её §9.3 предписывает эту переписку ТЕМ ЖЕ изменением и называет обе половины;
// здесь они не пересказываются.
func TestDoD1_TypeUnknownToTheBuildReachesTheVerdictThroughTheComposedModel(t *testing.T) {
	ctx, pool := catalogPool(t)
	catRepo := kachopg.NewCatalogRepo(pool)
	repo := kachopg.New(pool, nil)

	// КОНТРОЛЬ ПРЕДПОСЫЛКИ: сборка синтетического типа не знает. Впиши его
	// кто-нибудь в манифест дерева — и проба зеленела бы вхолостую, утверждая о
	// композиции на типе, который приехал бы и без неё.
	if _, known := authzmap.FGAObjectType(verdictAppliedDotted); known {
		t.Fatalf("сборка знает %q — предпосылка отпала, проба стала бы вакуумной",
			verdictAppliedDotted)
	}
	// Зеркало: поставляемого соседа сборка знает. Без него контроль выше зеленел
	// бы и на словаре, не знающем НИЧЕГО.
	if _, known := authzmap.FGAObjectType(verdictShippedDotted); !known {
		t.Fatalf("сборка не знает поставляемого соседа %q — контроль предпосылки беспредметен",
			verdictShippedDotted)
	}
	// КАНОН ОБРАЗА этого типа не объявляет — иначе «доехал через композицию»
	// зеленело бы на типе, который вшит и приехал бы сам.
	canonOnly, cerr := authzmodel.New(authzmodel.DSL)
	require.NoError(t, cerr, "канон образа не разобран")
	require.Falsef(t, canonOnly.DeclaresType(verdictAppliedModel),
		"канон образа УЖЕ объявляет %q — проба обязана брать тип, которого в каноне нет",
		verdictAppliedModel)

	// УСЛОВИЕ ПРОБЫ, а не её предмет: харнесс модель поставил. Спрашивается
	// отдельно и называется своими словами — иначе несозданное условие пришло бы
	// сюда отказом вердикта, то есть «не выполнилось» читалось бы как «красное»,
	// и чинить пошли бы `relverdict`, который ни при чём.
	plans, perr := authzmodel.Shared()
	require.NoError(t, perr, "модель процесса не отдалась")
	require.Truef(t, plans.DeclaresType(verdictAppliedModel),
		"УСЛОВИЕ НЕ СОЗДАНО: модель процесса не объявляет %q. Харнесс обязан ставить "+
			"собранную модель в TestMain (installHarnessComposedModel) — это обстановка "+
			"пробы, а не предмет её утверждения", verdictAppliedModel)

	census, err := seed.AssertCatalogParity(ctx, catRepo, seed.ImageAnchor())
	require.NoError(t, err, "страж паритета каталога")
	snap, err := catalog.NewSnapshot(census.Live, catRepo, nil, nil)
	require.NoError(t, err, "снимок каталога")

	tn := seedVerdictTenant(t, ctx, pool)

	// Применяется ТО ЖЕ объявление ресурса, из которого харнесс собрал модель.
	rep, err := applierOver(t, pool).Apply(ctx, probeManifest(verdictAppliedResource()))
	require.NoError(t, err, "применение манифеста с типом, которого сборка не знает")
	require.Truef(t, rep.Changed(), "применение каталог не изменило (%s) — заводить было нечего", rep)
	require.NoError(t, snap.Refresh(ctx), "обновление снимка каталога")
	t.Logf("применение: %s", rep)

	mods, res, verbs := liveCatalogCounts(t, ctx, pool)
	t.Logf("перепись каталога после применения: модулей %d, ресурсов %d, действий %d", mods, res, verbs)

	// (1) ПРОЕКЦИЯ ПОЛНА — предмет #1816.
	roleID, pairs := declareRole(t, ctx, pool, repo, snap,
		tn.accountID, tn.userID, applierProbeModule, verdictAppliedRes)
	require.NotEmptyf(t, pairs,
		"проекция по заведённому типу %q пуста: строки записаны, роль создалась без отказа, "+
			"а арендатор не получил бы НИЧЕГО — это дословно блокатор, названный эпиком #1027",
		verdictAppliedDotted)
	require.Lenf(t, pairs, len(verdictProbeVerbs),
		"проекция по %q неполна: объявлено глаголов %d, в проекции %d (%v)",
		verdictAppliedDotted, len(verdictProbeVerbs), len(pairs), verbsOf(pairs))
	t.Logf("проекция: тип %q → %q, пар %d, глаголы %v",
		verdictAppliedDotted, verdictAppliedModel, len(pairs), verbsOf(pairs))

	grantOnProject(t, ctx, pool, tn, "acb-dod1-applied", roleID, verdictAppliedModel, "alpha-dod1")

	// (2) ВЕРДИКТ РАЗРЕШАЕТ — предмет #1969.
	got, grounds, aerr := askVerdict(t, ctx, pool, tn.granted, verdictAppliedModel, "alpha-dod1", "v_get")
	require.NoErrorf(t, aerr,
		"вердикт по типу, объявленному только доставкой, НЕ ВЫЧИСЛЕН: %v. Это третий исход — "+
			"«не выполнилось», а не ответ: вызывающий не может отличить сбой от отказа", aerr)
	require.Falsef(t, grounds.TypeNotDeclared,
		"вердикт по %q отвечает «тип не объявлен моделью»: модель процесса собрана без блока "+
			"этого типа, то есть композиция до вердикта НЕ ДОЕХАЛА", verdictAppliedModel)
	require.Equalf(t, relverdict.Allow, got,
		"тип %q объявлен ТОЛЬКО манифестом, право на него выдано, а вердикт даёт %v — "+
			"последняя миля пункта 1 DoD эпика #1027 разомкнута", verdictAppliedModel, got)
	t.Logf("СКВОЗНОЙ ПУТЬ (#1969): манифест → каталог → проекция (пар %d, глаголы %v) → "+
		"модель процесса (собрана из доставки) → вердикт по %q = %v",
		len(pairs), verbsOf(pairs), verdictAppliedModel, got)

	// (3а) ОТРИЦАНИЕ: субъект БЕЗ выдачи. Без него «разрешение» выше выполнимо
	// вердиктом, отвечающим «да» всем.
	bare, bareGrounds, bareErr := askVerdict(t, ctx, pool, tn.bare, verdictAppliedModel, "alpha-dod1", "v_get")
	require.NoError(t, bareErr, "вердикт по субъекту без выдачи не вычислен")
	require.Equalf(t, relverdict.Deny, bare,
		"субъект БЕЗ выдачи получил право (тип не объявлен моделью=%t)", bareGrounds.TypeNotDeclared)

	// (3б) ЗАКОННЫЙ БЛИЗНЕЦ: тип, которого не объявляет НИКТО — ни канон, ни
	// доставка. Он обязан по-прежнему отвергаться, и отвергаться С ОСНОВАНИЕМ:
	// иначе «разрешение» выше выполнимо моделью, объявляющей типом что угодно, а
	// тихий отказ читался бы как «право не выдано» и искался бы в правах.
	const neverDeclared = applierProbeModule + "_neverdeclared"
	require.Falsef(t, plans.DeclaresType(neverDeclared),
		"близнец %q объявлен моделью — контроль беспредметен", neverDeclared)
	nosuch, nosuchGrounds, nosuchErr := askVerdict(t, ctx, pool, tn.granted, neverDeclared, "x-1", "v_get")
	require.NoError(t, nosuchErr, "вопрос о несуществующем типе обязан быть ОТВЕТОМ, а не ошибкой")
	require.Equal(t, relverdict.Deny, nosuch, "тип, которого не объявляет никто, получил право")
	require.Truef(t, nosuchGrounds.TypeNotDeclared,
		"ТИХИЙ ОТКАЗ по %q: основание не названо — тогда «право не выдано» и «модель этого "+
			"типа не знает» отвечают одинаково", neverDeclared)
	t.Logf("близнецы: объявленный доставкой %q → %v; не объявленный никем %q → %v/тип не объявлен=%t",
		verdictAppliedModel, got, neverDeclared, nosuch, nosuchGrounds.TypeNotDeclared)
}
