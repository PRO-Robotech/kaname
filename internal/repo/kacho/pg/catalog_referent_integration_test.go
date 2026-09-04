// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// catalog_referent_integration_test.go — у сегментов правила роли есть РЕФЕРЕНТ.
//
// Приёмка `services/iam/docs/engineering/acceptance/rule-segments-have-a-referent.md`
// (APPROVED круга 3), сценарии IAM-CT-1-02, -03, -05, -06, -07, -08, -09, -10,
// -11, -12, -14. Задача продукта #1030.
//
// # Что здесь утверждается и чего здесь НЕТ
//
// Утверждается ССЫЛОЧНАЯ ЦЕЛОСТНОСТЬ и её наблюдаемые следствия: сегмент правила,
// не имеющий строки каталога, отвергается ОПЕРАТОРОМ вставки; снятие строки
// каталога при живой выдаче отвергается; после переселения — проходит, и выдач по
// паре ноль. О транспорте, операции и правах эти пробы не говорят НИЧЕГО: они
// подают вход слоем репозитория, и их зелёный этого не покрывает.
//
// # Фикстура НЕ отменяет немедленность — это условие годности, а не аккуратность
//
// Приёмка §5.0 (требование Т12): в дереве есть фикстуры, открывающие транзакцию
// оператором `SET CONSTRAINTS ALL DEFERRED`, и он накрывает ключ, объявленный
// `DEFERRABLE INITIALLY IMMEDIATE` (измерено, проба `P12` приёмки). Под таким
// оператором отказ приходит не из оператора вставки, а с коммита; подсказка
// писателя не ставится, и проба наблюдала бы общий текст вместо названного
// сегмента — то есть проверяла бы ДРУГУЮ форму ключа, чем та, что работает у
// арендатора. Ни одна фикстура этого файла такого оператора не открывает, и
// помощники ниже заведены СВОИ именно поэтому.

import (
	"context"
	"errors"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/internal/pgtest"
	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	kachorepo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// catalogPool — своя база на пробу, БЕЗ отмены немедленности (см. шапку).
func catalogPool(t *testing.T) (context.Context, *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	return ctx, pool
}

// catalogRole — роль в собственном аккаунте. Своя, а не общая: правило роли
// ссылается на строку каталога, и общая роль связала бы две пробы одной строкой.
func catalogRole(t *testing.T, ctx context.Context, pool *pgxpool.Pool, suffix string) domain.RoleID {
	t.Helper()
	uid := domain.UserID(ids.NewID(domain.PrefixUser))
	accID := domain.AccountID(ids.NewID(domain.PrefixAccount))
	rid := domain.RoleID(ids.NewID(domain.PrefixRole))

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `
		INSERT INTO users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, $3, $4, $5, 'ACTIVE')`,
		string(uid), string(accID), "ext-ct1-"+suffix+"-"+string(uid),
		"u-ct1-"+suffix+"@example.com", "CT1 "+suffix)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `
		INSERT INTO accounts (id, name, owner_user_id, labels)
		VALUES ($1, $2, $3, '{}'::jsonb)`,
		string(accID), "ct1-acc-"+suffix+"-"+string(accID)[len(accID)-6:], string(uid))
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `
		INSERT INTO roles (id, account_id, name, description, permissions)
		VALUES ($1, $2, $3, $4, '["iam.users.*.read"]'::jsonb)`,
		string(rid), string(accID), "ct1_"+suffix, "catalog referent "+suffix)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
	return rid
}

// writeRuleRefs — вызов писателя проекции правила ЧЕРЕЗ ПОРТ, в своей транзакции.
// Своего SQL записи проба не держит: писатель у таблицы один (требование Т5), и
// второй оператор записи здесь сделал бы пробу вторым писателем.
func writeRuleRefs(t *testing.T, ctx context.Context, repo kachorepo.Repository,
	roleID domain.RoleID, refs []domain.RoleRuleRef) error {
	t.Helper()
	w, err := repo.Writer(ctx)
	require.NoError(t, err, "открыть транзакцию записи")
	committed := false
	defer func() {
		if !committed {
			_ = w.Rollback(ctx)
		}
	}()
	if rerr := w.RolesW().ReplaceRuleRefs(ctx, roleID, refs); rerr != nil {
		return rerr
	}
	if cerr := w.Commit(ctx); cerr != nil {
		return cerr
	}
	committed = true
	return nil
}

// liveCatalogCounts — перепись живых строк каталога. Печатается КАЖДОЙ пробой,
// которая на каталог опирается: «ноль находок» обязано быть отличимо от «ноль
// прочитанного».
func liveCatalogCounts(t *testing.T, ctx context.Context, pool *pgxpool.Pool) (mods, res, verbs int) {
	t.Helper()
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.catalog_module WHERE live`).Scan(&mods))
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.catalog_resource WHERE live`).Scan(&res))
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.catalog_verb WHERE live`).Scan(&verbs))
	return mods, res, verbs
}

// pgCode — SQLSTATE и имя ограничения из отказа сервера.
func pgCode(err error) (code, constraint string) {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code, pgErr.ConstraintName
	}
	return "", ""
}

// retireResource — административный путь снятия ресурса: сперва его ГЛАГОЛЫ,
// затем сама строка ресурса. У каждого шага `retired_at` и `live` ОДНИМ
// оператором (требование Т3).
//
// # Почему шага стало ДВА (#1878)
//
// Ключ `catalog_verb_resource_live_fk` держит порядок «глаголы → ресурсы» так
// же, как `catalog_resource_module_live_fk` держит «ресурсы → модуль»: снятие
// ресурса при живом глаголе отвергается `23503`. Прежде такой ход проходил
// МОЛЧА, оставляя живые глаголы под снятым ресурсом, — это и было предметом
// #1868. Порядок здесь выписан, но держит его не он: держит ключ, а выписанный
// порядок — форма административного глагола. Тот же порядок и по той же причине
// у `withdrawModule` уровнем выше.
//
// # Что это меняет для вызывающих
//
// Отказ по-прежнему приходит НА ОПЕРАТОРЕ и по-прежнему `23503` — но может
// прийти на ПЕРВОМ из двух: правило, назвавшее глагол, отвергает его снятие
// ключом `role_rule_ref_verb_fk` раньше, чем дело дойдёт до строки ресурса.
// Сценарии, утверждающие имя ограничения, обязаны это учитывать; те, что
// утверждают SQLSTATE, не меняются.
//
// Вход «снять ресурс, не трогая глаголы» этим путём подать больше НЕЛЬЗЯ — он
// подаётся своим оператором в `verb_liveness_key_integration_test.go`, где он и
// есть предмет: проба утверждает, что такой вход отвергается.
func retireResource(ctx context.Context, q interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}, module, resource, reason string) error {
	if err := retireVerbsOf(ctx, q, module, resource, reason); err != nil {
		return err
	}
	_, err := q.Exec(ctx, `
		UPDATE kacho_iam.catalog_resource
		   SET retired_at = now(), live = false, retired_reason = $3
		 WHERE module = $1 AND resource = $2`, module, resource, reason)
	return err
}

// deferCatalogKeys — отложить ИМЕННО ТРИ ключа каталога, а не `ALL`.
//
// Ключей три, а не два, как называет приёмка §5.3: проекция ГЛАГОЛОВ
// (`role_verb`) тоже ссылается на живую строку каталога, и без неё снятие
// отказало бы на своём операторе даже под отложенностью двух остальных.
// Расхождение с текстом приёмки названо в отчёте задачи, а не подогнано молча.
//
// `ALL` здесь запрещён намеренно: он накрыл бы и ключи, к предмету отношения не
// имеющие, и — что важнее — превратил бы немедленную форму в отложенную для
// ВСЕЙ транзакции, то есть сделал бы фикстуру снисходительнее продукта (Т12).
const deferCatalogKeys = `SET CONSTRAINTS ` +
	`kacho_iam.role_rule_ref_res_fk, ` +
	`kacho_iam.role_rule_ref_verb_fk, ` +
	`kacho_iam.role_verb_type_fk DEFERRED`

// requireNoRefsYet — предпосылка сценариев снятия: на этот ресурс НЕ ссылается
// ни одно правило, посеянное миграциями.
//
// Проверяется запросом, а не предполагается, и это не педантизм: обратное
// заполнение миграции кладёт строки проекции за КАЖДУЮ системную роль, поэтому у
// большинства типов каталога ссылки есть уже на чистой базе (замер на этой
// ревизии: из 27 живых ресурсов свободны 10). Сценарий «снятие отвергается»,
// поставленный на занятом ресурсе, отвергался бы ЧУЖОЙ строкой и зеленел бы,
// даже если бы своя не записалась вовсе.
func requireNoRefsYet(t *testing.T, ctx context.Context, pool *pgxpool.Pool, module, resource string) {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM kacho_iam.role_rule_ref WHERE module = $1 AND resource = $2`,
		module, resource).Scan(&n))
	require.Zerof(t, n, "предпосылка сценария: правил на %s.%s нет — найдено %d",
		module, resource, n)
}

// ─────────────────────────────────────────────────────────────────────────────
// IAM-CT-1-04 — посев согласен с литералом, в ОБЕ стороны.

func TestIAMCT104_CatalogSeedMatchesTheLiteralBothWays(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx, pool := catalogPool(t)

	wantRes := map[string]bool{}
	wantVerb := map[string]bool{}
	wantTier := map[string]bool{}
	wantMod := map[string]bool{}
	for _, m := range authzmap.CatalogSeedModules() {
		wantMod[m] = true
	}
	for _, e := range authzmap.Catalog() {
		wantRes[e.Module+"."+e.Resource] = true
		fgaType, ok := authzmap.ObjectType(e.Module, e.Resource)
		require.True(t, ok, "тип каталога без формы модели: %s.%s", e.Module, e.Resource)
		for _, v := range authzmap.VerbsOfType(fgaType) {
			wantVerb[e.Module+"."+e.Resource+"."+v] = true
		}
	}
	// Половин у словаря глаголов ДВЕ (#1863), и сверяются они порознь: слитая
	// сверка молчала бы на строке, перетёкшей из одной в другую, — а перетекание
	// в ПООБЪЕКТНУЮ и есть возврат снятого отношения.
	for _, v := range authzmap.CatalogSeedVerbs() {
		if v.PerObject {
			continue
		}
		wantTier[v.Module+"."+v.Resource+"."+v.Verb] = true
	}
	require.NotEmpty(t, wantRes, "литерал пуст — утверждение равенства было бы вакуумным")
	require.NotEmpty(t, wantTier, "ярусная половина литерала пуста — вторая сверка была бы вакуумной")

	gotRes := readSet(t, ctx, pool,
		`SELECT dotted FROM kacho_iam.catalog_resource WHERE live`)
	gotVerb := readSet(t, ctx, pool,
		`SELECT module || '.' || resource || '.' || verb FROM kacho_iam.catalog_verb
		  WHERE live AND per_object`)
	gotTier := readSet(t, ctx, pool,
		`SELECT module || '.' || resource || '.' || verb FROM kacho_iam.catalog_verb
		  WHERE live AND NOT per_object`)
	gotMod := readSet(t, ctx, pool,
		`SELECT module FROM kacho_iam.catalog_module WHERE live`)

	t.Logf("осмотрено: литерал — модулей %d, ресурсов %d, пообъектных пар %d, ярусных %d; "+
		"посев — модулей %d, ресурсов %d, пообъектных пар %d, ярусных %d",
		len(wantMod), len(wantRes), len(wantVerb), len(wantTier),
		len(gotMod), len(gotRes), len(gotVerb), len(gotTier))

	require.Equal(t, keysOf(wantMod), keysOf(gotMod), "catalog_module ≠ authzmap.CatalogSeedModules()")
	require.Equal(t, keysOf(wantRes), keysOf(gotRes), "catalog_resource ≠ authzmap.Catalog()")
	require.Equal(t, keysOf(wantVerb), keysOf(gotVerb),
		"пообъектная половина catalog_verb ≠ typeVerbRelations")
	require.Equal(t, keysOf(wantTier), keysOf(gotTier),
		"ярусная половина catalog_verb ≠ ярусной половине CatalogSeedVerbs()")
}

// ─────────────────────────────────────────────────────────────────────────────
// IAM-CT-1-02 / -07 — подстановка `verb IS NULL`: ключ РЕСУРСА сохраняется.
//
// Ради этой пары ключей два, а не один: под ОДНИМ составным ключом
// `MATCH SIMPLE` снимает проверку ЦЕЛИКОМ, когда любой столбец NULL, и правило,
// называющее несуществующий ресурс, принимается успешно (измерено приёмкой, Н1).

func TestIAMCT107_AnchorRuleStillChecksTheResource(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx, pool := catalogPool(t)
	repo := kachopg.New(pool, nil)
	m, r, v := liveCatalogCounts(t, ctx, pool)
	t.Logf("осмотрено живых строк каталога: модулей %d, ресурсов %d, пар %d", m, r, v)
	require.NotZero(t, r, "каталог пуст — обе половины пробы были бы вакуумны")

	// Положительный контроль (IAM-CT-1-02): якорь при ЖИВОМ ресурсе проходит.
	live := catalogRole(t, ctx, pool, "ct102")
	require.NoError(t, writeRuleRefs(t, ctx, repo, live,
		[]domain.RoleRuleRef{{Module: "vpc", Resource: "network"}}),
		"якорь при живом ресурсе обязан проходить — иначе отрицание ниже "+
			"зеленело бы на схеме, где не проходит ничто")

	var anchors int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.role_rule_ref WHERE role_id = $1 AND verb IS NULL`,
		string(live)).Scan(&anchors))
	require.Equal(t, 1, anchors, "якорь обязан лечь строкой с verb IS NULL")

	// Отрицание (IAM-CT-1-07): тот же якорь при ресурсе ВНЕ каталога.
	// Токен грамматику `ruleResRe` проходит — иначе отказ пришёл бы от
	// валидатора формы, и о ключе проба не сказала бы ничего.
	require.Regexp(t, `^[a-z][a-zA-Z0-9_-]*$`, "nonesuch",
		"токен обязан проходить грамматику правила, иначе проверяется не ключ")
	absent := catalogRole(t, ctx, pool, "ct107")
	err := writeRuleRefs(t, ctx, repo, absent,
		[]domain.RoleRuleRef{{Module: "vpc", Resource: "nonesuch"}})
	require.Error(t, err, "якорь на ресурсе вне каталога обязан отвергаться — "+
		"при ОДНОМ составном ключе он проходит успешно (Н1 приёмки)")
	require.ErrorIs(t, err, iamerr.ErrFailedPrecondition,
		"полоса ключа — предусловие на существующий сегмент, а не поломка службы")
	require.Contains(t, err.Error(), "resources",
		"отказ обязан называть ПОЛЕ — его производит ветвь по имени ограничения")
	require.Contains(t, err.Error(), "nonesuch",
		"отказ обязан называть ТОКЕН — его ставит подсказка писателя на своём операторе")

	var rows int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.role_rule_ref WHERE role_id = $1`,
		string(absent)).Scan(&rows))
	require.Zero(t, rows, "отвергнутое правило не оставляет строк проекции")
}

// ─────────────────────────────────────────────────────────────────────────────
// IAM-CT-1-05 / -06 — ресурс вне каталога и чужой глагол.

func TestIAMCT105_ResourceOutsideTheCatalogIsRefused(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx, pool := catalogPool(t)
	repo := kachopg.New(pool, nil)

	// Положительный контроль (IAM-CT-1-01): живая пара проходит.
	ok := catalogRole(t, ctx, pool, "ct101")
	require.NoError(t, writeRuleRefs(t, ctx, repo, ok,
		[]domain.RoleRuleRef{{Module: "vpc", Resource: "network", Verb: "get"}}))

	bad := catalogRole(t, ctx, pool, "ct105")
	err := writeRuleRefs(t, ctx, repo, bad,
		[]domain.RoleRuleRef{{Module: "vpc", Resource: "nonesuch", Verb: "get"}})
	require.Error(t, err)
	require.ErrorIs(t, err, iamerr.ErrFailedPrecondition)
	require.Contains(t, err.Error(), "resources")
	require.Contains(t, err.Error(), "nonesuch")
	// Ограничение сервера через границу репозитория НЕ проходит: `mapErr`
	// оборачивает отказ в признак контракта и снимает *pgconn.PgError вместе с
	// его текстом (защита от разведки схемы). Утверждать его надо там, где он
	// есть, — на уровне SQL (пробы -08/-09/-11), а не требовать от края того,
	// чего тот не производит.
	t.Logf("отказ классифицирован признаком контракта: %v", err)
}

func TestIAMCT106_VerbOutsideTheResourceIsRefused(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx, pool := catalogPool(t)
	repo := kachopg.New(pool, nil)

	// Положительный контроль: тот же ресурс со СВОИМ глаголом проходит.
	ok := catalogRole(t, ctx, pool, "ct106ok")
	require.NoError(t, writeRuleRefs(t, ctx, repo, ok,
		[]domain.RoleRuleRef{{Module: "vpc", Resource: "network", Verb: "get"}}))

	// `frobnicate` выбран потому, что грамматику `ruleVerbRe` он проходит:
	// негатив, отвергаемый формой токена, о ключе не утверждает ничего.
	require.Regexp(t, `^[a-z][a-zA-Z0-9_-]*$`, "frobnicate")
	bad := catalogRole(t, ctx, pool, "ct106")
	err := writeRuleRefs(t, ctx, repo, bad,
		[]domain.RoleRuleRef{{Module: "vpc", Resource: "network", Verb: "frobnicate"}})
	require.Error(t, err)
	require.ErrorIs(t, err, iamerr.ErrFailedPrecondition)
	require.Contains(t, err.Error(), "verbs")
	require.Contains(t, err.Error(), "frobnicate")
}

// ─────────────────────────────────────────────────────────────────────────────
// IAM-CT-1-08 / -03 / -09 — ОБЕ стороны снятия.

func TestIAMCT108_RetiringAResourceWithALiveGrantIsRefused(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx, pool := catalogPool(t)
	repo := kachopg.New(pool, nil)

	requireNoRefsYet(t, ctx, pool, "vpc", "networkInterface")
	role := catalogRole(t, ctx, pool, "ct108")
	require.NoError(t, writeRuleRefs(t, ctx, repo, role,
		[]domain.RoleRuleRef{{Module: "vpc", Resource: "networkInterface", Verb: "get"}}))

	err := retireResource(ctx, pool, "vpc", "networkInterface", "проба IAM-CT-1-08")
	require.Error(t, err, "снятие ресурса при живой выдаче обязано отвергаться")
	code, constraint := pgCode(err)
	t.Logf("снятие отвергнуто: SQLSTATE %s, ограничение %q", code, constraint)
	require.Equal(t, "23503", code)
	require.NotEmpty(t, constraint, "имя ограничения обязано приходить с отказом")

	var live bool
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT live FROM kacho_iam.catalog_resource WHERE module='vpc' AND resource='networkInterface'`).
		Scan(&live))
	require.True(t, live, "транзакция снятия не применилась: строка обязана остаться живой")

	var kept int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.role_rule_ref WHERE role_id = $1`, string(role)).Scan(&kept))
	require.Equal(t, 1, kept, "роль своих строк не теряет")
}

// IAM-CT-1-03 — положительный контроль к -08: снятие ресурса БЕЗ выдач проходит.
// Без него «снятие отвергается» зеленело бы на схеме, где снятие невозможно вовсе.
func TestIAMCT103_RetiringAnUnreferencedResourcePasses(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx, pool := catalogPool(t)

	var refs int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM kacho_iam.role_rule_ref
		 WHERE module='vpc' AND resource='cidrGroup'`).Scan(&refs))
	require.Zero(t, refs, "предпосылка сценария: правил на этот ресурс нет — "+
		"проверено запросом, а не предположено")

	require.NoError(t, retireResource(ctx, pool, "vpc", "cidrGroup", "проба IAM-CT-1-03"))

	var live bool
	var retiredAt *time.Time
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT live, retired_at FROM kacho_iam.catalog_resource
		 WHERE module='vpc' AND resource='cidrGroup'`).Scan(&live, &retiredAt))
	require.False(t, live)
	require.NotNil(t, retiredAt)
}

// IAM-CT-1-09 / -14 — переселение и снятие ОДНОЙ транзакцией, с ДВУМЯ контролями.
func TestIAMCT109_RelocateThenRetireInOneTransaction(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx, pool := catalogPool(t)
	repo := kachopg.New(pool, nil)

	requireNoRefsYet(t, ctx, pool, "storage", "volumes")
	role := catalogRole(t, ctx, pool, "ct109")
	require.NoError(t, writeRuleRefs(t, ctx, repo, role,
		[]domain.RoleRuleRef{{Module: "storage", Resource: "volumes", Verb: "get"}}))
	// Выдача — вторая сторона того же правила: переселять предстоит ЕЁ, а строку
	// объявления снимает административный путь. Без неё утверждение «сирот ровно
	// столько, сколько переселено» было бы вакуумным.
	require.NoError(t, writeRoleVerbs(t, ctx, repo, role,
		[]domain.RoleVerb{{ObjectType: "storage.volumes", Verb: "get"}}))

	// Контроль в ОДНУ сторону (§5.3 -14): без явного отказа от немедленности
	// порядок «снять, затем переселить» невозможен — отказ приходит на первом же
	// операторе.
	txA, err := pool.Begin(ctx)
	require.NoError(t, err)
	rerr := retireResource(ctx, txA, "storage", "volumes", "контроль немедленности")
	require.Error(t, rerr, "без SET CONSTRAINTS снятие обязано отказать НА ОПЕРАТОРЕ")
	codeA, _ := pgCode(rerr)
	require.Equal(t, "23503", codeA)
	require.NoError(t, txA.Rollback(ctx))

	// Контроль в ДРУГУЮ сторону (§5.3 -14): отложенность ОТКЛАДЫВАЕТ проверку,
	// а не отменяет её — та же транзакция без переселения отказывает на коммите.
	txB, err := pool.Begin(ctx)
	require.NoError(t, err)
	_, err = txB.Exec(ctx,
		deferCatalogKeys)
	require.NoError(t, err)
	require.NoError(t, retireResource(ctx, txB, "storage", "volumes", "контроль отложенности"))
	cerr := txB.Commit(ctx)
	require.Error(t, cerr, "отложенность откладывает проверку, а не снимает её")
	codeB, _ := pgCode(cerr)
	require.Equal(t, "23503", codeB)

	var stillLive bool
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT live FROM kacho_iam.catalog_resource WHERE module='storage' AND resource='volumes'`).
		Scan(&stillLive))
	require.True(t, stillLive, "отказ на коммите оставляет строку каталога живой")

	// Сам сценарий: снятие И переселение в одной транзакции.
	txC, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = txC.Rollback(ctx) }()
	_, err = txC.Exec(ctx,
		deferCatalogKeys)
	require.NoError(t, err)
	require.NoError(t, retireResource(ctx, txC, "storage", "volumes", "снятие тома"))
	moved := relocateGrants(t, ctx, txC, "storage", "volumes", "снятие тома")
	require.Positive(t, moved, "переселять было нечего — сценарий вакуумен")
	require.NoError(t, txC.Commit(ctx))

	var refs, orphans, verbRows int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM kacho_iam.role_rule_ref WHERE module='storage' AND resource='volumes'`).
		Scan(&refs))
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM kacho_iam.role_grant_orphan
		 WHERE object_type='storage.volumes' AND source='role_verb'`).
		Scan(&orphans))
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM kacho_iam.role_verb WHERE object_type='storage.volumes'`).
		Scan(&verbRows))
	t.Logf("переселено %d; осталось строк проекции правила %d, выдачи %d, сирот %d",
		moved, refs, verbRows, orphans)
	require.Zero(t, refs)
	require.Zero(t, verbRows, "строк выдачи по снятой паре обязано быть ноль")
	require.Equal(t, moved, orphans, "сирот ровно столько, сколько переселено")

	var reason string
	var at time.Time
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT reason, orphaned_at FROM kacho_iam.role_grant_orphan
		 WHERE object_type='storage.volumes' AND source='role_verb' LIMIT 1`).Scan(&reason, &at))
	require.NotEmpty(t, reason, "каждая сирота несёт причину")
	require.False(t, at.IsZero(), "каждая сирота несёт отметку времени")

	// Авторский текст правила остаётся у роли дословно — снятие отбирает
	// ВЕРДИКТ, а не написанное арендатором.
	var rules string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT rules::text FROM kacho_iam.roles WHERE id = $1`, string(role)).Scan(&rules))
	t.Logf("правила роли после снятия: %s", rules)
}

// relocateGrants — административное переселение выдач по снятой паре.
func relocateGrants(t *testing.T, ctx context.Context, tx pgx.Tx, module, resource, reason string) int {
	t.Helper()
	dotted := module + "." + resource
	tag, err := tx.Exec(ctx, `
		INSERT INTO kacho_iam.role_grant_orphan (role_id, object_type, verb, source, reason)
		SELECT role_id, object_type, verb, 'role_verb', $2
		  FROM kacho_iam.role_verb WHERE object_type = $1
		ON CONFLICT (role_id, object_type, verb, source, cause)
		DO UPDATE SET reason = EXCLUDED.reason, orphaned_at = now()`, dotted, reason)
	require.NoError(t, err)
	moved := int(tag.RowsAffected())
	_, err = tx.Exec(ctx, `DELETE FROM kacho_iam.role_verb WHERE object_type = $1`, dotted)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `
		DELETE FROM kacho_iam.role_rule_ref WHERE module = $1 AND resource = $2`, module, resource)
	require.NoError(t, err)
	return moved
}

// ─────────────────────────────────────────────────────────────────────────────
// IAM-CT-1-11 — правка только `retired_at` отвергается проверкой живости.

func TestIAMCT111_RetiredAtWithoutLiveIsRefused(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx, pool := catalogPool(t)

	// Положительный контроль: оба столбца одним оператором — проходит.
	require.NoError(t, retireResource(ctx, pool, "vpc", "addressPool", "контроль -11"))

	_, err := pool.Exec(ctx, `
		UPDATE kacho_iam.catalog_resource SET retired_at = now()
		 WHERE module='vpc' AND resource='gateway'`)
	require.Error(t, err, "правка только retired_at обязана отвергаться")
	code, constraint := pgCode(err)
	t.Logf("отказ проверки живости: SQLSTATE %s, ограничение %q", code, constraint)
	require.Equal(t, "23514", code)
	// Имя ограничения — ПОЛНОЕ, а не подстрока: под `Contains(constraint,
	// "live")` подходят и соседние ограничения той же таблицы
	// (`catalog_resource_live_uk`, `catalog_resource_dotted_live_uk`), поэтому
	// прежнее утверждение было слабее сценария IAM-MW-1-06 и молчало бы, ответь
	// на этот вход другой ключ. Верное имя подтверждено прогоном.
	require.Equal(t, "catalog_resource_live_matches_retired", constraint)

	var live bool
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT live FROM kacho_iam.catalog_resource WHERE module='vpc' AND resource='gateway'`).
		Scan(&live))
	require.True(t, live, "строка обязана остаться живой")
}

// ─────────────────────────────────────────────────────────────────────────────
// IAM-CT-1-10 — снятый ресурс несёт преемника СТРОКОЙ каталога.

func TestIAMCT110_RetiredResourceCarriesItsSuccessor(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx, pool := catalogPool(t)

	retired := domain.RetiredTypes()
	require.NotEmpty(t, retired, "снятых типов ноль — утверждение было бы вакуумным")

	live := map[string]bool{}
	for _, e := range authzmap.Catalog() {
		live[e.Module+"."+e.Resource] = true
	}

	for _, dotted := range retired {
		var isLive bool
		var successor *string
		err := pool.QueryRow(ctx, `
			SELECT live, superseded_by FROM kacho_iam.catalog_resource WHERE dotted = $1`,
			dotted).Scan(&isLive, &successor)
		require.NoErrorf(t, err, "снятый тип %s обязан существовать СТРОКОЙ каталога", dotted)
		require.Falsef(t, isLive, "%s обязан быть снятым", dotted)
		require.NotNilf(t, successor, "%s обязан нести преемника", dotted)
		require.Truef(t, live[*successor],
			"преемник %s типа %s обязан быть ЖИВЫМ ключом каталога", *successor, dotted)
		t.Logf("снятый %s → преемник %s", dotted, *successor)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// IAM-CT-1-12 — конкуренция: висячей выдачи нет ни при каком чередовании.

func TestIAMCT112_ConcurrentRetireAndGrantLeaveNoDanglingRow(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	for _, retireLeads := range []bool{true, false} {
		name := "выдача первой"
		if retireLeads {
			name = "снятие первым"
		}
		t.Run(name, func(t *testing.T) {
			ctx, pool := catalogPool(t)
			repo := kachopg.New(pool, nil)
			requireNoRefsYet(t, ctx, pool, "compute", "placementGroup")
			role := catalogRole(t, ctx, pool, "ct112")

			// Чередование задаётся СИГНАЛОМ, а не паузой: пауза даёт порядок,
			// который зависит от загрузки машины, и подпись сценария («снятие
			// первым») тогда описывает не то, что произошло. Ведущая транзакция
			// исполняет свой оператор, сообщает об этом и только потом коммитится.
			led := make(chan struct{})
			var retireErr, grantErr error
			var wg sync.WaitGroup
			wg.Add(2)

			retire := func(lead bool) {
				defer wg.Done()
				if !lead {
					<-led
				}
				tx, err := pool.Begin(ctx)
				if err != nil {
					retireErr = err
					return
				}
				if rerr := retireResource(ctx, tx, "compute", "placementGroup", "конкуренция"); rerr != nil {
					retireErr = rerr
					_ = tx.Rollback(ctx)
					if lead {
						close(led)
					}
					return
				}
				if lead {
					close(led)
					// Ведущая держит строку под замком, пока ведомая в него
					// упирается: без этого «ждёт коммита ведущей» не проверяется.
					time.Sleep(300 * time.Millisecond)
				}
				retireErr = tx.Commit(ctx)
			}
			grant := func(lead bool) {
				defer wg.Done()
				if !lead {
					<-led
				}
				grantErr = writeRuleRefs(t, ctx, repo, role,
					[]domain.RoleRuleRef{{Module: "compute", Resource: "placementGroup", Verb: "get"}})
				if lead {
					close(led)
				}
			}

			go retire(retireLeads)
			go grant(!retireLeads)
			wg.Wait()

			t.Logf("исход: снятие=%v выдача=%v", retireErr, grantErr)
			require.Truef(t, retireErr != nil || grantErr != nil,
				"обе транзакции прошли — висячая выдача возможна")
			require.Falsef(t, retireErr != nil && grantErr != nil,
				"обе транзакции отказали — ни одна не выиграла, чередование потеряно")
			if retireLeads {
				require.NoError(t, retireErr, "ведущее снятие обязано выиграть")
				require.Error(t, grantErr, "ведомая выдача обязана получить отказ ключа")
				require.ErrorIs(t, grantErr, iamerr.ErrFailedPrecondition)
			} else {
				require.NoError(t, grantErr, "ведущая выдача обязана выиграть")
				require.Error(t, retireErr, "ведомое снятие обязано получить 23503")
				code, _ := pgCode(retireErr)
				require.Equal(t, "23503", code)
			}

			dangling := countDangling(t, ctx, pool)
			require.Zerof(t, dangling,
				"строк проекции, ссылающихся на снятое, обязано быть ноль (найдено %d)", dangling)
		})
	}
}

// countDangling — строки проекции правила, чей ресурс в каталоге не жив.
// Утверждается ИСХОД (висячих нет), а не то, какая транзакция выиграла.
func countDangling(t *testing.T, ctx context.Context, pool *pgxpool.Pool) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM kacho_iam.role_rule_ref rr
		 WHERE NOT EXISTS (
		       SELECT 1 FROM kacho_iam.catalog_resource cr
		        WHERE cr.module = rr.module AND cr.resource = rr.resource AND cr.live)`).Scan(&n))
	return n
}

// ─────────────────────────────────────────────────────────────────────────────
// вспомогательное чтение множеств

func readSet(t *testing.T, ctx context.Context, pool *pgxpool.Pool, q string) map[string]bool {
	t.Helper()
	rows, err := pool.Query(ctx, q)
	require.NoError(t, err)
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var s string
		require.NoError(t, rows.Scan(&s))
		out[s] = true
	}
	require.NoError(t, rows.Err())
	return out
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ─────────────────────────────────────────────────────────────────────────────
// ИНЪЕКЦИИ ФОРМЫ (§7 приёмки) — обязательные, а не примерные.
//
// Решение «ключей два» и решение «фикстура не отменяет немедленность» — это
// утверждения о ПОВЕДЕНИИ ДВИЖКА и о годности проб. Утверждать их прозой нельзя:
// обе формы компилируются, обе принимаются DDL, и различие видно только прогоном.

// TestIAMCT107_InjectionOneCompositeKeyLetsTheAnchorThrough — ради чего ключей
// два.
//
// Схема собирается СИНТЕТИЧЕСКАЯ, в своей схеме базы: вернуть один ключ в
// продуктовую миграцию нельзя (её правка снимала бы то самое свойство, которое
// проба доказывает), а инъекция обязана ронять только проверяемое.
func TestIAMCT107_InjectionOneCompositeKeyLetsTheAnchorThrough(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx, pool := catalogPool(t)

	_, err := pool.Exec(ctx, `
		CREATE SCHEMA inj;
		CREATE TABLE inj.cat_res (
		  module text NOT NULL, resource text NOT NULL, live boolean NOT NULL DEFAULT true,
		  PRIMARY KEY (module, resource), UNIQUE (module, resource, live));
		CREATE TABLE inj.cat_verb (
		  module text NOT NULL, resource text NOT NULL, verb text NOT NULL,
		  live boolean NOT NULL DEFAULT true,
		  PRIMARY KEY (module, resource, verb), UNIQUE (module, resource, verb, live),
		  FOREIGN KEY (module, resource) REFERENCES inj.cat_res (module, resource));
		INSERT INTO inj.cat_res (module, resource) VALUES ('vpc', 'network');
		INSERT INTO inj.cat_verb (module, resource, verb) VALUES ('vpc', 'network', 'get');

		-- ОДИН составной ключ, как просило тело задачи #1030.
		CREATE TABLE inj.rule_one (
		  module text NOT NULL, resource text NOT NULL, verb text,
		  live boolean NOT NULL DEFAULT true,
		  FOREIGN KEY (module, resource, verb, live)
		    REFERENCES inj.cat_verb (module, resource, verb, live));

		-- ДВА ключа, как решила приёмка.
		CREATE TABLE inj.rule_two (
		  module text NOT NULL, resource text NOT NULL, verb text,
		  live boolean NOT NULL DEFAULT true,
		  CONSTRAINT inj_res_fk FOREIGN KEY (module, resource, live)
		    REFERENCES inj.cat_res (module, resource, live),
		  CONSTRAINT inj_verb_fk FOREIGN KEY (module, resource, verb, live)
		    REFERENCES inj.cat_verb (module, resource, verb, live));`)
	require.NoError(t, err)

	// Положительный контроль: якорь при ЖИВОМ ресурсе проходит под ОБЕИМИ формами.
	_, err = pool.Exec(ctx,
		`INSERT INTO inj.rule_one (module, resource, verb) VALUES ('vpc','network',NULL)`)
	require.NoError(t, err, "законный якорь обязан проходить — иначе отрицание ниже вакуумно")
	_, err = pool.Exec(ctx,
		`INSERT INTO inj.rule_two (module, resource, verb) VALUES ('vpc','network',NULL)`)
	require.NoError(t, err)

	// ИНЪЕКЦИЯ: якорь на ресурсе ВНЕ каталога.
	_, oneErr := pool.Exec(ctx,
		`INSERT INTO inj.rule_one (module, resource, verb) VALUES ('vpc','nonesuch',NULL)`)
	_, twoErr := pool.Exec(ctx,
		`INSERT INTO inj.rule_two (module, resource, verb) VALUES ('vpc','nonesuch',NULL)`)

	t.Logf("один ключ: %v; два ключа: %v", oneErr, twoErr)
	require.NoError(t, oneErr, "ПОД ОДНИМ КЛЮЧОМ строка обязана ВСТАВИТЬСЯ: MATCH SIMPLE "+
		"снимает проверку целиком, когда любой столбец ключа NULL. Если здесь отказ — "+
		"довод §0.2 Н1 приёмки неверен, и решение «ключей два» подлежит пересмотру")
	require.Error(t, twoErr, "под ДВУМЯ ключами тот же вход обязан отвергаться ключом РЕСУРСА")
	code, constraint := pgCode(twoErr)
	require.Equal(t, "23503", code)
	require.Equal(t, "inj_res_fk", constraint,
		"отвергать обязан ключ РЕСУРСА, а не глагола: на якоре ключ глагола пропускается")
}

// TestIAMCT112_InjectionFixtureThatDefersEverythingHidesTheSegment — требование
// Т12: фикстура, отменяющая немедленность, делает пробу СНИСХОДИТЕЛЬНЕЕ продукта.
//
// Проба не «проверяет оператор SET CONSTRAINTS» — она показывает ЦЕНУ его
// появления в фикстуре: отказ переезжает с оператора на коммит, подсказка
// писателя не ставится, и сценарий -05 наблюдал бы общий текст вместо названного
// сегмента. Без этого показа требование Т12 осталось бы утверждением.
func TestIAMCT112_InjectionFixtureThatDefersEverythingHidesTheSegment(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx, pool := catalogPool(t)
	repo := kachopg.New(pool, nil)
	role := catalogRole(t, ctx, pool, "ct112inj")

	// Контроль — тот же вход БЕЗ отмены немедленности: отказ называет сегмент.
	strict := writeRuleRefs(t, ctx, repo, role,
		[]domain.RoleRuleRef{{Module: "vpc", Resource: "nonesuch", Verb: "get"}})
	require.Error(t, strict)
	require.Contains(t, strict.Error(), "nonesuch",
		"при немедленной форме писатель держит тот самый сегмент — токен обязан быть назван")

	// ИНЪЕКЦИЯ — та же запись в транзакции, открытой `SET CONSTRAINTS ALL DEFERRED`.
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `SET CONSTRAINTS ALL DEFERRED`)
	require.NoError(t, err)
	_, insErr := tx.Exec(ctx, `
		INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb)
		VALUES ($1, 'vpc', 'nonesuch', 'get')`, string(role))
	require.NoError(t, insErr, "ПОД `SET CONSTRAINTS ALL DEFERRED` оператор обязан ПРОЙТИ: "+
		"оператор накрывает и ключ, объявленный INITIALLY IMMEDIATE. Если здесь отказ — "+
		"предпосылка требования Т12 неверна, и гейт фикстур подлежит снятию вместе с ним")
	commitErr := tx.Commit(ctx)
	require.Error(t, commitErr, "отказ обязан прийти на КОММИТЕ")
	code, _ := pgCode(commitErr)
	require.Equal(t, "23503", code)
	t.Logf("немедленно: %v", strict)
	t.Logf("под отменой немедленности отказ приезжает с коммита: %v", commitErr)
	require.NotContains(t, commitErr.Error(), "nonesuch",
		"вот цена: на коммите подсказки писателя нет, и назвать сегмент нечем — "+
			"проба, идущая по такой фикстуре, проверяет ДРУГУЮ форму ключа, чем та, "+
			"что работает у арендатора")
}
