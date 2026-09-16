// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// service_manifest_seed_integration_test.go — манифест СЛУЖБЫ объявляет свою
// группу и её выдачу, и применитель приводит к объявленному живую базу
// (приёмка MRW-1, стадия S1; задача kaname#106).
//
// # Почему против живой базы, поднятой ВСЕМИ миграциями дерева
//
// Строка группы `module-relation-writers` и её выдача `fga_writer` живы на
// каждой установке из свода (`0001_initial.sql`), а якорь кластера переименован
// следом (`20260906214500`). Значит идентификатор живой выдачи выведен при
// ПРЕЖНЕМ написании якоря, и выражение применителя даёт другое значение — на
// синтетической строке, выведенной при живом якоре, это не воспроизводится
// (§2.2 приёмки). Утверждение о состоянии группы («ровно одна») на такой базе
// истинно и при применителе, который раздела `seed.groups` не читает вовсе,
// поэтому пишущая ветвь утверждается на базе, из которой строка СНЯТА (§2.10):
// у каждой оси названы обе стороны.
//
// # Порядок снятия строк диктует схема
//
// Строку группы, числящуюся субъектом выдачи, прямое удаление не берёт
// (`groups_subject_ref_before_delete_trg`, код 23503) — выдача снимается
// первой, дочерний субъект и ведомость эмитированного уходят каскадом ключей.
// Это единственный порядок, которым схема допускает первый факт, а не второй
// факт мира.
package pg_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/moduleseed"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/servicemanifest"
)

// Строки свода, о которых утверждают сценарии. Идентификаторы — СИСТЕМНЫХ строк,
// одинаковые на каждой установке по построению свода (`0001_initial.sql:3489`,
// `:3196`); адресовать ими снаружи нечего.
const (
	writersGroupName   = "module-relation-writers"
	writersGroupSeedID = "grp258e6bbe9bbe45568"
	writersGrantSeedID = "acb9e920fb038c7e4f74"
	writersRelation    = "fga_writer"
	systemAccountName  = "system"
	clusterAnchor      = "cluster_root"
)

// deliveredComputeProbe — доставленный манифест модуля со вступлением в группу
// службы. Синтетический: манифестов платформы в дереве службы нет by
// construction (§5 приёмки). Аккаунт назван живым написанием `system`.
const deliveredComputeProbe = `
apiVersion: iam/v1
module: compute
resources: []
seed:
  serviceAccounts:
    - name: kacho-compute
      account: system
      description: "Module SA: kacho-compute (probe of the seed order)"
  joins:
    - serviceAccount: {account: system, name: kacho-compute}
      group: {account: system, name: module-relation-writers}
      why: "проба порядка применения посева службы"
`

// deliveredVpcRelationProbe — выдача ОТНОШЕНИЕМ служебной записи: близнец
// MRW-20 по виду получателя (MRW-21).
const deliveredVpcRelationProbe = `
apiVersion: iam/v1
module: vpc
resources: []
seed:
  serviceAccounts:
    - name: kacho-vpc
      account: system
      description: "Module SA: kacho-vpc (probe of the subject form)"
  accessBindings:
    - subjects:
        - {type: serviceAccount, name: kacho-vpc}
      grantedRelation: system_viewer
      scopeType: iam.cluster
      scopeId: cluster_root
      target: allInScope
`

// deliveredVpcRoleProbe — выдача РОЛЬЮ служебной записи (MRW-14): роль —
// системная строка свода `iam.account.admin`, живая и назначаемая на кластере.
const deliveredVpcRoleProbe = `
apiVersion: iam/v1
module: vpc
resources: []
seed:
  serviceAccounts:
    - name: kacho-vpc
      account: system
      description: "Module SA: kacho-vpc (probe of the role natural key)"
  accessBindings:
    - subjects:
        - {type: serviceAccount, name: kacho-vpc}
      roleId: rol6307d201bf18e6763
      scopeType: iam.cluster
      scopeId: cluster_root
      target: allInScope
`

func seedPool(ctx context.Context, t *testing.T) *pgxpool.Pool {
	t.Helper()
	if testing.Short() {
		t.Skip("нужен Postgres: свойство утверждается прогоном против живой базы")
	}
	pool, err := pgxpool.New(ctx, pgtest.NewDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	return pool
}

func ownManifest(t *testing.T) *manifest.Manifest {
	t.Helper()
	m, err := servicemanifest.Load()
	require.NoError(t, err, "встроенный манифест службы не разобран — вердикт беспредметен")
	return m
}

func loadProbe(t *testing.T, doc string) *manifest.Manifest {
	t.Helper()
	m, err := manifest.Load([]byte(doc))
	require.NoError(t, err, "проба подаёт манифест, который разбор не принимает — вердикт беспредметен")
	return m
}

func applySeed(ctx context.Context, t *testing.T, pool *pgxpool.Pool,
	own *manifest.Manifest, delivered ...*manifest.Manifest,
) moduleseed.Census {
	t.Helper()
	census, err := moduleseed.NewApplier(kanamepg.NewModuleSeedWriteRepo(pool)).Apply(ctx, own, delivered)
	t.Logf("перепись применения: %s", census)
	require.NoError(t, err, "применитель посева отказал")
	return census
}

// writersGroup — живая строка группы службы: идентификатор и назначение.
func writersGroup(ctx context.Context, t *testing.T, pool *pgxpool.Pool) (id, description string, count int) {
	t.Helper()
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*), coalesce(min(g.id), ''), coalesce(min(g.description), '')
		  FROM kaname.groups g JOIN kaname.accounts a ON a.id = g.account_id
		 WHERE a.name = $1 AND g.name = $2`, systemAccountName, writersGroupName).
		Scan(&count, &id, &description))
	return id, description, count
}

// writersGrant — живая активная выдача отношения группе службы на якоре кластера.
func writersGrant(ctx context.Context, t *testing.T, pool *pgxpool.Pool, groupID string) (id string, count int) {
	t.Helper()
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*), coalesce(min(id), '')
		  FROM kaname.access_bindings
		 WHERE subject_type = 'group' AND subject_id = $1 AND granted_relation = $2
		   AND resource_type = 'cluster' AND resource_id = $3 AND revoked_at IS NULL`,
		groupID, writersRelation, clusterAnchor).Scan(&count, &id))
	return id, count
}

func writersJournalRows(ctx context.Context, t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM kaname.fga_outbox
		 WHERE event_type = 'fga.tuple.write' AND payload ->> 'relation' = $1`, writersRelation).Scan(&n))
	return n
}

func groupMembers(ctx context.Context, t *testing.T, pool *pgxpool.Pool, groupID string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.group_members WHERE group_id = $1`, groupID).Scan(&n))
	return n
}

// removeWritersGrant снимает живую выдачу свода: дочерний субъект и ведомость
// эмитированного уходят каскадом ключей.
func removeWritersGrant(ctx context.Context, t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	tag, err := pool.Exec(ctx, `DELETE FROM kaname.access_bindings WHERE id = $1`, writersGrantSeedID)
	require.NoError(t, err)
	require.EqualValues(t, 1, tag.RowsAffected(), "живой выдачи свода %s в базе не оказалось — дом не построен", writersGrantSeedID)
}

// removeWritersGroup снимает строку группы свода — ПОСЛЕ её выдачи, иначе
// триггер ссылки отвергает удаление.
func removeWritersGroup(ctx context.Context, t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	removeWritersGrant(ctx, t, pool)
	tag, err := pool.Exec(ctx, `DELETE FROM kaname.groups WHERE id = $1`, writersGroupSeedID)
	require.NoError(t, err)
	require.EqualValues(t, 1, tag.RowsAffected(), "живой группы свода %s в базе не оказалось — дом не построен", writersGroupSeedID)
}

// TestMRW01_CleanInstallSeedsTheGroupAndItsGrant — чистая установка без
// доставки: группа и её выдача заведены объявлением, членов ноль.
func TestMRW01_CleanInstallSeedsTheGroupAndItsGrant(t *testing.T) {
	ctx := context.Background()
	pool := seedPool(ctx, t)
	own := ownManifest(t)

	census := applySeed(ctx, t, pool, own)
	require.NotNil(t, census.Own, "свой манифест не применён")
	require.Equal(t, 1, census.Own.DeclaredGroups, "манифест службы не объявляет группу")
	require.Equal(t, 1, census.Own.DeclaredGrants, "манифест службы не объявляет выдачу")

	groupID, description, groups := writersGroup(ctx, t, pool)
	require.Equal(t, 1, groups, "групп %s в аккаунте %s не ровно одна", writersGroupName, systemAccountName)
	require.Equal(t, own.Seed.Groups[0].Description, description, "назначение живой строки не равно объявленному")

	grantID, grants := writersGrant(ctx, t, pool, groupID)
	require.Equal(t, 1, grants, "активных выдач %s группе на cluster:%s не ровно одна", writersRelation, clusterAnchor)
	var isSystem, protected bool
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT is_system, deletion_protection FROM kaname.access_bindings WHERE id = $1`, grantID).
		Scan(&isSystem, &protected))
	require.True(t, isSystem, "выдача не помечена системной")
	require.True(t, protected, "выдача не защищена от удаления")

	require.Zero(t, groupMembers(ctx, t, pool, groupID),
		"у группы есть члены при отсутствии доставки — их некому было завести")
	t.Logf("перепись: группа %s · выдача %s · членов 0", groupID, grantID)
}

// TestMRW02_SecondStartWritesNothing — повторный старт: перепись «групп 0/1 ·
// выдач 0/1», идентификаторы прежние, журнал прав не растёт.
func TestMRW02_SecondStartWritesNothing(t *testing.T) {
	ctx := context.Background()
	pool := seedPool(ctx, t)
	own := ownManifest(t)

	first := applySeed(ctx, t, pool, own)
	require.NotNil(t, first.Own)
	declared, _ := first.Totals()
	require.NotZero(t, declared, "свой манифест не объявил ни одной строки — повтор утверждать не о чем")
	groupBefore, _, _ := writersGroup(ctx, t, pool)
	grantBefore, _ := writersGrant(ctx, t, pool, groupBefore)
	journalBefore := writersJournalRows(ctx, t, pool)

	second := applySeed(ctx, t, pool, own)
	require.NotNil(t, second.Own)
	require.Contains(t, second.Own.String(), "групп 0/1")
	require.Contains(t, second.Own.String(), "выдач 0/1")

	groupAfter, _, _ := writersGroup(ctx, t, pool)
	grantAfter, _ := writersGrant(ctx, t, pool, groupAfter)
	require.Equal(t, groupBefore, groupAfter, "идентификатор группы сменился на повторном старте")
	require.Equal(t, grantBefore, grantAfter, "идентификатор выдачи сменился на повторном старте")
	require.Equal(t, journalBefore, writersJournalRows(ctx, t, pool), "повторный старт дописал журнал прав")
}

// TestMRW03_GrantSeededUnderThePreviousAnchorIsAdoptedNotRefused — живая выдача
// свода выведена при прежнем написании якоря; применитель её усыновляет по
// естественному ключу: без второй строки, без отказа, без строки журнала.
func TestMRW03_GrantSeededUnderThePreviousAnchorIsAdoptedNotRefused(t *testing.T) {
	ctx := context.Background()
	pool := seedPool(ctx, t)
	own := ownManifest(t)

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ дома: живая строка свода на месте и несёт свой
	// идентификатор; выражение применителя на живом якоре даёт ДРУГОЙ.
	liveID, live := writersGrant(ctx, t, pool, writersGroupSeedID)
	require.Equal(t, 1, live, "живой выдачи свода нет — дом не построен")
	require.Equal(t, writersGrantSeedID, liveID)
	var derived string
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT 'acb' || substr(md5('system-grant:' || $1::text || ':' || $2::text
		                           || ':cluster:' || $3::text), 1, 17)`,
		domain.FGASubjectRef("group", writersGroupSeedID), writersRelation, clusterAnchor).Scan(&derived))
	require.NotEqual(t, liveID, derived,
		"выражение применителя совпало с живым идентификатором — переименование якоря "+
			"перестало различать их, и проба утверждает не о том")
	var emittedBefore int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.access_binding_emitted_tuples WHERE binding_id = $1`, liveID).Scan(&emittedBefore))
	journalBefore := writersJournalRows(ctx, t, pool)

	census := applySeed(ctx, t, pool, own)
	require.NotNil(t, census.Own)
	require.Equal(t, 1, census.Own.DeclaredGrants, "манифест службы не объявляет выдачу — усыновлять нечего")
	require.Zero(t, census.Own.WrittenGrants, "применитель записал выдачу поверх живой")

	afterID, after := writersGrant(ctx, t, pool, writersGroupSeedID)
	require.Equal(t, 1, after, "выдач стало не одна")
	require.Equal(t, writersGrantSeedID, afterID, "идентификатор живой выдачи изменился")
	var emittedAfter int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.access_binding_emitted_tuples WHERE binding_id = $1`, liveID).Scan(&emittedAfter))
	require.Equal(t, emittedBefore, emittedAfter, "ведомость эмитированного изменилась")
	require.Equal(t, journalBefore, writersJournalRows(ctx, t, pool), "журнал прав получил строку — кортеж перезаписан")
	t.Logf("перепись: живая %s · выведенная %s · строк выдачи 1 · журнал без изменений", liveID, derived)
}

// TestMRW04_OwnGroupIsSeededBeforeTheDeliveredJoin — на базе БЕЗ строки свода
// вступление доставленного модуля ложится: группу завёл свой манифест раньше.
func TestMRW04_OwnGroupIsSeededBeforeTheDeliveredJoin(t *testing.T) {
	ctx := context.Background()
	pool := seedPool(ctx, t)
	removeWritersGroup(ctx, t, pool)

	census := applySeed(ctx, t, pool, ownManifest(t), loadProbe(t, deliveredComputeProbe))
	require.NotNil(t, census.Own, "свой манифест не применён")
	require.Equal(t, 1, census.Manifests, "доставленных манифестов не один")
	require.Len(t, census.Reports, 1)
	require.Equal(t, 1, census.Reports[0].WrittenJoins, "вступление compute не записано")

	groupID, _, groups := writersGroup(ctx, t, pool)
	require.Equal(t, 1, groups)
	require.Equal(t, 1, groupMembers(ctx, t, pool, groupID), "членство модуля в группе службы не легло")
}

// TestMRW05_StandaloneInstallSeedsTheGroupWithoutDelivery — отрицательный
// близнец MRW-04 по одной оси: доставки нет вовсе.
func TestMRW05_StandaloneInstallSeedsTheGroupWithoutDelivery(t *testing.T) {
	ctx := context.Background()
	pool := seedPool(ctx, t)
	removeWritersGroup(ctx, t, pool)
	own := ownManifest(t)

	census := applySeed(ctx, t, pool, own)
	require.NotNil(t, census.Own)
	require.Zero(t, census.Manifests, "доставленных манифестов ноль, а перепись считает иначе")
	require.Contains(t, census.String(), "доставлено 0")

	groupID, description, groups := writersGroup(ctx, t, pool)
	require.Equal(t, 1, groups, "группа службы не заведена применителем")
	require.Equal(t, own.Seed.Groups[0].Description, description)
	_, grants := writersGrant(ctx, t, pool, groupID)
	require.Equal(t, 1, grants, "выдача группе не заведена применителем")
	require.Zero(t, groupMembers(ctx, t, pool, groupID), "членов ноль — от отсутствия доставки")
}

// TestMRW19_MissingGrantIsSeededByTheApplier — ось «строка выдачи есть /
// строки нет», обе стороны: снята — «записано 1», журнал и ведомость по одной
// НОВОЙ строке; на месте — «записано 0», журнал без строки.
func TestMRW19_MissingGrantIsSeededByTheApplier(t *testing.T) {
	ctx := context.Background()
	own := ownManifest(t)

	t.Run("строка выдачи снята — применитель её заводит", func(t *testing.T) {
		pool := seedPool(ctx, t)
		removeWritersGrant(ctx, t, pool)
		journalBefore := writersJournalRows(ctx, t, pool)

		census := applySeed(ctx, t, pool, own)
		require.NotNil(t, census.Own)
		require.Equal(t, 1, census.Own.WrittenGrants, "перепись выдач не печатает «записано 1»")

		grantID, grants := writersGrant(ctx, t, pool, writersGroupSeedID)
		require.Equal(t, 1, grants)
		require.Equal(t, journalBefore+1, writersJournalRows(ctx, t, pool), "журнал прав не получил ровно одну новую строку")
		var emitted int
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM kaname.access_binding_emitted_tuples WHERE binding_id = $1`, grantID).Scan(&emitted))
		require.Equal(t, 1, emitted, "ведомость эмитированного не получила ровно одну строку")
	})

	t.Run("строка выдачи на месте — записано 0", func(t *testing.T) {
		pool := seedPool(ctx, t)
		journalBefore := writersJournalRows(ctx, t, pool)
		census := applySeed(ctx, t, pool, own)
		require.NotNil(t, census.Own)
		require.Equal(t, 1, census.Own.DeclaredGrants)
		require.Zero(t, census.Own.WrittenGrants)
		require.Equal(t, journalBefore, writersJournalRows(ctx, t, pool))
	})
}

// TestMRW20_GroupRecipientSubjectCarriesTheMembershipSigil — форма субъекта у
// получателя-ГРУППЫ берётся у канона: сигил членства в ведомости эмитированного,
// в журнале прав и в производной идентификатора.
func TestMRW20_GroupRecipientSubjectCarriesTheMembershipSigil(t *testing.T) {
	ctx := context.Background()
	pool := seedPool(ctx, t)
	removeWritersGrant(ctx, t, pool)
	journalBefore := writersJournalRows(ctx, t, pool)

	census := applySeed(ctx, t, pool, ownManifest(t))
	require.NotNil(t, census.Own)
	require.Equal(t, 1, census.Own.WrittenGrants, "выдача не записана — о форме утверждать не о чем")

	grantID, grants := writersGrant(ctx, t, pool, writersGroupSeedID)
	require.Equal(t, 1, grants)
	require.Equal(t, journalBefore+1, writersJournalRows(ctx, t, pool))

	canon := domain.FGASubjectRef("group", writersGroupSeedID)
	bare := "group:" + writersGroupSeedID

	var emittedUser string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT fga_user FROM kaname.access_binding_emitted_tuples WHERE binding_id = $1`, grantID).Scan(&emittedUser))
	require.Equal(t, canon, emittedUser, "ведомость эмитированного несёт не форму канона")

	var journalUser string
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT payload ->> 'user' FROM kaname.fga_outbox
		 WHERE event_type = 'fga.tuple.write' AND payload ->> 'relation' = $1
		 ORDER BY id DESC LIMIT 1`, writersRelation).Scan(&journalUser))
	require.Equal(t, canon, journalUser, "журнал прав несёт не того субъекта, что ведомость")

	var withSigil, withoutSigil string
	const derive = `SELECT 'acb' || substr(md5('system-grant:' || $1::text || ':' || $2::text || ':cluster:' || $3::text), 1, 17)`
	require.NoError(t, pool.QueryRow(ctx, derive, canon, writersRelation, clusterAnchor).Scan(&withSigil))
	require.NoError(t, pool.QueryRow(ctx, derive, bare, writersRelation, clusterAnchor).Scan(&withoutSigil))
	require.Equal(t, withSigil, grantID, "идентификатор выдачи выведен не из формы с сигилом")
	require.NotEqual(t, withoutSigil, grantID, "идентификатор выдачи выведен из голого объекта группы")

	// Свод пишет для этой же выдачи тот же литерал (`0001_initial.sql:3162`).
	require.Equal(t, "group:"+writersGroupSeedID+"#member", emittedUser,
		"применитель и свод адресуют разных субъектов одной выдачи")
	t.Logf("перепись: субъект %s · идентификатор %s", emittedUser, grantID)
}

// TestMRW21_ServiceAccountRecipientSubjectHasNoSigil — положительный близнец
// MRW-20: у служебной записи форма остаётся без сигила и совпадает с каноном.
func TestMRW21_ServiceAccountRecipientSubjectHasNoSigil(t *testing.T) {
	ctx := context.Background()
	pool := seedPool(ctx, t)

	census := applySeed(ctx, t, pool, nil, loadProbe(t, deliveredVpcRelationProbe))
	require.Len(t, census.Reports, 1)
	require.Equal(t, 1, census.Reports[0].WrittenGrants, "выдача служебной записи не записана — дом «выдачи нет» не построен")

	var saID string
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT sa.id FROM kaname.service_accounts sa JOIN kaname.accounts a ON a.id = sa.account_id
		 WHERE a.name = $1 AND sa.name = 'kacho-vpc'`, systemAccountName).Scan(&saID))
	canon := domain.FGASubjectRef("service_account", saID)

	var emittedUser string
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT t.fga_user FROM kaname.access_binding_emitted_tuples t
		  JOIN kaname.access_bindings b ON b.id = t.binding_id
		 WHERE b.subject_type = 'service_account' AND b.subject_id = $1 AND b.granted_relation = 'system_viewer'`,
		saID).Scan(&emittedUser))
	require.Equal(t, "service_account:"+saID, emittedUser)
	require.Equal(t, canon, emittedUser, "форма служебной записи разошлась с каноном")

	var journalUser string
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT payload ->> 'user' FROM kaname.fga_outbox
		 WHERE event_type = 'fga.tuple.write' AND payload ->> 'relation' = 'system_viewer'
		 ORDER BY id DESC LIMIT 1`).Scan(&journalUser))
	require.Equal(t, canon, journalUser)
}

// TestMRW23_MissingGroupIsSeededByTheApplier — ось «строка группы есть /
// строки нет», обе стороны: снята — «записано 1» и НОВЫЙ идентификатор; на
// месте — «записано 0» и прежний.
func TestMRW23_MissingGroupIsSeededByTheApplier(t *testing.T) {
	ctx := context.Background()
	own := ownManifest(t)

	t.Run("строка группы снята — применитель её заводит", func(t *testing.T) {
		pool := seedPool(ctx, t)
		removeWritersGroup(ctx, t, pool)

		census := applySeed(ctx, t, pool, own)
		require.NotNil(t, census.Own)
		require.Equal(t, 1, census.Own.WrittenGroups, "перепись групп не печатает «записано 1»")

		groupID, description, groups := writersGroup(ctx, t, pool)
		require.Equal(t, 1, groups)
		require.Equal(t, own.Seed.Groups[0].Description, description)
		require.NotEqual(t, writersGroupSeedID, groupID,
			"идентификатор совпал со снятым — «записано 1» означало бы восстановление прежней строки")
		require.True(t, ids.IsValid(groupID, domain.PrefixGroup),
			"идентификатор %q не отчеканен генератором продукта", groupID)
	})

	t.Run("строка группы на месте — записано 0", func(t *testing.T) {
		pool := seedPool(ctx, t)
		census := applySeed(ctx, t, pool, own)
		require.NotNil(t, census.Own)
		require.Equal(t, 1, census.Own.DeclaredGroups)
		require.Zero(t, census.Own.WrittenGroups)
		groupID, _, _ := writersGroup(ctx, t, pool)
		require.Equal(t, writersGroupSeedID, groupID, "идентификатор живой группы изменился")
	})
}

// TestMRW14_RoleGrantIsAdoptedByItsNaturalKey — выдача РОЛЬЮ усыновляется своим
// естественным ключом (`access_bindings_active_grant_uniq`), обе стороны оси.
func TestMRW14_RoleGrantIsAdoptedByItsNaturalKey(t *testing.T) {
	ctx := context.Background()

	t.Run("строка с другим идентификатором есть — усыновляется", func(t *testing.T) {
		pool := seedPool(ctx, t)
		// Личность заводится первым применением; выдача роли кладётся рукой с
		// СЛУЧАЙНЫМ идентификатором — как её завёл бы публичный путь создания.
		applySeed(ctx, t, pool, nil, loadProbe(t, deliveredVpcRelationProbe))
		var saID string
		require.NoError(t, pool.QueryRow(ctx, `
			SELECT sa.id FROM kaname.service_accounts sa JOIN kaname.accounts a ON a.id = sa.account_id
			 WHERE a.name = $1 AND sa.name = 'kacho-vpc'`, systemAccountName).Scan(&saID))
		foreignID := ids.NewID(domain.PrefixAccessBinding)
		_, err := pool.Exec(ctx, `
			INSERT INTO kaname.access_bindings (id, subject_type, subject_id, role_id, is_system,
			    resource_type, resource_id, status, deletion_protection, granted_by_user_id)
			VALUES ($1, 'service_account', $2, 'rol6307d201bf18e6763', true, 'cluster', $3, 'ACTIVE', true, '')`,
			foreignID, saID, clusterAnchor)
		require.NoError(t, err, "дом не построен: строка выдачи роли не легла")

		census := applySeed(ctx, t, pool, nil, loadProbe(t, deliveredVpcRoleProbe))
		require.Len(t, census.Reports, 1)
		require.Zero(t, census.Reports[0].WrittenGrants, "применитель записал вторую строку выдачи роли")
		var rows int
		require.NoError(t, pool.QueryRow(ctx, `
			SELECT count(*) FROM kaname.access_bindings
			 WHERE subject_type = 'service_account' AND subject_id = $1 AND role_id = 'rol6307d201bf18e6763'
			   AND revoked_at IS NULL`, saID).Scan(&rows))
		require.Equal(t, 1, rows, "строк выдачи роли не одна")
	})

	t.Run("строки нет — заводится и считается записанной", func(t *testing.T) {
		pool := seedPool(ctx, t)
		census := applySeed(ctx, t, pool, nil, loadProbe(t, deliveredVpcRoleProbe))
		require.Len(t, census.Reports, 1)
		require.Equal(t, 1, census.Reports[0].WrittenGrants, "выдача роли не записана")
	})
}
