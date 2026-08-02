// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// operator_dead_fanout_integration_test.go — гейт на снятие МЁРТВОГО веера
// служебной учётки оператора сети, и — отдельным утверждением — на сохранность
// того, что у неё ЖИВО.
//
// # Что было снято и почему это не изменило ни одного доступа
//
// Роль `module.vpc_operator_sa` объявляла четыре правила
// (`vpc.subnetses`, `vpc.networks`, `vpc.network_interfaces`, `iam.projectses`).
// Ни одно из четырёх имён закрытая таблица типов не несёт, поэтому
// материализация, спросив таблицу и не получив типа, не эмитила НИ ОДНОГО
// кортежа («a typo'd type never grants», reconcile/tuples.go). Отказ верный и
// молчаливый — и именно молчаливость делала объявление похожим на действующую
// выдачу.
//
// Веер был мёртв по ЧЕТЫРЁМ независимым основаниям, каждое проверено отдельно:
//
//  1. имена не разрешаются закрытой таблицей (контроль в обе стороны —
//     TestSeedResolvabilityPredicate_HasAControlBothWays);
//  2. каскад `viewer … or system_viewer from cluster`, ради которого веер
//     задумывался, УДАЛЁН из модели — fga_model.fga говорит это прямо на типах
//     `account` и `project`;
//  3. страница видимости аккаунтов/проектов не несёт кластерного пола вовсе:
//     `visible = viewer ∨ v_list` пообъектно (api/account/list.go);
//  4. эмиттер привязки: роль С правилами эмитит ТОЛЬКО иерархический
//     родительский указатель и НИ ОДНОГО кортежа доступа
//     (access_binding/tuples.go, buildBindingTuples).
//
// # Почему снята РОЛЬ целиком, а не только её правила
//
// Основание — четвёртое из перечисленных, и оно же ловушка. `buildBindingTuples`
// ветвится на `len(role.Rules) > 0`: роль С правилами не эмитит кортежей
// доступа, а роль БЕЗ правил уходит в легаси-ветку и эмитит ЯРУСНЫЕ отношения на
// якоре области привязки. Снять правила, оставив строки прав, значило бы
// перевести роль в легаси-режим и ВЫДАТЬ `viewer@cluster`, которого до правки не
// было, — то есть выдать новое право под видом снятия мёртвого. Поэтому уходят
// вместе правила, права, привязка и сама роль.
//
// # Что НЕ снято и снято быть не может
//
// Кластерный кортеж `system_viewer@cluster:cluster_kacho_root` (посев 0010)
// ОСТАЁТСЯ. Он был посеян ради каскада из пункта 2, но с тех пор приобрёл
// ВТОРОГО, действующего читателя, и это записано в дереве прямым текстом:
// миграция 0014 не сеет оператору system_viewer именно потому, что «он уже
// держит его из 0010», а `authzguard.SystemViewerFloor` гейтит на этом отношении
// READ-RPC внутреннего листенера; vpc отдельно гейтит на нём
// `InternalNetworkService/GetNetwork` (чтение инфра-чувствительного vrf_id),
// называя потребителем именно оператора сети. Снятие кортежа было бы снятием
// ЖИВОГО права. Второе утверждение файла держит это свойство, чтобы следующая
// уборка не приняла кортеж за остаток снятого веера.
package pg_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/seed"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmap"
)

// Детерминированные выражения идентичности оператора — те же, что в посеве 0009
// и 0010, чтобы проба пинила ИМЕННО его строки, а не похожие.
const (
	operatorSVAExpr  = `'sva' || substr(md5('kacho-vpc-operator'), 1, 17)`
	operatorRoleExpr = `'rol' || substr(md5('module.vpc_operator_sa'), 1, 17)`
)

// resolvableTypesReachableBySubject — ЕДИНЫЙ путь запроса, которым проба
// спрашивает «какие типы объектов материализуются этому субъекту»: ACTIVE-
// привязки субъекта → роли → селекторы → объявленные типы, оставляя лишь те,
// что закрытая таблица РАЗРЕШАЕТ.
//
// Один и тот же путь обслуживает и отрицание (оператор), и положительный
// контроль (живой принципал). Разные запросы для двух половин дали бы «ноль» из
// опечатки в запросе, неотличимый от «ноль» по существу.
func resolvableTypesReachableBySubject(
	t *testing.T, ctx context.Context, pool *pgxpool.Pool, subjectID string,
) (resolvable, declared []string) {
	t.Helper()
	rows, err := pool.Query(ctx,
		`SELECT DISTINCT unnest(rrs.object_types)
		   FROM kacho_iam.access_bindings b
		   JOIN kacho_iam.role_rule_selectors rrs ON rrs.role_id = b.role_id
		  WHERE b.status = 'ACTIVE' AND b.subject_id = $1
		  ORDER BY 1`, subjectID)
	require.NoError(t, err)
	defer rows.Close()
	for rows.Next() {
		var dotted string
		require.NoError(t, rows.Scan(&dotted))
		declared = append(declared, dotted)
		if _, ok := authzmap.FGAObjectType(dotted); ok {
			resolvable = append(resolvable, dotted)
		}
	}
	require.NoError(t, rows.Err())
	return resolvable, declared
}

func scalarString(t *testing.T, ctx context.Context, pool *pgxpool.Pool, expr string) string {
	t.Helper()
	var v string
	require.NoError(t, pool.QueryRow(ctx, `SELECT `+expr).Scan(&v))
	return v
}

func scalarInt(t *testing.T, ctx context.Context, pool *pgxpool.Pool, q string, args ...any) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx, q, args...).Scan(&n))
	return n
}

// TestOperatorFanout_RetiredAndGrantsNothing — оператор сети не достижим ни
// одним материализующим селектором, а тот же путь запроса на ЖИВОМ принципале
// отвечает «да».
//
// Отрицание в одиночку зеленеет сильнее всего именно тогда, когда сломано всё:
// пустая база, разъехавшийся запрос, непосеянные селекторы — каждое дало бы
// «ноль» даром. Поэтому положительный контроль идёт тем же путём и обязан быть
// НЕпустым.
func TestOperatorFanout_RetiredAndGrantsNothing(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()

	// Селекторы системных ролей проецируются самолечащим посевом (в проде — на
	// загрузке). Зовём его явно, иначе «ноль селекторов» был бы получен из того,
	// что их не проецировал никто, а не из снятия роли.
	require.NoError(t, seed.SyncAllSystemRoleSelectors(ctx, pool))

	operatorSVA := scalarString(t, ctx, pool, operatorSVAExpr)
	operatorRole := scalarString(t, ctx, pool, operatorRoleExpr)

	// ── Перепись ДО вердикта: «ноль находок» обязано быть отличимо от «ноль
	// прочитанного».
	totalRoles := scalarInt(t, ctx, pool, `SELECT count(*) FROM kacho_iam.roles`)
	totalSelectors := scalarInt(t, ctx, pool, `SELECT count(*) FROM kacho_iam.role_rule_selectors`)
	t.Logf("осмотрено: ролей=%d, строк селекторов=%d; оператор sva=%s rol=%s",
		totalRoles, totalSelectors, operatorSVA, operatorRole)
	require.NotZero(t, totalRoles, "предпосылка гейта нарушена: в посеве нет ни одной роли")
	require.NotZero(t, totalSelectors,
		"предпосылка гейта нарушена: селекторы не спроецированы — «ноль у оператора» был бы получен даром")

	// ── Отрицание: роль снята, привязка снята, селекторов нет.
	require.Zero(t, scalarInt(t, ctx, pool,
		`SELECT count(*) FROM kacho_iam.roles WHERE id = $1`, operatorRole),
		"роль module.vpc_operator_sa обязана быть снята: её четыре правила не разрешаются "+
			"закрытой таблицей типов и не материализуют ни одного кортежа")
	require.Zero(t, scalarInt(t, ctx, pool,
		`SELECT count(*) FROM kacho_iam.access_bindings WHERE subject_id = $1 AND status = 'ACTIVE'`,
		operatorSVA),
		"у оператора сети не должно остаться ACTIVE-привязки: снятая роль не может оставаться выданной")
	require.Zero(t, scalarInt(t, ctx, pool,
		`SELECT count(*) FROM kacho_iam.role_rule_selectors WHERE role_id = $1`, operatorRole),
		"селекторы снятой роли обязаны уйти вместе с ней (ON DELETE CASCADE)")

	opResolvable, opDeclared := resolvableTypesReachableBySubject(t, ctx, pool, operatorSVA)
	require.Empty(t, opDeclared,
		"оператор сети не должен достигать ни одного объявленного типа: объявлено %v", opDeclared)
	require.Empty(t, opResolvable,
		"оператор сети не должен достигать ни одного РАЗРЕШИМОГО типа: разрешимо %v", opResolvable)

	// ── Положительный контроль тем же путём: живой принципал свои объекты видит.
	liveSubject := seedLivePrincipalBoundToResolvableRole(t, ctx, pool)
	liveResolvable, liveDeclared := resolvableTypesReachableBySubject(t, ctx, pool, liveSubject)
	require.NotEmpty(t, liveDeclared,
		"контроль: живой принципал не достиг ни одного объявленного типа — путь запроса не измеряет свойство, "+
			"и «ноль у оператора» получен даром")
	require.NotEmpty(t, liveResolvable,
		"контроль: живой принципал не достиг ни одного РАЗРЕШИМОГО типа — предикат разрешимости не различает, "+
			"и «ноль у оператора» получен даром")
	t.Logf("контроль: живой принципал %s достигает разрешимых типов %v", liveSubject, liveResolvable)
}

// seedLivePrincipalBoundToResolvableRole создаёт служебную учётку и выдаёт ей
// ACTIVE-привязку на СИСТЕМНУЮ роль, чьё правило разрешается закрытой таблицей
// (`vpc.subnet.view` → `vpc.subnet` → `vpc_subnet`). Возвращает id субъекта.
//
// Контроль намеренно живёт на роли ИЗ ПОСЕВА, а не на выдуманной: подставная
// роль доказала бы работоспособность запроса, но не то, что действующий посев
// вообще содержит хоть одну работающую выдачу.
func seedLivePrincipalBoundToResolvableRole(
	t *testing.T, ctx context.Context, pool *pgxpool.Pool,
) string {
	t.Helper()
	const roleNameExpr = `'rol' || substr(md5('vpc.subnet.view'), 1, 17)`
	roleID := scalarString(t, ctx, pool, roleNameExpr)
	require.Equal(t, 1, scalarInt(t, ctx, pool,
		`SELECT count(*) FROM kacho_iam.roles WHERE id = $1`, roleID),
		"предпосылка контроля нарушена: системная роль vpc.subnet.view не посеяна — "+
			"положительная половина стала бы недостижимой")

	accountID := scalarString(t, ctx, pool, `'acc' || substr(md5('kacho-system'), 1, 17)`)
	subjectID := scalarString(t, ctx, pool, `'sva' || substr(md5('live-control-principal'), 1, 17)`)
	bindingID := scalarString(t, ctx, pool, `'acb' || substr(md5('live-control-binding'), 1, 17)`)

	_, err := pool.Exec(ctx,
		`INSERT INTO kacho_iam.service_accounts (id, account_id, name, description)
		 VALUES ($1, $2, 'live-control-principal', 'positive control for the operator fan-out gate')
		 ON CONFLICT (id) DO NOTHING`, subjectID, accountID)
	require.NoError(t, err, "контроль: не удалось создать живого принципала")

	_, err = pool.Exec(ctx,
		`INSERT INTO kacho_iam.access_bindings
		   (id, subject_type, subject_id, role_id, resource_type, resource_id, scope, status)
		 VALUES ($1, 'service_account', $2, $3, 'cluster', 'cluster_kacho_root', 1, 'ACTIVE')
		 ON CONFLICT DO NOTHING`, bindingID, subjectID, roleID)
	require.NoError(t, err, "контроль: не удалось выдать живому принципалу привязку")

	require.NoError(t, seed.SyncAllSystemRoleSelectors(ctx, pool),
		"контроль: не удалось спроецировать селекторы после выдачи")
	return subjectID
}

// TestOperatorClusterTupleSurvivesRetirement — кортеж
// `system_viewer@cluster:cluster_kacho_root` оператора ОСТАЁТСЯ, и его учётка
// тоже.
//
// Это не «на всякий случай». Кортеж посеян 0010 ради каскада, который из модели
// удалён, — но с тех пор у него появился второй, действующий читатель, и снятие
// стало бы снятием живого права. Утверждение стоит рядом со снятием мёртвого
// именно потому, что оба предмета выглядят одинаково «остатками SEC-L»: без
// этого замка следующая уборка снимет живое, опираясь на ту же историю
// происхождения.
func TestOperatorClusterTupleSurvivesRetirement(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()

	operatorSVA := scalarString(t, ctx, pool, operatorSVAExpr)

	require.Equal(t, 1, scalarInt(t, ctx, pool,
		`SELECT count(*) FROM kacho_iam.service_accounts WHERE id = $1`, operatorSVA),
		"учётка оператора сети — его личность на внутреннем периметре; снятие мёртвой выдачи "+
			"её не касается")

	require.Equal(t, 1, scalarInt(t, ctx, pool,
		fmt.Sprintf(`SELECT count(*) FROM kacho_iam.fga_outbox
		              WHERE event_type = 'fga.tuple.write'
		                AND payload->>'relation' = 'system_viewer'
		                AND payload->>'object'   = 'cluster:cluster_kacho_root'
		                AND payload->>'user'     = 'service_account:' || %s`, operatorSVAExpr)),
		"кортеж system_viewer@cluster оператора обязан ОСТАТЬСЯ: на нём гейтятся READ-RPC "+
			"внутреннего листенера (authzguard.SystemViewerFloor) и vpc "+
			"InternalNetworkService/GetNetwork; миграция 0014 прямо на него опирается, "+
			"не сея оператору собственный")
}
