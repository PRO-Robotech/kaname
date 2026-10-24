// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// catalog_projection_lock_order_integration_test.go — инверсии порядка захвата строк
// `catalog_resource`, найденные переписью kaname#922, и их снятие.
//
// # Предмет
//
// Применитель каталога берёт строку модуля и затем строки ресурсов модуля
// `FOR UPDATE` одним оператором в порядке `dotted` (шаг 2а, kaname#913). Писатели
// проекций роли берут те же строки `FOR KEY SHARE` — ключом проекции на каталог
// (`role_rule_ref_res_fk`, `role_verb_type_fk`). Ключ проверяется на КАЖДОЙ
// вставке, то есть в порядке перечня, а не базы. Пара встречается на двух
// ресурсах одного модуля, названных писателем в обратном порядке:
//
//	писатель   zzz (ключ вставки)  → aaa (ключ вставки)
//	применитель модуль → aaa → zzz (FOR UPDATE, ORDER BY dotted)
//
// и Postgres снимает одну сторону взаимной блокировкой (40P01).
//
// Писателей с таким порядком перепись нашла три:
//
//	I1  ReplaceRuleRefs  — досев проекции сегментов системных ролей на старте
//	                       (seed.ReseedSystemRoleRuleRefs), транзакция на роль;
//	I2  ReplaceRoleVerbs — досев проекции глаголов (seed.ReseedSystemRoleVerbs);
//	I3  применитель ролей модуля — проекции нескольких ролей одной транзакцией,
//	    правила которых называют ресурсы ЧУЖОГО модуля: замок строки своего
//	    модуля (kaname#913) чужой модуль не запирает.
//
// # Ход — заданный ожиданием, а не временем
//
// I1, I2: ДЕРЖАТЕЛЬ вставляет в проекцию строку второго ресурса и не фиксирует её —
// с отложенным ключом на каталог, поэтому строки каталога он не держит. Писатель
// вставляет первую строку (ключ берёт `zzz`) и встаёт на вставке второй — за
// незафиксированным дубликатом держателя. Применитель встаёт на `zzz`. Держатель
// откатывается — писатель идёт к ключу на `aaa`, которую держит применитель.
//
// I3: настоящий применитель ролей модуля останавливается перед записью второй
// роли (rolePause, kaname#913); первая роль уже взяла ключом ресурс чужого модуля.
//
// В каждом повторе утверждается: применитель ВСТАЛ за писателем (иначе стороны не
// встретились); ни одна сторона не отвергнута взаимной блокировкой; обе дошли до
// конца. Двадцать повторов подряд — предикат kaname#922.

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/moduleroles"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// projectionLockRepeats — повторов подряд (предикат kaname#922).
const projectionLockRepeats = 20

// projectionLockBudget — предел ожидания любого шага хода.
const projectionLockBudget = 30 * time.Second

// projectionFarModule — ЧУЖОЙ модуль для I3: его ресурсы называют роли модуля пробы.
const projectionFarModule = "probefar"

// projectionWriter — писатель проекции под гонкой (I1/I2).
type projectionWriter struct {
	name string
	// tag — метка писателя в имени роли пробы (строчная: грамматика имени роли).
	tag string
	// deferKeys / hold — держатель: ключи проекции на каталог отложены, затем
	// незафиксированная строка по второму ресурсу (`aaa`). Строк каталога держатель
	// поэтому не берёт.
	deferKeys string
	hold      string
	// write — запись проекции роли настоящим писателем: `zzz`, затем `aaa`.
	write func(ctx context.Context, repo *kanamepg.Repository, role domain.RoleID) error
}

var (
	ruleRefsWriter = projectionWriter{
		name: "ReplaceRuleRefs", tag: "refs",
		deferKeys: `SET CONSTRAINTS kaname.role_rule_ref_res_fk, kaname.role_rule_ref_verb_fk DEFERRED`,
		hold: `INSERT INTO kaname.role_rule_ref (role_id, module, resource, verb) VALUES ($1, '` +
			applierProbeModule + `', '` + crossEarlyName + `', 'get')`,
		write: func(ctx context.Context, repo *kanamepg.Repository, role domain.RoleID) error {
			return inWriteTx(ctx, repo, func(w kanamerepo.Writer) error {
				return w.RolesW().ReplaceRuleRefs(ctx, role, []domain.RoleRuleRef{
					{Module: applierProbeModule, Resource: crossLateName, Verb: "get"},
					{Module: applierProbeModule, Resource: crossEarlyName, Verb: "get"},
				})
			})
		},
	}
	roleVerbsWriter = projectionWriter{
		name: "ReplaceRoleVerbs", tag: "verbs",
		deferKeys: `SET CONSTRAINTS kaname.role_verb_type_fk DEFERRED`,
		hold:      `INSERT INTO kaname.role_verb (role_id, object_type, verb) VALUES ($1, '` + crossLockEarly + `', 'get')`,
		write: func(ctx context.Context, repo *kanamepg.Repository, role domain.RoleID) error {
			return inWriteTx(ctx, repo, func(w kanamerepo.Writer) error {
				return w.RolesW().ReplaceRoleVerbs(ctx, role, []domain.RoleVerb{
					{ObjectType: crossLockLate, Verb: "get"},
					{ObjectType: crossLockEarly, Verb: "get"},
				})
			})
		},
	}
)

// inWriteTx — одна писательская транзакция репозитория: fn и фиксация.
func inWriteTx(ctx context.Context, repo *kanamepg.Repository, fn func(kanamerepo.Writer) error) error {
	w, err := repo.Writer(ctx)
	if err != nil {
		return err
	}
	if err := fn(w); err != nil {
		_ = w.Rollback(ctx)
		return err
	}
	return w.Commit(ctx)
}

func TestCatalogProjectionWriterRuleRefsTakesCatalogRowsInTheApplierOrder(t *testing.T) {
	raceProjectionWriter(t, ruleRefsWriter)
}

func TestCatalogProjectionWriterRoleVerbsTakesCatalogRowsInTheApplierOrder(t *testing.T) {
	raceProjectionWriter(t, roleVerbsWriter)
}

// raceProjectionWriter — двадцать ходов «писатель проекции против применителя».
func raceProjectionWriter(t *testing.T, pw projectionWriter) {
	t.Helper()
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx, pool := catalogPool(t)
	applier := applierOver(t, pool)
	repo := kanamepg.New(pool, nil)
	install := probeManifest(probeResource(crossEarlyName, "get"), probeResource(crossLateName, "get"))
	_, err := applier.Apply(ctx, install)
	require.NoError(t, err, "Дано: модуль %s с живыми ресурсами %s и %s", applierProbeModule, crossEarlyName, crossLateName)

	deadlocks := 0
	var first error
	for i := 0; i < projectionLockRepeats; i++ {
		role := platformProbeRole(t, ctx, repo, fmt.Sprintf("p922%s%02d", pw.tag, i))
		werr, aerr := raceProjectionOnce(t, ctx, pool, repo, pw, role, i, func() error {
			_, e := applier.Apply(ctx, install)
			return e
		})
		if isDeadlockOrAborted(werr) || isDeadlockOrAborted(aerr) {
			deadlocks++
			if first == nil {
				first = fmt.Errorf("повтор %d: %s=%v · применитель=%v", i, pw.name, werr, aerr)
			}
			continue
		}
		require.NoErrorf(t, werr, "повтор %d: %s не дошёл до конца", i, pw.name)
		require.NoErrorf(t, aerr, "повтор %d: применитель не дошёл до конца", i)
	}
	t.Logf("%s: повторов %d · взаимных блокировок %d", pw.name, projectionLockRepeats, deadlocks)
	require.Zerof(t, deadlocks,
		"взаимная блокировка в %d из %d повторов (первая: %v): %s берёт строки `catalog_resource` "+
			"ключом вставки в порядке перечня, применитель — в порядке `dotted`",
		deadlocks, projectionLockRepeats, first, pw.name)
}

// raceProjectionOnce — один ход I1/I2. Отдаёт исходы писателя и применителя.
func raceProjectionOnce(t *testing.T, ctx context.Context, pool *pgxpool.Pool, repo *kanamepg.Repository,
	pw projectionWriter, role domain.RoleID, n int, apply func() error) (werr, aerr error) {
	t.Helper()
	holder, err := pool.Begin(ctx)
	require.NoError(t, err)
	holderDone := false
	defer func() {
		if !holderDone {
			_ = holder.Rollback(ctx)
		}
	}()
	_, err = holder.Exec(ctx, pw.deferKeys)
	require.NoErrorf(t, err, "ПРЕДПОСЫЛКА повтора %d: держатель отложил ключи проекции", n)
	_, err = holder.Exec(ctx, pw.hold, string(role))
	require.NoErrorf(t, err, "ПРЕДПОСЫЛКА повтора %d: держатель положил строку проекции по %s", n, crossLockEarly)

	wres := make(chan error, 1)
	go func() { wres <- pw.write(ctx, repo, role) }()
	// Писатель встал за дубликатом держателя: первая строка проекции записана.
	requireWaiters(t, ctx, pool, 1, wres, n, pw.name+" не встал за строкой держателя")

	ares := make(chan error, 1)
	go func() { ares <- apply() }()
	requireWaiters(t, ctx, pool, 2, ares, n, "применитель не встал за писателем проекции")

	require.NoError(t, holder.Rollback(ctx))
	holderDone = true
	return awaitBoth(t, wres, ares, n)
}

// requireWaiters — на замках стоят РОВНО want процессов; сторона, вернувшаяся
// раньше, — стороны не встретились, утверждение о порядке беспредметно.
func requireWaiters(t *testing.T, ctx context.Context, pool *pgxpool.Pool, want int, side <-chan error, n int, why string) {
	t.Helper()
	deadline := time.Now().Add(projectionLockBudget)
	for !lockWaiters(ctx, pool, want, 100*time.Millisecond) {
		select {
		case err := <-side:
			t.Fatalf("повтор %d: %s — сторона вернулась (%v), не встав на замке", n, why, err)
		default:
		}
		require.Truef(t, time.Now().Before(deadline), "повтор %d: %s за %s", n, why, projectionLockBudget)
	}
}

// awaitBoth — исходы обеих сторон в пределах бюджета.
func awaitBoth(t *testing.T, a, b <-chan error, n int) (aerr, berr error) {
	t.Helper()
	for k := 0; k < 2; k++ {
		select {
		case aerr = <-a:
		case berr = <-b:
		case <-time.After(projectionLockBudget):
			t.Fatalf("повтор %d: сторона не завершилась за %s", n, projectionLockBudget)
		}
	}
	return aerr, berr
}

// platformProbeRole — живая системная роль платформенного яруса: владелец
// проекций, которые досев пишет на старте.
func platformProbeRole(t *testing.T, ctx context.Context, repo *kanamepg.Repository, tag string) domain.RoleID {
	t.Helper()
	rules := domain.Rules{{Module: applierProbeModule, Resources: []string{crossLateName, crossEarlyName}, Verbs: []string{"get"}}}
	compiled, err := domain.CompileRules(rules)
	require.NoError(t, err)
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	defer func() { _ = w.Rollback(ctx) }()
	out, _, err := w.RolesW().UpsertSystemRole(ctx, domain.Role{
		ID: domain.RoleID(ids.NewID(domain.PrefixRole)), ClusterID: domain.ClusterSingletonID,
		Name: domain.RoleName("sys-" + tag), Description: domain.Description("роль пробы kaname#922"),
		Rules: rules, Permissions: compiled,
	})
	require.NoError(t, err, "ПРЕДПОСЫЛКА: системная роль пробы")
	require.NoError(t, w.Commit(ctx))
	return out.ID
}

// TestModuleRolesApplierTakesForeignCatalogRowsInTheApplierOrder — I3: роли
// модуля пробы называют ресурсы ЧУЖОГО модуля, первая — поздний, вторая — ранний.
func TestModuleRolesApplierTakesForeignCatalogRowsInTheApplierOrder(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx, pool := catalogPool(t)
	catalogApplier := applierOver(t, pool)
	repo := kanamepg.New(pool, nil)

	_, err := catalogApplier.Apply(ctx, probeManifest(probeResource(crossEarlyName, "get")))
	require.NoError(t, err, "Дано: модуль-владелец %s", applierProbeModule)
	far := &manifest.Manifest{APIVersion: "iam/v1", Module: projectionFarModule,
		Resources: []manifest.Resource{farResource(crossEarlyName), farResource(crossLateName)}}
	_, err = catalogApplier.Apply(ctx, far)
	require.NoError(t, err, "Дано: чужой модуль %s с ресурсами %s и %s", projectionFarModule, crossEarlyName, crossLateName)

	deadlocks := 0
	var first error
	for i := 0; i < projectionLockRepeats; i++ {
		late := fmt.Sprintf("%s.p922f%02da.viewer", applierProbeModule, i)
		early := fmt.Sprintf("%s.p922f%02db.viewer", applierProbeModule, i)
		pause := newRolePause(domain.SystemRoleID(domain.RoleName(early)))
		paused := moduleroles.NewApplier(pause.over(moduleroles.NewRepoTxRunner(repo)), literalRights{})
		rres := make(chan error, 1)
		go func() {
			_, rerr := paused.Apply(ctx, farRolesManifest(
				farRoleDecl{late, crossLateName}, farRoleDecl{early, crossEarlyName}), moduleroles.BootActorID)
			rres <- rerr
		}()
		select {
		case <-pause.reached:
		case rerr := <-rres:
			t.Fatalf("повтор %d: применитель ролей завершился (%v), не дойдя до второй роли", i, rerr)
		case <-time.After(projectionLockBudget):
			t.Fatalf("повтор %d: применитель ролей не дошёл до второй роли за %s", i, projectionLockBudget)
		}
		ares := make(chan error, 1)
		go func() {
			_, aerr := catalogApplier.Apply(ctx, far)
			ares <- aerr
		}()
		deadline := time.Now().Add(projectionLockBudget)
		for !lockWaiters(ctx, pool, 1, 100*time.Millisecond) {
			select {
			case aerr := <-ares:
				close(pause.release)
				t.Fatalf("повтор %d: применитель каталога НЕ встал за транзакцией ролей (%v)", i, aerr)
			default:
			}
			if !time.Now().Before(deadline) {
				close(pause.release)
				t.Fatalf("повтор %d: применитель каталога не встал за %s", i, projectionLockBudget)
			}
		}
		close(pause.release)
		roleErr, applyErr := awaitBoth(t, rres, ares, i)
		if isDeadlockOrAborted(roleErr) || isDeadlockOrAborted(applyErr) {
			deadlocks++
			if first == nil {
				first = fmt.Errorf("повтор %d: роли модуля=%v · применитель=%v", i, roleErr, applyErr)
			}
			continue
		}
		require.NoErrorf(t, roleErr, "повтор %d: применитель ролей не дошёл до конца", i)
		require.NoErrorf(t, applyErr, "повтор %d: применитель каталога не дошёл до конца", i)
	}
	t.Logf("роли модуля по чужому модулю: повторов %d · взаимных блокировок %d", projectionLockRepeats, deadlocks)
	require.Zerof(t, deadlocks,
		"взаимная блокировка в %d из %d повторов (первая: %v): применитель ролей модуля берёт строки "+
			"ресурсов ЧУЖОГО модуля по ролям, в порядке их записи, а не базы", deadlocks, projectionLockRepeats, first)
}

// farResource — ресурс чужого модуля.
func farResource(name string) manifest.Resource {
	return manifest.Resource{Name: name, ObjectType: projectionFarModule + "_" + name,
		Verbs: []manifest.Verb{{Name: "get"}}}
}

// farRoleDecl — роль модуля пробы с единственным правилом по ресурсу чужого модуля.
type farRoleDecl struct {
	name     string
	resource string
}

// farRolesManifest — манифест модуля пробы, чьи роли называют ресурсы чужого модуля.
func farRolesManifest(roles ...farRoleDecl) *manifest.Manifest {
	m := &manifest.Manifest{APIVersion: "iam/v1", Module: applierProbeModule}
	for _, r := range roles {
		m.Roles = append(m.Roles, manifest.Role{
			ID:          r.name,
			Description: "Роль модуля пробы kaname#922.",
			Tier:        &manifest.Tier{TierType: domain.ScopeTypeClusterDotted, TierID: domain.ClusterSingletonID},
			Rules:       []manifest.Rule{{Module: projectionFarModule, Resources: []string{r.resource}, Verbs: []string{"get"}}},
		})
	}
	return m
}
