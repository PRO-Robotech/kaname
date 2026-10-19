// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// catalog_applier_module_role_lock_order_integration_test.go — ПОРЯДОК СТРОЧНЫХ
// ЗАМКОВ применителя каталога против записи РОЛИ МОДУЛЯ (kaname#913, признак —
// опыт полосы kaname#865).
//
// # Признак
//
// Применитель каталога и применитель ролей модуля, работающие одновременно,
// встречались на двух строках каталога в обратном порядке:
//
//	роль модуля  вставка `roles` (owner_module) → ключ на строку `catalog_module`
//	             FOR KEY SHARE; затем `ReplaceRuleRefs` → ключ на строку
//	             `catalog_resource` FOR KEY SHARE
//	применитель  шаг 2а → строки `catalog_resource` FOR UPDATE; затем шаг 4
//	             `UpsertModule` → строка `catalog_module` FOR UPDATE
//
// Первая сторона шла «модуль → ресурсы», вторая «ресурсы → модуль», и Postgres
// отвергал взаимной блокировкой (40P01) одну из сторон. Какую — решает момент
// проверки взаимной блокировки, а не порядок: в опыте kaname#865 — сторону
// ролей (клиент получал `aborted: conflicting concurrent change`), в этой пробе
// до правки — применитель каталога, 20 повторов из 20.
//
// # Что утверждается
//
// Двадцать повторов подряд одного и того же хода — вставка роли модуля,
// затем применение каталога того же модуля, затем запись проекции правил
// роли. В каждом повторе:
//
//  1. применитель ВСТАЁТ за транзакцией роли (ждёт замка) — иначе стороны не
//     встретились, и «взаимной блокировки нет» получено даром;
//  2. ни одна сторона не отвергнута взаимной блокировкой — собственно предмет;
//  3. обе стороны доходят до конца — иначе п. 2 выполним стороной, которая
//     перестала работать.
//
// Число повторов — предикат задачи: исход гонки здесь не случаен (порядок
// событий задан ожиданием, а не временем), и двадцать подряд отличают порядок
// от удачи на любом исполнителе.
//
// Законный близнец хода — `TestLoneCatalogApplyAgainstAnIdleCatalogPasses`
// (применение без соперника не ждёт) и одиночная запись роли модуля
// (`module_roles_applier_integration_test.go`).

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/moduleroles"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// moduleRoleLockRepeats — число повторов подряд (предикат kaname#913).
const moduleRoleLockRepeats = 20

// moduleRoleLockBudget — предел ожидания любого шага хода.
const moduleRoleLockBudget = 30 * time.Second

// TestCatalogApplierAndModuleRoleWriterTakeTheModuleRowFirst — предмет kaname#913.
func TestCatalogApplierAndModuleRoleWriterTakeTheModuleRowFirst(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx, pool := catalogPool(t)
	applier := applierOver(t, pool)
	repo := kanamepg.New(pool, nil)

	install := probeManifest(probeResource(crossEarlyName, "get"))
	_, err := applier.Apply(ctx, install)
	require.NoError(t, err, "Дано: модуль %s с живым ресурсом %s", applierProbeModule, crossEarlyName)

	deadlocks := 0
	var firstRefusal error
	for i := 0; i < moduleRoleLockRepeats; i++ {
		roleErr, applyErr := raceModuleRoleAgainstApplier(t, ctx, pool, repo, i, func() error {
			_, aerr := applier.Apply(ctx, install)
			return aerr
		})
		if isDeadlock(roleErr) || isDeadlock(applyErr) {
			deadlocks++
			if firstRefusal == nil {
				firstRefusal = fmt.Errorf("повтор %d: роль модуля=%v · применитель=%v", i, roleErr, applyErr)
			}
			continue
		}
		require.NoErrorf(t, roleErr, "повтор %d: запись роли модуля не дошла до конца", i)
		require.NoErrorf(t, applyErr, "повтор %d: применитель не дошёл до конца", i)
	}
	t.Logf("повторов %d · взаимных блокировок %d", moduleRoleLockRepeats, deadlocks)
	require.Zerof(t, deadlocks,
		"взаимная блокировка в %d из %d повторов (первая: %v): применитель берёт строки "+
			"`catalog_resource` раньше строки `catalog_module`, а запись роли модуля — строку модуля "+
			"раньше строк ресурсов", deadlocks, moduleRoleLockRepeats, firstRefusal)
}

// raceModuleRoleAgainstApplier — один ход: транзакция роли модуля вставляет
// строку роли (ключ на строку модуля), применитель запускается и ВСТАЁТ за ней,
// затем та же транзакция пишет проекцию правил по ресурсу модуля и фиксируется.
// Отдаёт исходы обеих сторон.
func raceModuleRoleAgainstApplier(
	t *testing.T, ctx context.Context, pool *pgxpool.Pool, repo *kanamepg.Repository, n int,
	apply func() error,
) (roleErr, applyErr error) {
	t.Helper()
	rules := domain.Rules{{Module: applierProbeModule, Resources: []string{crossEarlyName}, Verbs: []string{"get"}}}
	role := ownedModuleRole(t, applierProbeModule,
		fmt.Sprintf("%s.p913r%02d.viewer", applierProbeModule, n), "Роль модуля пробы kaname#913.", rules)

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	closed := false
	defer func() {
		if !closed {
			_ = w.Rollback(ctx)
		}
	}()
	out, changed, err := w.RolesW().UpsertSystemRole(ctx, role)
	require.NoErrorf(t, err, "повтор %d: вставка роли модуля", n)
	require.Truef(t, changed, "ПРЕДПОСЫЛКА повтора %d: роль вставлена впервые — ключ на строку модуля взят", n)

	ares := make(chan error, 1)
	go func() { ares <- apply() }()

	// ПРЕДПОСЫЛКА п. 1: применитель встал на замке за транзакцией роли.
	deadline := time.Now().Add(moduleRoleLockBudget)
	for !lockWaiters(ctx, pool, 1, 100*time.Millisecond) {
		select {
		case aerr := <-ares:
			t.Fatalf("повтор %d: применитель НЕ встал за транзакцией роли модуля (%v) — стороны "+
				"не встретились, и утверждение о порядке замков беспредметно", n, aerr)
		default:
		}
		require.Truef(t, time.Now().Before(deadline), "повтор %d: применитель не встал за %s", n, moduleRoleLockBudget)
	}

	roleErr = w.RolesW().ReplaceRuleRefs(ctx, out.ID, domain.RuleRefsOf(out.Rules))
	if roleErr == nil {
		roleErr = w.Commit(ctx)
	} else {
		_ = w.Rollback(ctx)
	}
	closed = true

	select {
	case applyErr = <-ares:
	case <-time.After(moduleRoleLockBudget):
		t.Fatalf("повтор %d: применитель не завершился за %s после фиксации роли", n, moduleRoleLockBudget)
	}
	return roleErr, applyErr
}

// TestCatalogApplierAndModuleRolesApplierMeetOnTheModuleRowWhenRolesAreUpdated —
// второй вид той же встречи (остаток класса kaname#913): роли модуля УЖЕ
// записаны, и применитель ролей приводит их правила.
//
// Вставки роли здесь нет, а значит нет и ключа на строку модуля: ключ
// `roles_owner_module_live_fk` проверяется, только когда меняются его столбцы,
// а приведение правил меняет `rules`. Транзакция ролей тогда берёт из каталога
// одни строки ресурсов — по мере записи проекций, роль за ролью, — и в обход
// порядка `dotted`: первая роль называет `zzz`, вторая `aaa`. Применитель,
// вставший между ними, держит `aaa` и ждёт `zzz` — та же взаимная блокировка,
// которую единый порядок «модуль → ресурсы» снимает, лишь если ПЕРВЫМ строчным
// замком транзакции ролей стоит строка модуля.
//
// Ход ведёт НАСТОЯЩИЙ применитель ролей (`moduleroles.Applier`) над настоящим
// репозиторием; пауза ставится перед записью второй роли обёрткой порта, а не
// подменой писателя. Производитель правил — дословный перевод правил манифеста:
// синтетический модуль пробы не входит в каталог платформы, по которому
// производит правила настоящий экспортёр, а предмет здесь — порядок замков, не
// перевод классов.
func TestCatalogApplierAndModuleRolesApplierMeetOnTheModuleRowWhenRolesAreUpdated(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx, pool := catalogPool(t)
	catalogApplier := applierOver(t, pool)
	repo := kanamepg.New(pool, nil)

	install := probeManifest(probeResource(crossEarlyName, "get"), probeResource(crossLateName, "get"))
	_, err := catalogApplier.Apply(ctx, install)
	require.NoError(t, err, "Дано: модуль %s с живыми ресурсами %s и %s", applierProbeModule, crossEarlyName, crossLateName)

	deadlocks := 0
	var firstRefusal error
	for i := 0; i < moduleRoleLockRepeats; i++ {
		first := fmt.Sprintf("%s.p913u%02da.viewer", applierProbeModule, i)
		second := fmt.Sprintf("%s.p913u%02db.viewer", applierProbeModule, i)

		// Дано: обе роли записаны; первая называет оба ресурса, вторая — поздний.
		plain := moduleroles.NewApplier(moduleroles.NewRepoTxRunner(repo), literalRights{})
		_, err := plain.Apply(ctx, moduleRolesManifest(
			moduleRoleDecl{first, []string{crossEarlyName, crossLateName}},
			moduleRoleDecl{second, []string{crossLateName}}), moduleroles.BootActorID)
		require.NoErrorf(t, err, "Дано повтора %d: роли модуля записаны", i)

		// Ход: первая роль сужается до позднего ресурса, вторая переходит на ранний.
		pause := newRolePause(domain.SystemRoleID(domain.RoleName(second)))
		paused := moduleroles.NewApplier(pause.over(moduleroles.NewRepoTxRunner(repo)), literalRights{})
		rres := make(chan error, 1)
		go func() {
			_, rerr := paused.Apply(ctx, moduleRolesManifest(
				moduleRoleDecl{first, []string{crossLateName}},
				moduleRoleDecl{second, []string{crossEarlyName}}), moduleroles.BootActorID)
			rres <- rerr
		}()
		select {
		case <-pause.reached:
		case rerr := <-rres:
			t.Fatalf("повтор %d: применитель ролей завершился (%v), не дойдя до второй роли", i, rerr)
		case <-time.After(moduleRoleLockBudget):
			t.Fatalf("повтор %d: применитель ролей не дошёл до второй роли за %s", i, moduleRoleLockBudget)
		}

		ares := make(chan error, 1)
		go func() {
			_, aerr := catalogApplier.Apply(ctx, install)
			ares <- aerr
		}()
		deadline := time.Now().Add(moduleRoleLockBudget)
		for !lockWaiters(ctx, pool, 1, 100*time.Millisecond) {
			select {
			case aerr := <-ares:
				close(pause.release)
				t.Fatalf("повтор %d: применитель каталога НЕ встал за транзакцией ролей (%v) — стороны "+
					"не встретились", i, aerr)
			default:
			}
			if !time.Now().Before(deadline) {
				close(pause.release)
				t.Fatalf("повтор %d: применитель каталога не встал за %s", i, moduleRoleLockBudget)
			}
		}
		close(pause.release)

		var roleErr, applyErr error
		for k := 0; k < 2; k++ {
			select {
			case roleErr = <-rres:
			case applyErr = <-ares:
			case <-time.After(moduleRoleLockBudget):
				t.Fatalf("повтор %d: сторона не завершилась за %s: роли=%v каталог=%v", i, moduleRoleLockBudget, roleErr, applyErr)
			}
		}
		if isDeadlockOrAborted(roleErr) || isDeadlockOrAborted(applyErr) {
			deadlocks++
			if firstRefusal == nil {
				firstRefusal = fmt.Errorf("повтор %d: роли модуля=%v · применитель=%v", i, roleErr, applyErr)
			}
			continue
		}
		require.NoErrorf(t, roleErr, "повтор %d: применитель ролей не дошёл до конца", i)
		require.NoErrorf(t, applyErr, "повтор %d: применитель каталога не дошёл до конца", i)
	}
	t.Logf("повторов %d · взаимных блокировок %d", moduleRoleLockRepeats, deadlocks)
	require.Zerof(t, deadlocks,
		"взаимная блокировка в %d из %d повторов (первая: %v): транзакция приведения ролей модуля "+
			"берёт строки ресурсов, не взяв строку модуля первой", deadlocks, moduleRoleLockRepeats, firstRefusal)
}

// isDeadlockOrAborted — взаимная блокировка в любом виде, включая приведённый к
// статусу отказ применителя ролей (`aborted: conflicting concurrent change`).
func isDeadlockOrAborted(err error) bool {
	return isDeadlock(err) || status.Code(err) == codes.Aborted
}

// moduleRoleDecl — роль модуля пробы: имя и ресурсы её единственного правила.
type moduleRoleDecl struct {
	name      string
	resources []string
}

// moduleRolesManifest — манифест модуля пробы с ролями кластерного яруса.
func moduleRolesManifest(roles ...moduleRoleDecl) *manifest.Manifest {
	m := &manifest.Manifest{APIVersion: "iam/v1", Module: applierProbeModule}
	for _, r := range roles {
		m.Roles = append(m.Roles, manifest.Role{
			ID:          r.name,
			Description: "Роль модуля пробы kaname#913.",
			Tier:        &manifest.Tier{TierType: domain.ScopeTypeClusterDotted, TierID: domain.ClusterSingletonID},
			Rules:       []manifest.Rule{{Module: applierProbeModule, Resources: r.resources, Verbs: []string{"get"}}},
		})
	}
	return m
}

// literalRights — производитель правил, переводящий правило манифеста
// дословно: поимённые действия правила и есть его глаголы.
type literalRights struct{}

func (literalRights) ExportRoleRules(m *manifest.Manifest) (map[string][]domain.Rule, []error) {
	out := make(map[string][]domain.Rule, len(m.Roles))
	for _, r := range m.Roles {
		for _, rule := range r.Rules {
			out[r.ID] = append(out[r.ID], domain.Rule{Module: rule.Module, Resources: rule.Resources, Verbs: rule.Verbs})
		}
	}
	return out, nil
}

// rolePause — остановка применителя ролей ПЕРЕД записью роли `on`: транзакция
// открыта, предыдущие роли записаны, и проба решает, когда идти дальше.
type rolePause struct {
	on      domain.RoleID
	reached chan struct{}
	release chan struct{}
}

func newRolePause(on domain.RoleID) *rolePause {
	return &rolePause{on: on, reached: make(chan struct{}), release: make(chan struct{})}
}

// over — исполнитель транзакций, отдающий функции писателя с остановкой.
func (p *rolePause) over(inner moduleroles.TxRunner) moduleroles.TxRunner {
	return pausingTxRunner{inner: inner, pause: p}
}

type pausingTxRunner struct {
	inner moduleroles.TxRunner
	pause *rolePause
}

func (r pausingTxRunner) RunInWriteTx(ctx context.Context, fn func(context.Context, moduleroles.RoleWriter) error) error {
	return r.inner.RunInWriteTx(ctx, func(ctx context.Context, w moduleroles.RoleWriter) error {
		return fn(ctx, pausingRoleWriter{RoleWriter: w, pause: r.pause})
	})
}

// pausingRoleWriter — настоящий писатель; отличие одно — остановка перед ролью.
type pausingRoleWriter struct {
	moduleroles.RoleWriter
	pause *rolePause
}

func (w pausingRoleWriter) UpsertSystemRole(ctx context.Context, r domain.Role) (domain.Role, bool, error) {
	if r.ID == w.pause.on {
		close(w.pause.reached)
		<-w.pause.release
	}
	return w.RoleWriter.UpsertSystemRole(ctx, r)
}
