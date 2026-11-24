// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/moduleroles"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/moduleseed"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

// Три настоящих адаптера: запись, откат позднего отказа и законный повтор.
// Один runtime slot исключает скрытое второе соединение при входе.
func TestInstallationCatalogModuleSeedRolePreparedStrict(t *testing.T) {
	for _, strict := range []bool{false, true} {
		for _, family := range []string{"catalog", "module_seed", "module_role"} {
			name := map[bool]string{false: "prepared", true: "strict"}[strict] + "/" + family
			t.Run(name, func(t *testing.T) {
				r := identityLifecycleSingle(t, writerProtocolRig(t))
				if strict {
					require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
				}
				var accountName string
				require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT name FROM kaname.accounts WHERE id=$1`, r.a).Scan(&accountName))
				role := declaredModuleRole(t, "vpc.installation_probe.viewer", "Проба typed установки", domain.Rules{{Module: "vpc", Resources: []string{"network"}, Verbs: []string{"get"}}})
				late := errors.New("поздний отказ после записи")
				var run func(error) error
				var query string
				var args []any
				switch family {
				case "catalog":
					run = func(tail error) error {
						return kanamepg.NewCatalogWriteRepo(r.runtime).RunInWriteTx(r.ctx, func(ctx context.Context, w modulecatalog.CatalogWriter) error {
							if err := w.LockCatalog(ctx); err != nil {
								return err
							}
							changed, err := w.UpsertModule(ctx, "installation_probe")
							if err != nil {
								return err
							}
							require.True(t, changed)
							return tail
						})
					}
					query = `SELECT count(*) FROM kaname.catalog_module WHERE module='installation_probe'`
				case "module_seed":
					run = func(tail error) error {
						return kanamepg.NewModuleSeedWriteRepo(r.runtime).RunInWriteTx(r.ctx, func(ctx context.Context, w moduleseed.Writer) error {
							changed, err := w.UpsertGroup(ctx, accountName, "installation-probe", "Проба записи")
							if err != nil {
								return err
							}
							require.True(t, changed)
							return tail
						})
					}
					query = `SELECT count(*) FROM kaname.groups WHERE account_id=$1 AND name='installation-probe'`
					args = []any{r.a}
				case "module_role":
					run = func(tail error) error {
						return moduleroles.NewRepoTxRunner(r.repo).RunInWriteTx(r.ctx, func(ctx context.Context, w moduleroles.RoleWriter) error {
							if err := w.LockOwnerModule(ctx, "vpc"); err != nil {
								return err
							}
							_, changed, err := w.UpsertSystemRole(ctx, role)
							if err != nil {
								return err
							}
							require.True(t, changed)
							return tail
						})
					}
					query = `SELECT count(*) FROM kaname.roles WHERE id=$1`
					args = []any{string(role.ID)}
				}
				require.Error(t, run(late))
				var count int
				require.NoError(t, r.admin.QueryRow(r.ctx, query, args...).Scan(&count))
				require.Zero(t, count)
				require.NoError(t, run(nil))
				require.NoError(t, r.admin.QueryRow(r.ctx, query, args...).Scan(&count))
				require.Equal(t, 1, count)
				authorityWaitReleased(t, r.runtime)
			})
		}
	}
}

// GLOBAL должен остановить применитель до его первого catalog advisory lock.
func TestInstallationCatalogEntryPrecedesBodyAndCancellationReleasesLease(t *testing.T) {
	r := writerProtocolRig(t)
	held, err := r.repo.ParticipantAuthorityWriter(r.ctx, kaname.AuthorityWriteIntent{Kind: kaname.AuthorityCatalog, Bundle: r.bundle, Plan: kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal}})
	require.NoError(t, err)
	defer held.Rollback(context.Background())
	r = identityLifecycleSingle(t, r)
	ctx, cancel := context.WithCancel(r.ctx)
	defer cancel()
	entered := false
	done := make(chan error, 1)
	go func() {
		done <- kanamepg.NewCatalogWriteRepo(r.runtime).RunInWriteTx(ctx, func(ctx context.Context, w modulecatalog.CatalogWriter) error {
			entered = true
			return w.LockCatalog(ctx)
		})
	}()
	waiter := authorityWaitLock(t, r.ctx, r.admin)
	var blocked bool
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT cardinality(pg_blocking_pids($1)) > 0`, waiter).Scan(&blocked))
	require.True(t, blocked, "нужно настоящее ожидание SQL fence, не ожидание pool slot")
	cancel()
	select {
	case err = <-done:
		require.Error(t, err)
	case <-time.After(6 * time.Second):
		t.Fatal("entry waiter не завершился после отмены")
	}
	require.False(t, entered)
	require.NoError(t, held.Rollback(r.ctx))
	authorityWaitReleased(t, r.runtime)
	require.NoError(t, kanamepg.NewCatalogWriteRepo(r.runtime).RunInWriteTx(r.ctx, func(ctx context.Context, w modulecatalog.CatalogWriter) error { return w.LockCatalog(ctx) }))
	ctx, cancel = context.WithCancel(r.ctx)
	err = kanamepg.NewCatalogWriteRepo(r.runtime).RunInWriteTx(ctx, func(ctx context.Context, w modulecatalog.CatalogWriter) error {
		_, err := w.UpsertModule(ctx, "installation_cancel")
		if err != nil {
			return err
		}
		cancel()
		return ctx.Err()
	})
	cancel()
	require.Error(t, err)
	var count int
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*) FROM kaname.catalog_module WHERE module='installation_cancel'`).Scan(&count))
	require.Zero(t, count)
	authorityWaitReleased(t, r.runtime)
}

// Публичные функции startup реально пересеивают проекции и bootstrap grant.
func TestInstallationSeedProductionEntriesPreparedStrict(t *testing.T) {
	for _, strict := range []bool{false, true} {
		t.Run(map[bool]string{false: "prepared", true: "strict"}[strict], func(t *testing.T) {
			r := identityLifecycleSingle(t, writerProtocolRig(t))
			var uid, email, state string
			var verified bool
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT u.id,u.email,u.invite_status,u.email_verified_at IS NOT NULL FROM kaname.users u JOIN kaname.accounts a ON a.owner_user_id=u.id WHERE a.id=$1`, r.a).Scan(&uid, &email, &state, &verified))
			require.Equal(t, "ACTIVE", state)
			require.True(t, verified)
			require.NotEmpty(t, email)
			if strict {
				require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
			}
			role := declaredModuleRole(t, "vpc.installation_reseed.viewer", "Роль для настоящей очереди пересчёта", domain.Rules{{Module: "vpc", Resources: []string{"network"}, Verbs: []string{"get"}}})
			require.NoError(t, moduleroles.NewRepoTxRunner(r.repo).RunInWriteTx(r.ctx, func(ctx context.Context, w moduleroles.RoleWriter) error {
				_, _, err := w.UpsertSystemRole(ctx, role)
				return err
			}))
			require.NoError(t, seed.BackfillOwnerBindings(r.ctx, r.runtime))
			require.NoError(t, seed.SyncAllSystemRoleSelectors(r.ctx, r.runtime))
			halves, err := kanamepg.NewCatalogRepo(r.runtime).ReadCatalogHalves(r.ctx)
			require.NoError(t, err)
			facts, err := catalog.NewFacts(halves)
			require.NoError(t, err)
			queued, err := seed.RegrainQueuedSelectorVerbs(r.ctx, r.repo, r.runtime, facts)
			require.NoError(t, err)
			require.Positive(t, queued.Examined, "новая роль должна реально пройти очередь")
			verbs, err := seed.ReseedSystemRoleVerbs(r.ctx, r.repo, r.runtime, facts, nil)
			require.NoError(t, err)
			require.Positive(t, verbs.Examined)
			refs, err := seed.ReseedSystemRoleRuleRefs(r.ctx, r.repo, r.runtime, nil)
			require.NoError(t, err)
			require.Positive(t, refs.Examined)
			_, err = seed.RegrainQueuedSelectorVerbs(r.ctx, r.repo, r.runtime, facts)
			require.NoError(t, err)
			got, err := seed.RunBootstrapAdmin(r.ctx, r.runtime, nil, seed.BootstrapAdminInput{Email: email})
			require.NoError(t, err)
			require.False(t, got.Skipped)
			require.Equal(t, uid, got.UserID)
			var grants, bindings int
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*) FROM kaname.cluster_admin_grants WHERE subject_type='user' AND subject_id=$1 AND granted_until IS NULL`, uid).Scan(&grants))
			require.Equal(t, 1, grants)
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*) FROM kaname.access_bindings WHERE subject_type='user' AND subject_id=$1 AND resource_id=$2 AND status='ACTIVE' AND revoked_at IS NULL`, uid, r.a).Scan(&bindings))
			require.Positive(t, bindings)
			again, err := seed.RunBootstrapAdmin(r.ctx, r.runtime, nil, seed.BootstrapAdminInput{Email: email})
			require.NoError(t, err)
			require.True(t, again.Skipped)
			authorityWaitReleased(t, r.runtime)
		})
	}
}

// Историческая orphan-фикстура остаётся той же: мёртвую область убрать, живую сохранить.
// Существующий неблокирующий singleton lease уборки требует отдельного pool slot.
func TestInstallationOrphanSweepPreparedStrict(t *testing.T) {
	for _, strict := range []bool{false, true} {
		t.Run(map[bool]string{false: "prepared", true: "strict"}[strict], func(t *testing.T) {
			r := writerProtocolRig(t)
			f := setupOrphanScope(t, r.ctx, r.admin, "installation")
			if strict {
				require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
			}
			sweeper := seed.NewOrphanScopeSweeper(r.repo, kanamepg.NewOrphanScopeAdapter(r.runtime), seed.OrphanScopeConfig{})
			got, err := sweeper.RunOnce(r.ctx)
			require.NoError(t, err)
			require.True(t, got.Executed)
			require.Equal(t, 1, got.ScopesRevoked)
			require.Equal(t, 1, got.BindingsRevoked)
			require.Equal(t, 2, got.TuplesRetracted)
			require.Zero(t, bindingRowCount(t, r.ctx, r.admin, f.bDead))
			require.Zero(t, ledgerTupleCount(t, r.ctx, r.admin, f.bDead))
			require.Equal(t, 1, bindingRowCount(t, r.ctx, r.admin, f.bLive))
			require.Equal(t, 1, ledgerTupleCount(t, r.ctx, r.admin, f.bLive))
			require.ElementsMatch(t, f.deadRels, fgaOutboxRelations(t, r.ctx, r.admin, "fga.tuple.delete", f.objDead))
			require.Zero(t, countFGAOutbox(t, r.ctx, r.admin, "fga.tuple.delete", f.objLive))
			authorityWaitReleased(t, r.runtime)
		})
	}
}

// Отказ настоящего протокола не превращается в обычный незарегистрированный Writer.
func TestInstallationCatalogProtocolDenialDoesNotFallback(t *testing.T) {
	r := identityLifecycleSingle(t, writerProtocolRig(t))
	require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
	var allowed bool
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT has_function_privilege(current_user,'kaname.authority_installation_enter_v2(text)','EXECUTE')`).Scan(&allowed))
	require.True(t, allowed)
	quoted := pgx.Identifier{r.role}.Sanitize()
	_, err := r.admin.Exec(r.ctx, `REVOKE EXECUTE ON FUNCTION kaname.authority_installation_enter_v2(text) FROM `+quoted)
	require.NoError(t, err)
	called := false
	err = kanamepg.NewCatalogWriteRepo(r.runtime).RunInWriteTx(r.ctx, func(ctx context.Context, w modulecatalog.CatalogWriter) error {
		called = true
		_, e := w.UpsertModule(ctx, "installation_denied")
		return e
	})
	require.Error(t, err)
	require.False(t, called)
	var count int
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*) FROM kaname.catalog_module WHERE module='installation_denied'`).Scan(&count))
	require.Zero(t, count)
	authorityWaitReleased(t, r.runtime)
	_, err = r.admin.Exec(r.ctx, `GRANT EXECUTE ON FUNCTION kaname.authority_installation_enter_v2(text) TO `+quoted)
	require.NoError(t, err)
	require.NoError(t, kanamepg.NewCatalogWriteRepo(r.runtime).RunInWriteTx(r.ctx, func(ctx context.Context, w modulecatalog.CatalogWriter) error {
		_, e := w.UpsertModule(ctx, "installation_denied")
		return e
	}))
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*) FROM kaname.catalog_module WHERE module='installation_denied'`).Scan(&count))
	require.Equal(t, 1, count)
}
