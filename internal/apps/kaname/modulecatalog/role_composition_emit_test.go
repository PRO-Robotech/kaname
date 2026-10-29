// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package modulecatalog_test

// role_composition_emit_test.go — путь последствий каталога даёт роли,
// потерявшей строку проекции, ОДНО событие на транзакцию (kaname#76, приёмка
// `catalog-consequence-reaches-role-readers.md` §3.1).
//
// Здесь утверждается то, что видно без базы: множество ролей берётся из ВЫХОДА
// операторов отбора, а функция события зовётся ОДИН раз и ПОСЛЕ всех шагов
// последствий. Поздно — несущее: транзакция, писавшая в журнал, держит порог
// доставки всего потока службы до коммита, и ранняя запись растянула бы эту
// задержку на снятие действий, ресурсов и вырезание. Сама функция, её
// оболочка и гашение повтора доказаны против живой Postgres
// (`catalog_consequence_reaches_role_readers_integration_test.go`).

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// composingWriter — писатель, у которого операторы отбора отдают тронутые роли.
type composingWriter struct {
	pruningWriter
	resettledRoles []domain.RoleID
	prunedRoles    []domain.RoleID
	emitErr        error
	emitted        [][]domain.RoleID
}

func (w *composingWriter) ResettleTenantProjections(_ context.Context,
	_ []catalog.ResourceRow, _ []catalog.VerbRow, _ string, _ string) (modulecatalog.Resettled, error) {
	w.calls = append(w.calls, "resettle")
	return modulecatalog.Resettled{RuleRefs: len(w.resettledRoles), Roles: w.resettledRoles}, nil
}

func (w *composingWriter) PruneRetiredSelectorTypes(_ context.Context,
	_ []catalog.ResourceRow, _ string) (modulecatalog.Pruned, error) {
	w.calls = append(w.calls, "prune")
	return modulecatalog.Pruned{Rows: len(w.prunedRoles), Elements: len(w.prunedRoles), Roles: w.prunedRoles}, nil
}

func (w *composingWriter) EmitRoleComposition(_ context.Context, roles []domain.RoleID) error {
	ids := make([]string, 0, len(roles))
	for _, r := range roles {
		ids = append(ids, string(r))
	}
	w.calls = append(w.calls, "role_composition:"+strings.Join(ids, ","))
	w.emitted = append(w.emitted, roles)
	return w.emitErr
}

type composingTx struct{ w *composingWriter }

func (r *composingTx) RunInWriteTx(ctx context.Context,
	fn func(context.Context, modulecatalog.CatalogWriter) error) error {
	return fn(ctx, r.w)
}

// indexOf — позиция первого вызова с префиксом; -1, если его нет.
func indexOf(calls []string, prefix string) int {
	for i, c := range calls {
		if strings.HasPrefix(c, prefix) {
			return i
		}
	}
	return -1
}

func TestRoleComposition_OneCallAfterEveryConsequenceStep(t *testing.T) {
	w := &composingWriter{
		pruningWriter:  pruningWriter{live: liveTwo()},
		resettledRoles: []domain.RoleID{"rolB", "rolA"},
		prunedRoles:    []domain.RoleID{"rolC", "rolB"},
	}
	_, err := modulecatalog.NewApplier(&composingTx{w: w}).Apply(context.Background(), fixtureManifest("vpc", "network"))
	require.NoError(t, err)

	require.Len(t, w.emitted, 1,
		"функция события звана %d раз — одна транзакция обязана звать её один раз на "+
			"объединённое множество (журнал: %v)", len(w.emitted), w.calls)
	require.Equal(t, []domain.RoleID{"rolA", "rolB", "rolC"}, w.emitted[0],
		"множество ролей — объединение выходов операторов отбора, без повторов и в "+
			"детерминированном порядке")

	at := indexOf(w.calls, "role_composition:")
	for _, step := range []string{"resettle", "retire_verb:", "retire_resource:", "prune"} {
		if i := indexOf(w.calls, step); i >= 0 {
			require.Greaterf(t, at, i,
				"событие роли записано ДО шага %q: транзакция держала бы порог доставки "+
					"потока службы дольше, чем нужно (журнал: %v)", step, w.calls)
		}
	}
	if audit := indexOf(w.calls, "audit:"); audit >= 0 {
		require.Less(t, at, audit, "событие роли — до следа применения, внутри той же транзакции")
	}
}

// TestRoleComposition_NothingTakenEmitsNothing — близнец: снятие, не тронувшее
// ни одной роли, функцию не зовёт.
func TestRoleComposition_NothingTakenEmitsNothing(t *testing.T) {
	w := &composingWriter{pruningWriter: pruningWriter{live: liveTwo()}}
	_, err := modulecatalog.NewApplier(&composingTx{w: w}).Apply(context.Background(), fixtureManifest("vpc", "network"))
	require.NoError(t, err)
	require.Empty(t, w.emitted, "событие роли без тронутых ролей (журнал: %v)", w.calls)
}

// TestRoleComposition_JournalRefusalFailsTheApply — отказ функции события —
// отказ применения целиком: событие и отбор неделимы.
func TestRoleComposition_JournalRefusalFailsTheApply(t *testing.T) {
	refusal := errors.New("журнал отказал")
	w := &composingWriter{
		pruningWriter:  pruningWriter{live: liveTwo()},
		resettledRoles: []domain.RoleID{"rolA"},
		emitErr:        refusal,
	}
	_, err := modulecatalog.NewApplier(&composingTx{w: w}).Apply(context.Background(), fixtureManifest("vpc", "network"))
	require.ErrorIs(t, err, refusal, "отказ журнала проглочен — отбор зафиксировался бы без события")
	require.ErrorIs(t, err, modulecatalog.ErrWriteFailed)
}
