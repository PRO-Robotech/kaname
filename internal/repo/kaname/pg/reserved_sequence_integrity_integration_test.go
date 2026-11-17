// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

func TestPreparedMetadataSequenceRejectsMissingReplayedForeignAndCrossFamilyEffects(t *testing.T) {
	for _, probe := range []string{"missing", "replay", "wrong-origin", "foreign-id", "unplanned-fga"} {
		t.Run(probe, func(t *testing.T) {
			w := metadataFixture(t, false)
			observedRepo, observed := sequenceObservedFullRepo(t, w.r)
			var err error
			w.factory, err = kanamepg.NewMetadataMutationWriters(w.r.ctx, observedRepo, w.r.bundle)
			require.NoError(t, err)
			before := metadataSnapshot(t, w)
			changed := w.project
			changed.Description = "exact sequence metadata"
			writer, err := w.factory.ProjectMetadataWriter(w.r.ctx, changed, []string{"description"}, w.subject(w.actor))
			require.NoError(t, err)
			defer writer.Rollback(context.WithoutCancel(w.r.ctx))
			switch probe {
			case "missing":
				err = kanamepg.MetadataSequenceProbeForTest(w.r.ctx, writer, "commit")
			case "replay":
				_, err = writer.ProjectsW().Update(w.r.ctx, changed, []string{"description"})
				require.NoError(t, err)
				// Второе реальное изменение не может потребить прежний origin/ordinal.
				changed.Description = "unplanned second event"
				_, err = writer.ProjectsW().Update(w.r.ctx, changed, []string{"description"})
			default:
				err = kanamepg.MetadataSequenceProbeForTest(w.r.ctx, writer, probe)
			}
			require.Error(t, err)
			var pe *pgconn.PgError
			// Repo mapper намеренно скрывает PgError; наблюдаем тот же actual SQL до mapper.
			require.ErrorAs(t, observed.last(), &pe)
			require.Equal(t, "42501", pe.Code)
			_ = writer.Rollback(context.WithoutCancel(w.r.ctx))
			require.Equal(t, before, metadataSnapshot(t, w), "отказ откатывает row, journal, audit и reconcile")
		})
	}
}

func TestPreparedMetadataSequenceConsumesExactEventAndAcceptsZeroEffectProgram(t *testing.T) {
	w := metadataFixture(t, false)
	for _, change := range []bool{true, false} {
		t.Run(map[bool]string{true: "one-event", false: "unchanged"}[change], func(t *testing.T) {
			rd, err := w.r.repo.Reader(w.r.ctx)
			require.NoError(t, err)
			current, err := rd.Projects().Get(w.r.ctx, w.project.ID)
			require.NoError(t, err)
			require.NoError(t, rd.Rollback(w.r.ctx))
			var before int
			require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(*) FROM kaname.resource_journal WHERE resource_kind='project' AND resource_id=$1`, string(current.ID)).Scan(&before))
			if change {
				current.Description = "committed exact sequence"
			}
			writer, err := w.factory.ProjectMetadataWriter(w.r.ctx, current, []string{"description"}, w.subject(w.actor))
			require.NoError(t, err)
			defer writer.Rollback(context.WithoutCancel(w.r.ctx))
			got, err := writer.ProjectsW().Update(w.r.ctx, current, []string{"description"})
			require.NoError(t, err)
			require.Equal(t, current.Description, got.Description)
			require.NoError(t, writer.Commit(w.r.ctx))
			var after int
			require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(*) FROM kaname.resource_journal WHERE resource_kind='project' AND resource_id=$1`, string(current.ID)).Scan(&after))
			want := before
			if change {
				want++
			}
			require.Equal(t, want, after, "пустая выбранная программа не создаёт dummy journal rows")
		})
	}
}

func TestBindingAuthorizationModeCannotMutateAndMutationCannotOmitSelectedEffects(t *testing.T) {
	for _, mode := range []string{"authorization", "authorization-commit", "mutation-missing", "legacy-metadata"} {
		t.Run(mode, func(t *testing.T) {
			r := writerProtocolRig(t)
			seed := stageBinding(t, r, r.a, false)
			proposal := bindingRow(t, r, seed)
			actor := policyActor(t, r, r.a)
			_, _ = fullContractActivate(t, r)
			full, observed := sequenceObservedFullRepo(t, r)
			factory, err := kanamepg.NewGrantPolicyWriters(r.ctx, full, r.bundle)
			require.NoError(t, err)
			before := sevenCRUDCommandSnapshot(t, r)
			called := false
			callback := func(ctx context.Context, writer kaname.SemanticAuthorityWriter, _ domain.AccessBinding, _ domain.Role) error {
				called = true
				if mode == "authorization-commit" {
					return writer.Commit(ctx)
				}
				if mode == "authorization" {
					_, err := writer.AccessBindingsW().SetDeletionProtection(ctx, seed, !proposal.DeletionProtection)
					return err
				}
				return nil
			}
			switch mode {
			case "authorization", "authorization-commit":
				err = factory.RunBindingAuthorizationDecision(r.ctx, actor, proposal, false, false, nil, callback)
			case "mutation-missing":
				err = factory.RunBindingMetadataDecision(r.ctx, actor, kaname.BindingMetadataDecision{ID: seed, ApplyDeletionProtection: true, DeletionProtection: !proposal.DeletionProtection}, callback)
			default:
				err = factory.RunBindingDecision(r.ctx, actor, proposal, false, nil, callback)
			}
			require.Error(t, err)
			if mode == "legacy-metadata" {
				require.False(t, called)
				require.ErrorIs(t, err, kaname.ErrInvalidAuthorityFencePlan)
			} else {
				require.True(t, called)
				var pe *pgconn.PgError
				require.ErrorAs(t, observed.last(), &pe)
				require.Equal(t, "42501", pe.Code)
			}
			require.Equal(t, before, sevenCRUDCommandSnapshot(t, r))
		})
	}
}

// Исчерпание actual BIGSERIAL не переносится в тело после финальных часов:
// owner GIVEN меняет только счётчик; отказ фабрики не публикует business rows.
func TestPreparedMetadataSequenceExhaustionRefusesBeforeBodyWithoutEffects(t *testing.T) {
	w := metadataFixture(t, false)
	before := metadataSnapshot(t, w)
	var last, maximum, cache int64
	require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT last_value FROM kaname.resource_journal_sequence_no_seq`).Scan(&last))
	require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT seqmax,seqcache FROM pg_sequence WHERE seqrelid='kaname.resource_journal_sequence_no_seq'::regclass`).Scan(&maximum, &cache))
	require.Positive(t, last)
	_, err := w.r.admin.Exec(w.r.ctx, fmt.Sprintf(`ALTER SEQUENCE kaname.resource_journal_sequence_no_seq MAXVALUE %d CACHE 1 NO CYCLE`, last))
	require.NoError(t, err)
	t.Cleanup(func() {
		_, e := w.r.admin.Exec(context.WithoutCancel(w.r.ctx), fmt.Sprintf(`ALTER SEQUENCE kaname.resource_journal_sequence_no_seq MAXVALUE %d CACHE %d NO CYCLE`, maximum, cache))
		require.NoError(t, e)
	})
	changed := w.project
	changed.Description = "cannot allocate reserved event"
	writer, err := w.factory.ProjectMetadataWriter(w.r.ctx, changed, []string{"description"}, w.subject(w.actor))
	if writer != nil {
		_ = writer.Rollback(w.r.ctx)
	}
	require.Nil(t, writer)
	var pe *pgconn.PgError
	require.ErrorAs(t, err, &pe)
	require.Equal(t, "2200H", pe.Code, "исчерпан настоящий счётчик PostgreSQL")
	require.Equal(t, before, metadataSnapshot(t, w))
}

// Наблюдатель получает исходный PgError обычного LOGIN до repository mapper.
// Он не подменяет SQL, ответ native checker, attestation или транзакцию фабрики.
// Ограниченный канал хранит Code/Message/Where, без TraceQueryStart SQL, аргументов и Detail.
// Hook ничего не исполняет и не делает assertions; вывод принадлежит потоку теста.
type sequenceSQLFailure struct{ code, message, where string }
type sequenceSQLErrorObserver struct {
	mu      sync.Mutex
	err     error
	records chan sequenceSQLFailure
}

func sequenceSQLBounded(s string, limit int) string {
	if len(s) > limit {
		return s[:limit]
	}
	return s
}
func (o *sequenceSQLErrorObserver) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	return ctx
}
func (o *sequenceSQLErrorObserver) TraceQueryEnd(_ context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	var pe *pgconn.PgError
	if errors.As(data.Err, &pe) {
		o.mu.Lock()
		// После первого отказа rollback может породить только вторичный 25P02.
		if o.err == nil {
			o.err = pe
		}
		o.mu.Unlock()
		select {
		case o.records <- sequenceSQLFailure{sequenceSQLBounded(pe.Code, 5), sequenceSQLBounded(pe.Message, 512), sequenceSQLBounded(pe.Where, 2048)}:
		default:
		}
	}
}
func (o *sequenceSQLErrorObserver) take() []sequenceSQLFailure {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	o.err = nil
	o.mu.Unlock()
	var records []sequenceSQLFailure
	for len(records) < cap(o.records) {
		select {
		case record := <-o.records:
			records = append(records, record)
		default:
			return records
		}
	}
	return records
}
func (o *sequenceSQLErrorObserver) last() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.err
}
func sequenceObservedFullRepo(t *testing.T, r protocolRig) (*kanamepg.Repository, *sequenceSQLErrorObserver) {
	t.Helper()
	observed := &sequenceSQLErrorObserver{records: make(chan sequenceSQLFailure, 8)}
	cfg := r.runtime.Config()
	cfg.ConnConfig.Tracer = observed
	pool, err := pgxpool.NewWithConfig(r.ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	repo := kanamepg.New(pool, nil)
	contract, err := kanamepg.NewFullWriterContract(r.ctx, repo, r.bundle)
	require.NoError(t, err)
	full, err := repo.WithFullWriterContract(contract)
	require.NoError(t, err)
	return full, observed
}

// Старый signed decision допустим в contract1. В contract2 тот же lower-level
// путь не получает пустую reservation автоматически и не может выполнить body.
func TestSequenceReservationDistinguishesAttestedContractOneAndTwo(t *testing.T) {
	for _, fullContract := range []bool{false, true} {
		t.Run(map[bool]string{false: "contract1", true: "contract2"}[fullContract], func(t *testing.T) {
			r := writerProtocolRig(t)
			repo := r.repo
			var observed *sequenceSQLErrorObserver
			if fullContract {
				_, _ = fullContractActivate(t, r)
				repo, observed = sequenceObservedFullRepo(t, r)
			} else {
				require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
			}
			factory, err := kanamepg.NewGrantPolicyWriters(r.ctx, repo, r.bundle)
			require.NoError(t, err)
			role := policyNewRole(r.a)
			role.ID = domain.RoleID(ids.NewID("rol"))
			before := sevenCRUDCommandSnapshot(t, r)
			writer, err := factory.RoleAuthorityWriter(r.ctx, role, true, policyActor(t, r, r.a))
			require.NoError(t, err)
			defer writer.Rollback(context.WithoutCancel(r.ctx))
			_, err = writer.RolesW().Insert(r.ctx, role)
			if fullContract {
				require.Error(t, err)
				var pe *pgconn.PgError
				require.ErrorAs(t, observed.last(), &pe)
				require.Equal(t, "42501", pe.Code)
			} else {
				require.NoError(t, err)
			}
			require.NoError(t, writer.Rollback(r.ctx))
			require.Equal(t, before, sevenCRUDCommandSnapshot(t, r))
		})
	}
}
