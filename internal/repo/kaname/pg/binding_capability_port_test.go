// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	ab "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const capabilityPortUpdateSQL = "UPDATE kaname.access_bindings SET grant_capability_version=1 WHERE id=$1 AND grant_capability_version=0"

// Незапрошенные методы встроенных интерфейсов не реализованы: лишний вызов
// падает, а не получает от общего mock случайное успешное значение.
type capabilityPortBindingStub struct {
	ab.WriterIface
	insert func(context.Context, domain.AccessBinding) (domain.AccessBinding, error)
	ledger func(context.Context, domain.AccessBindingID, []ab.RelationTuple) error
}

func (s *capabilityPortBindingStub) Insert(ctx context.Context, b domain.AccessBinding) (domain.AccessBinding, error) {
	return s.insert(ctx, b)
}

func (s *capabilityPortBindingStub) InsertEmittedTuples(ctx context.Context, id domain.AccessBindingID, tuples []ab.RelationTuple) error {
	return s.ledger(ctx, id, tuples)
}

type capabilityPortTxStub struct {
	pgx.Tx
	exec func(context.Context, string, ...any) (pgconn.CommandTag, error)
}

func (s *capabilityPortTxStub) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	return s.exec(ctx, sql, args...)
}

func capabilityPortTestBinding(id domain.AccessBindingID) domain.AccessBinding {
	expires := time.Date(2026, time.November, 15, 12, 0, 0, 0, time.UTC)
	return domain.AccessBinding{
		ID: id, SubjectType: domain.SubjectTypeUser, SubjectID: "usr_first",
		RoleID: "rol_viewer", ResourceType: "project", ResourceID: "prj_scope",
		Scope: domain.ScopeProject, Status: "ACTIVE", ExpiresAt: &expires,
		CreatedAt:          time.Date(2026, time.November, 14, 12, 0, 0, 0, time.UTC),
		DeletionProtection: true, DelegationID: "gdl_source",
		Subjects: []domain.Subject{
			{Type: domain.SubjectTypeUser, ID: "usr_first"},
			{Type: domain.SubjectTypeUser, ID: "usr_second"},
		},
		Target: domain.AccessTarget{AllInScope: true},
	}
}

func TestBindingCapabilityPortInsertSequenceAndErrors(t *testing.T) {
	insertErr := errors.New("base Insert failure")
	execErr := errors.New("version UPDATE failure")
	for _, tc := range []struct {
		name               string
		insertErr, execErr error
		tag                string
		wantErr            error
	}{
		{"insert_error", insertErr, nil, "UPDATE 1", insertErr},
		{"exec_error", nil, execErr, "UPDATE 1", execErr},
		{"affected_zero", nil, nil, "UPDATE 0", kaname.ErrAuthorityClassificationChanged},
		{"affected_two", nil, nil, "UPDATE 2", kaname.ErrAuthorityClassificationChanged},
		{"affected_one", nil, nil, "UPDATE 1", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			proposed := capabilityPortTestBinding("ab_proposed")
			wantProposed := capabilityPortTestBinding("ab_proposed")
			created := capabilityPortTestBinding("ab_created")
			// Независимый expected: изменение Subjects/ExpiresAt у created
			// не меняет одновременно ожидаемый результат через общий указатель.
			wantCreated := capabilityPortTestBinding("ab_created")
			var events []string
			base := &capabilityPortBindingStub{insert: func(gotCtx context.Context, got domain.AccessBinding) (domain.AccessBinding, error) {
				events = append(events, "insert")
				if gotCtx != ctx || !reflect.DeepEqual(got, wantProposed) {
					t.Fatalf("Insert получил иной context/input: %+v", got)
				}
				return created, tc.insertErr
			}}
			tx := &capabilityPortTxStub{exec: func(gotCtx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
				events = append(events, "update")
				if gotCtx != ctx || sql != capabilityPortUpdateSQL || !reflect.DeepEqual(args, []any{string(created.ID)}) {
					t.Fatalf("UPDATE должен использовать точный SQL и CREATED id: sql=%q args=%v", sql, args)
				}
				return pgconn.NewCommandTag(tc.tag), tc.execErr
			}}
			port := &capabilityBindingWriter{WriterIface: base, tx: tx}
			if port.BindingCapabilityVersion() != 1 || len(events) != 0 {
				t.Fatal("marker должен быть 1 без DML")
			}
			got, err := port.Insert(ctx, proposed)
			if err != tc.wantErr {
				t.Fatalf("ошибка изменена: got=%v want=%v", err, tc.wantErr)
			}
			wantEvents := []string{"insert", "update"}
			if tc.insertErr != nil {
				wantEvents = []string{"insert"}
			}
			if !reflect.DeepEqual(events, wantEvents) {
				t.Fatalf("порядок/число операций: got=%v want=%v", events, wantEvents)
			}
			if tc.wantErr != nil {
				wantCreated = domain.AccessBinding{}
			}
			if !reflect.DeepEqual(got, wantCreated) {
				t.Fatalf("результат Insert изменён: got=%+v want=%+v", got, wantCreated)
			}
		})
	}
}

func TestBindingCapabilityPortDelegatesLedgerWithoutUpdate(t *testing.T) {
	ledgerErr := errors.New("ledger failure")
	for _, tc := range []struct {
		name string
		err  error
	}{{"success", nil}, {"error", ledgerErr}} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			tuples := []ab.RelationTuple{
				{User: "user:usr_first", Relation: "viewer", Object: "project:prj_scope"},
				{User: "project:prj_scope", Relation: "project", Object: "iam_access_binding:ab_created"},
			}
			wantTuples := append([]ab.RelationTuple(nil), tuples...)
			calls := 0
			base := &capabilityPortBindingStub{ledger: func(gotCtx context.Context, id domain.AccessBindingID, got []ab.RelationTuple) error {
				calls++
				if gotCtx != ctx || id != "ab_created" || !reflect.DeepEqual(got, wantTuples) || &got[0] != &tuples[0] {
					t.Fatalf("ledger не получил исходный полный набор/ID/context: %q %+v", id, got)
				}
				return tc.err
			}}
			tx := &capabilityPortTxStub{exec: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
				t.Fatal("не-Insert метод не должен повышать capability version")
				return pgconn.CommandTag{}, nil
			}}
			port := &capabilityBindingWriter{WriterIface: base, tx: tx}
			if err := port.InsertEmittedTuples(ctx, "ab_created", tuples); err != tc.err || calls != 1 {
				t.Fatalf("ledger не делегирован ровно один раз: err=%v calls=%d", err, calls)
			}
		})
	}
}

func TestSemanticBindingCapabilityPortUsesOneTransaction(t *testing.T) {
	tx := &capabilityPortTxStub{exec: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
		t.Fatal("сборка порта не должна выполнять DML")
		return pgconn.CommandTag{}, nil
	}}
	base := &authorityWriteTx{writeTx: &writeTx{readTx: readTx{tx: tx}}}
	semantic := &semanticAuthorityWriteTx{authorityWriteTx: base}
	if _, marked := base.AccessBindingsW().(kaname.BindingCapabilityWriter); marked {
		t.Fatal("исходный raw-порт неожиданно получил semantic marker")
	}
	for range 2 {
		port, ok := semantic.AccessBindingsW().(*capabilityBindingWriter)
		if !ok {
			t.Fatal("semantic accessor вернул порт без private decorator")
		}
		underlying, ok := port.WriterIface.(*abWriter)
		if !ok || underlying == nil || underlying.tx != tx || port.tx != tx || port.BindingCapabilityVersion() != 1 {
			t.Fatal("base Insert и capability UPDATE должны использовать одну исходную транзакцию")
		}
	}
}

func TestInviteBindingCapabilityPortPreparedDelegation(t *testing.T) {
	insertErr := errors.New("invite Insert failure")
	for _, mode := range []string{"raw", "semantic"} {
		t.Run(mode, func(t *testing.T) {
			for _, name := range []string{"matching", "different_subjects", "different_scope", "empty_prepared_id", "insert_error"} {
				t.Run(name, func(t *testing.T) {
					ctx := t.Context()
					prepared := &preparedInvite{binding: capabilityPortTestBinding("ab_prepared")}
					input := prepared.Binding()
					var wantErr error
					switch name {
					case "different_subjects":
						input.Subjects[1].ID = "usr_other"
						wantErr = kaname.ErrInvalidAuthorityFencePlan
					case "different_scope":
						input.ResourceID = "prj_other"
						wantErr = kaname.ErrInvalidAuthorityFencePlan
					case "empty_prepared_id":
						prepared.binding.ID = ""
						input = prepared.Binding()
						wantErr = kaname.ErrInvalidAuthorityFencePlan
					case "insert_error":
						wantErr = insertErr
					}
					created := capabilityPortTestBinding("ab_created")
					var events []string
					base := &capabilityPortBindingStub{insert: func(gotCtx context.Context, b domain.AccessBinding) (domain.AccessBinding, error) {
						events = append(events, "insert")
						if gotCtx != ctx || !reflect.DeepEqual(b, capabilityPortTestBinding("ab_prepared")) {
							t.Fatal("invite изменил prepared input или context")
						}
						if name == "insert_error" {
							return domain.AccessBinding{}, insertErr
						}
						return created, nil
					}}
					tx := &capabilityPortTxStub{exec: func(gotCtx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
						events = append(events, "update")
						if gotCtx != ctx || sql != capabilityPortUpdateSQL || !reflect.DeepEqual(args, []any{"ab_created"}) {
							t.Fatal("invite semantic delegate изменил UPDATE/created ID/context")
						}
						return pgconn.NewCommandTag("UPDATE 1"), nil
					}}
					var delegate ab.WriterIface = base
					if mode == "semantic" {
						delegate = &capabilityBindingWriter{WriterIface: base, tx: tx}
					}
					port := &inviteBindingWriter{WriterIface: delegate, prepared: prepared}
					got, err := port.Insert(ctx, input)
					if err != wantErr {
						t.Fatalf("invite error got=%v want=%v", err, wantErr)
					}
					var wantEvents []string
					if wantErr != kaname.ErrInvalidAuthorityFencePlan {
						wantEvents = []string{"insert"}
						if mode == "semantic" && wantErr == nil {
							wantEvents = append(wantEvents, "update")
						}
					}
					if !reflect.DeepEqual(events, wantEvents) {
						t.Fatalf("invite не сохранил delegation/отказ до DML: got=%v want=%v", events, wantEvents)
					}
					wantCreated := capabilityPortTestBinding("ab_created")
					if wantErr != nil {
						wantCreated = domain.AccessBinding{}
					}
					if !reflect.DeepEqual(got, wantCreated) {
						t.Fatal("invite изменил результат underlying Insert")
					}
				})
			}
		})
	}
}
