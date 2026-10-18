// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

// target_forms_integration_test.go — та же таблица форм (target_forms_test.go), судимая базой
// и SQL-прочтением решения о доступе (kaname#863).
//
// По каждой строке:
//
//   - база: законная форма вставляется и становится значением обновления,
//     форма вне контракта отвергается и вставкой, и обновлением — ограничением
//     `access_bindings_target_form_ck`, SQLSTATE 23514;
//   - решение о доступе: на каждой ЗАКОННОЙ форме `wholeScopeTarget` и `namedInTarget`
//     дают тот же класс, что `DecodeTarget`, по каждой паре из `tfProbes`.
//
// Вместе с unit-частью это даёт замкнутое утверждение: `DecodeTarget` принимает
// ровно то, что принимает база (вне контракта — `ErrForm` и отказ базы на
// одних и тех же строках), а на всём, что база принимает, оба прочтения
// говорят одно. Класс SQL-прочтения на форме вне контракта не обещается и не
// судится: такой строки в таблице быть не может, её держит ограничение.

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
)

// tfSQLReading — ответ SQL-прочтения: вся область и названность каждой пары.
func tfSQLReading(ctx context.Context, tx pgx.Tx, target string) (whole bool, named []bool, err error) {
	q := `SELECT COALESCE(` + relverdict.WholeScopeTargetSQL + `, false)`
	args := []any{target}
	for i, p := range tfProbes {
		q += fmt.Sprintf(`, COALESCE(`+relverdict.NamedInTargetSQL("$%d::text", "$%d::text")+`, false)`,
			2+2*i, 3+2*i)
		args = append(args, p.Type, p.ID)
	}
	q += ` FROM (SELECT $1::jsonb AS target) AS b`
	named = make([]bool, len(tfProbes))
	dest := []any{&whole}
	for i := range named {
		dest = append(dest, &named[i])
	}
	err = tx.QueryRow(ctx, q, args...).Scan(dest...)
	return whole, named, err
}

func TestTargetFormIsReadAlikeByTheBaseAndBothReaders(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, pgtest.NewDB(t))
	if err != nil {
		t.Fatalf("пул: %v", err)
	}
	t.Cleanup(pool.Close)

	// Роль владельца аккаунта из посева цепи: выдача на аккаунт — её законная область.
	var role string
	if err := pool.QueryRow(ctx, `SELECT id FROM kaname.roles WHERE id = 'rol' || substr(md5('owner'), 1, 17)`).Scan(&role); err != nil {
		t.Fatalf("НЕ-ВЫПОЛНИЛОСЬ(фикстура): посев цепи несёт роль владельца аккаунта: %v", err)
	}

	var judged int
	for i, f := range tfForms {
		t.Run(f.name, func(t *testing.T) {
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(ctx) }()

			// Субъект и область — живые: стражи ссылок выдачи судят их на
			// вставке. Аккаунт раньше владельца — отложенный ключ владельца
			// проверяется на фиксации, которой здесь нет (транзакция откатывается).
			tenant := fmt.Sprintf("atf%04d", i)
			acc, usr := "acc"+tenant, "usr"+tenant
			if _, err := tx.Exec(ctx, `INSERT INTO kaname.accounts (id, name, owner_user_id) VALUES ($1, $1, $2)`, acc, usr); err != nil {
				t.Fatalf("НЕ-ВЫПОЛНИЛОСЬ(фикстура): аккаунт: %v", err)
			}
			if _, err := tx.Exec(ctx, `INSERT INTO kaname.users (id, external_id, email, account_id)
			    VALUES ($1, $1, $1 || '@example.invalid', $2)`, usr, acc); err != nil {
				t.Fatalf("НЕ-ВЫПОЛНИЛОСЬ(фикстура): личность: %v", err)
			}

			// Решение о доступе — на законной форме.
			if f.legal {
				whole, named, err := tfSQLReading(ctx, tx, f.json)
				if err != nil {
					t.Fatalf("SQL-прочтение %s: %v", f.json, err)
				}
				if whole != f.whole {
					t.Errorf("wholeScopeTarget(%s) = %v, ждали %v (как DecodeTarget)", f.json, whole, f.whole)
				}
				for j, p := range tfProbes {
					if named[j] != f.wantNamed(p) {
						t.Errorf("namedInTarget(%s, %s, %s) = %v, ждали %v (как DecodeTarget)", f.json, p.Type, p.ID, named[j], f.wantNamed(p))
					}
				}
			}

			// База: вставка.
			id := fmt.Sprintf("acbatf%04d", i)
			legalRow := `{"allInScope": true}`
			ins := func(target string) error {
				_, err := tx.Exec(ctx, `SAVEPOINT f`)
				if err != nil {
					return err
				}
				_, err = tx.Exec(ctx, `INSERT INTO kaname.access_bindings
				    (id, subject_type, subject_id, role_id, resource_type, resource_id, status, target)
				  VALUES ($1, 'user', $2, $3, 'account', $4, 'ACTIVE', $5::jsonb)`,
					id, usr, role, acc, target)
				if err != nil {
					_, _ = tx.Exec(ctx, `ROLLBACK TO SAVEPOINT f`)
				}
				return err
			}
			upd := func(target string) error {
				_, err := tx.Exec(ctx, `SAVEPOINT u`)
				if err != nil {
					return err
				}
				_, err = tx.Exec(ctx, `UPDATE kaname.access_bindings SET target = $2::jsonb WHERE id = $1`, id, target)
				if err != nil {
					_, _ = tx.Exec(ctx, `ROLLBACK TO SAVEPOINT u`)
				}
				return err
			}
			if f.legal {
				if err := ins(f.json); err != nil {
					t.Fatalf("законная форма %s: вставка отвергнута: %v", f.json, err)
				}
				if err := upd(legalRow); err != nil {
					t.Fatalf("законная форма: обновление в %s: %v", legalRow, err)
				}
				if err := upd(f.json); err != nil {
					t.Fatalf("законная форма %s: обновление отвергнуто: %v", f.json, err)
				}
				return
			}
			tfRefused(t, "вставка", f.json, ins(f.json))
			if err := ins(legalRow); err != nil {
				t.Fatalf("близнец: законная %s вставляется: %v", legalRow, err)
			}
			tfRefused(t, "обновление", f.json, upd(f.json))
		})
		judged++
	}
	t.Logf("перепись: форм таблицы %d, судимых базой и обоими прочтениями %d", len(tfForms), judged)
	if judged != len(tfForms) || judged == 0 {
		t.Fatalf("предпосылка: судимых %d из %d", judged, len(tfForms))
	}
}

// tfRefused — отказ базы именно ограничением формы, SQLSTATE 23514.
func tfRefused(t *testing.T, op, target string, err error) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		t.Fatalf("%s %s: база ПРИНЯЛА форму вне контракта (ошибка %v)", op, target, err)
	}
	if pgErr.ConstraintName != relverdict.TargetFormConstraint || pgErr.Code != "23514" {
		t.Fatalf("%s %s: ждали %s/23514, получено %s/%s: %v", op, target,
			relverdict.TargetFormConstraint, pgErr.ConstraintName, pgErr.Code, err)
	}
}
