// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// client_expiry_immutable_injection_test.go — доказательство падучести
// TestClientExpiryIsNeverUpdated в обе стороны, на синтетике.
package check_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/migrations"
)

const clientExpiryInjectedUpdate = `package pg

func (r *repo) bumpExpiry(id string, expiresAt int64) error {
	const q = ` + "`" + `UPDATE user_oauth_clients SET expires_at = $2 WHERE id = $1` + "`" + `
	_, err := r.pool.Exec(nil, q, id, expiresAt)
	return err
}
`

const clientExpiryLawfulTwin = `package pg

func (r *repo) touchLabel(id, label string) error {
	const q = ` + "`" + `UPDATE user_oauth_clients SET label = $2 WHERE id = $1` + "`" + `
	_, err := r.pool.Exec(nil, q, id, label)
	return err
}

func (r *repo) create(id string, expiresAt int64) error {
	const q = ` + "`" + `INSERT INTO user_oauth_clients (id, expires_at) VALUES ($1, $2)` + "`" + `
	_, err := r.pool.Exec(nil, q, id, expiresAt)
	return err
}

func (r *repo) get(id string) (int64, error) {
	const q = ` + "`" + `SELECT expires_at FROM user_oauth_clients WHERE id = $1` + "`" + `
	var v int64
	err := r.pool.QueryRow(nil, q, id).Scan(&v)
	return v, err
}
`

// TestClientExpiryImmutableInjection_ColumnInSet — правка `expires_at` в SET
// — находка; правка ДРУГОГО столбца, INSERT и SELECT на том же столбце —
// молчание.
func TestClientExpiryImmutableInjection_ColumnInSet(t *testing.T) {
	t.Parallel()
	updates, census, err := check.ScanSQLUpdates("synthetic/bad.go", []byte(clientExpiryInjectedUpdate),
		[]string{"user_oauth_clients", "service_account_oauth_clients"})
	if err != nil {
		t.Fatalf("разбор синтетики: %v", err)
	}
	if census.SQLLiterals == 0 {
		t.Fatalf("осмотрено ноль SQL-литералов — разбирается не то дерево")
	}
	var found bool
	for _, u := range updates {
		for _, c := range u.Columns {
			if c == "expires_at" {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("ИНЪЕКЦИЯ: правка expires_at не найдена разбором: %+v", updates)
	}

	twin, twinCensus, err := check.ScanSQLUpdates("synthetic/twin.go", []byte(clientExpiryLawfulTwin),
		[]string{"user_oauth_clients", "service_account_oauth_clients"})
	if err != nil {
		t.Fatalf("разбор близнеца: %v", err)
	}
	if twinCensus.Updates != 1 {
		t.Fatalf("у близнеца обязан быть РОВНО один оператор правки (touchLabel — единственный "+
			"UPDATE; create — INSERT, get — SELECT); найдено %d: %+v", twinCensus.Updates, twin)
	}
	for _, u := range twin {
		for _, c := range u.Columns {
			if c == "expires_at" {
				t.Errorf("ЗАКОННЫЙ БЛИЗНЕЦ: гейт покраснел на правке столбца label, "+
					"создании и чтении expires_at, приняв их за правку срока: %+v", u)
			}
		}
	}
}

// TestClientExpiryImmutableInjection_TableBody — CREATE TABLE находится, и
// колонка внутри — тоже.
func TestClientExpiryImmutableInjection_TableBody(t *testing.T) {
	t.Parallel()
	sql := "-- +goose Up\n" +
		"CREATE TABLE user_oauth_clients (\n\tid text PRIMARY KEY,\n\texpires_at timestamptz NOT NULL\n);\n" +
		"-- +goose Down\nDROP TABLE user_oauth_clients;\n"
	up := migrations.MigrationUpSection(sql)
	body := check.SQLCreateTableBody(up, "user_oauth_clients")
	if body == "" || !strings.Contains(body, "expires_at") {
		t.Fatalf("тело CREATE TABLE не разобрано либо не несёт expires_at: %q", body)
	}
	if check.SQLCreateTableBody(up, "no_such_table") != "" {
		t.Fatalf("разбор нашёл таблицу, которой нет в тексте")
	}
	// Имя таблицы в Down-секции (DROP TABLE) не должно попасть в тело —
	// секция отрезается по сырому маркеру ДО забеливания комментариев.
	if strings.Contains(up, "DROP TABLE") {
		t.Fatalf("Up-секция несёт DROP TABLE из Down — граница секций разобрана неверно")
	}
}
