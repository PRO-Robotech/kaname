// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// granted_relation_revoked_injection_test.go — ОТОЗВАННОЕ отношение модель
// требовать не обязана, и это доказывается инъекцией в обе стороны.
//
// # Зачем ось вообще
//
// Гейт выдачи читает ТЕКСТ всех миграций и позднейший отзыв не вычитает.
// Применённую миграцию не правят (запрет #5), поэтому выдача, записанная в
// сведённом посеве, держала бы своё отношение в модели НАВСЕГДА — снять его
// стало бы невозможно by construction, а не трудно.
//
// # Почему это не послабление
//
// Послабление прощало бы существующее нарушение. Здесь предмета нарушения
// НЕТ: после отзыва в очереди не остаётся ни одной строки, называющей это
// отношение, — то есть отравиться нечему. Это утверждение о РАНТАЙМЕ, и
// держит его не разбор текста, а интеграционная проба отзыва
// (`internal/migrations/limit_reader_grant_revoked_integration_test.go`,
// утверждение «очередь не несёт ни одной строки про это отношение»). Здесь —
// только текстовая половина, и её граница названа: разбор видит НАМЕРЕНИЕ
// миграции, а не исход её наката.
//
// # Точность важнее широты
//
// Отзыв ОДНОГО отношения не освобождает соседнее: иначе всякая миграция,
// снимающая выдачи, гасила бы ось целиком. Ниже это отдельное утверждение, а
// не следствие.
package check_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// injGrantingMigration — сведённый посев: выдаёт `cluster#quota_reader` ГОТОВОЙ
// формой JSON, как это делает первичная миграция после сведения.
const injGrantingMigration = `-- +goose Up
INSERT INTO kaname.fga_outbox (id, event_type, payload, created_at) VALUES
  (13, 'fga.tuple.write', '{"user": "group:g1#member", "object": "cluster:root", "relation": "quota_reader"}', now());
`

// injRevokingMigration — отзыв ровно той формы, какой его пишет дерево:
// отношение названо ОДИН раз константой, а оператор удаления берёт её.
const injRevokingMigration = `-- +goose Up
DO $$
DECLARE
    v_relation CONSTANT text := 'quota_reader';
BEGIN
    INSERT INTO kaname.audit_outbox (id, event_type, tenant_account_id, event_payload)
    SELECT 'evt_x', 'iam.access_binding.revoked', 'acc1', '{}'::jsonb
      FROM kaname.access_bindings WHERE granted_relation = v_relation;
    DELETE FROM kaname.access_bindings WHERE granted_relation = v_relation;
END
$$;
`

// injRevokingOther — отзыв ДРУГОГО отношения. Законный близнец: ось обязана
// молчать о нём и НЕ гасить находку по `quota_reader`.
const injRevokingOther = `-- +goose Up
DO $$
DECLARE
    v_relation CONSTANT text := 'other_reader';
BEGIN
    DELETE FROM kaname.access_bindings WHERE granted_relation = v_relation;
END
$$;
`

// injDeletesWithoutNamingARelation — удаление выдач, не называющее отношения
// ни одним литералом. Бланкетного освобождения быть не должно.
const injDeletesWithoutNamingARelation = `-- +goose Up
DELETE FROM kaname.access_bindings WHERE subject_type = 'service_account';
`

// injModelWithoutQuotaReader — применяемая модель БЕЗ снимаемого отношения.
const injModelWithoutQuotaReader = `
model
  schema 1.1

type user

type group
    relations
        define member: [user]

type cluster
    relations
        define system_admin: [user]
`

// mkRevokeTree — синтетический корень с перечисленными миграциями.
func mkRevokeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "internal", "migrations")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestGrantedRelationGate_RevokedRelationIsNotRequiredInTheModel(t *testing.T) {
	t.Parallel()

	model := check.RelationsByType(injModelWithoutQuotaReader)
	if len(model) == 0 {
		t.Fatal("модель-фикстура не разобрана — утверждения ниже беспредметны")
	}

	cases := []struct {
		name        string
		files       map[string]string
		wantMissing bool
		wantRevoked int
	}{
		{
			// НЕСУЩЕЕ: выдача есть, отзыв есть, отношения в модели нет — находки нет.
			name: "выдача отозвана позднейшей миграцией — модель её не требует",
			files: map[string]string{
				"0001_initial.sql":      injGrantingMigration,
				"20260914091500_go.sql": injRevokingMigration,
			},
			wantMissing: false,
			wantRevoked: 1,
		},
		{
			// ЗАКОННЫЙ БЛИЗНЕЦ: отзыва нет — ось обязана найти.
			name: "выдача не отозвана — находка остаётся",
			files: map[string]string{
				"0001_initial.sql": injGrantingMigration,
			},
			wantMissing: true,
			wantRevoked: 0,
		},
		{
			// ТОЧНОСТЬ: отозвано СОСЕДНЕЕ отношение — находка обязана остаться.
			name: "отозвано другое отношение — находка по этому остаётся",
			files: map[string]string{
				"0001_initial.sql":      injGrantingMigration,
				"20260914091500_go.sql": injRevokingOther,
			},
			wantMissing: true,
			wantRevoked: 1,
		},
		{
			// НЕТ БЛАНКЕТНОГО ОСВОБОЖДЕНИЯ: удаление выдач, не назвавшее отношения.
			name: "удаление выдач без имени отношения не освобождает никого",
			files: map[string]string{
				"0001_initial.sql":      injGrantingMigration,
				"20260914091500_go.sql": injDeletesWithoutNamingARelation,
			},
			wantMissing: true,
			wantRevoked: 0,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := mkRevokeTree(t, c.files)

			grants, read, _, err := check.GrantsFromMigrations(root)
			if err != nil {
				t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
			}
			if read == 0 || len(grants) == 0 {
				t.Fatalf("выдач не прочитано (миграций %d, пар %d) — утверждение беспредметно",
					read, len(grants))
			}

			revoked, revRead, err := check.RevokedRelationsFromMigrations(root)
			if err != nil {
				t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
			}
			if revRead == 0 {
				t.Fatal("разбор отзыва не прочитал НИ ОДНОЙ миграции — его ноль ничего не значит")
			}
			if len(revoked) != c.wantRevoked {
				t.Fatalf("отозванных отношений распознано %d, ожидалось %d (%v)",
					len(revoked), c.wantRevoked, revoked)
			}

			missing := check.MissingGrantedRelations(grants, model, revoked)
			if c.wantMissing && len(missing) == 0 {
				t.Fatal("ось смолчала там, где обязана найти: выдача есть, отзыва нет, " +
					"отношения в модели нет")
			}
			if !c.wantMissing && len(missing) != 0 {
				t.Fatalf("ось нашла там, где предмета нет: отзыв снимает выдачу. Находки: %v", missing)
			}
		})
	}
}
