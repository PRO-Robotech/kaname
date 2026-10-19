// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

// speaker_exists_integration_test.go — класс говорящего выводится только для
// СУЩЕСТВУЮЩЕЙ учётки (задача PRO-Robotech/kaname#909).
//
// Классы положены говорящему с личностью (приёмка, Р2); личность — строка
// учётки, а не вид записи (`domain.SpeakerClasses`). Учётка без строки классом
// не владеет ни на одной из трёх форм (прямой вопрос, вопрос о странице,
// перечень).
//
// Близнецы различаются РОВНО одним фактом — строкой учётки: живые человек и
// служебная учётка с той же выдачей читают, учётки без строки — нет. Контроль
// классу самому по себе — `system_class:anonymous` при выдаче анониму.

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
)

// seSeedWorld — роль чтения, объект в проекте выдачи и объект вне его; живая
// служебная учётка рядом с человеком `usr-1` из seedTenant.
func seSeedWorld(t *testing.T, ctx context.Context, tx pgx.Tx) {
	t.Helper()
	seedTenant(t, ctx, tx)
	seedRole(t, ctx, tx, "rol-sc", "vpc_network", "get", "anchor", "{}")
	exec(t, ctx, tx,
		`INSERT INTO kaname.service_accounts (id, account_id, name) VALUES ('sva-se-live', 'acc-1', 'se-live')`)
	exec(t, ctx, tx,
		`INSERT INTO kaname.resource_mirror (object_type, object_id) VALUES ($1, 'net-sc-1')`,
		catalogFormOf(t, "vpc_network"))
	exec(t, ctx, tx,
		`INSERT INTO kaname.resource_parent_edge (object_type, object_id, parent_type, parent_id, depth)
		 VALUES ('vpc_network', 'net-sc-1', 'project', 'prj-1', 1)`)
	exec(t, ctx, tx,
		`INSERT INTO kaname.projects (id, account_id, name) VALUES ('prj-sc-9', 'acc-1', 'other-sc')`)
	exec(t, ctx, tx,
		`INSERT INTO kaname.resource_mirror (object_type, object_id) VALUES ($1, 'net-sc-2')`,
		catalogFormOf(t, "vpc_network"))
	exec(t, ctx, tx,
		`INSERT INTO kaname.resource_parent_edge (object_type, object_id, parent_type, parent_id, depth)
		 VALUES ('vpc_network', 'net-sc-2', 'project', 'prj-sc-9', 1)`)
}

func TestSpeakerClass_OnlyAnExistingPrincipalHoldsIt(t *testing.T) {
	for _, class := range []string{"authenticated", "anonymous"} {
		t.Run(class, func(t *testing.T) {
			withTx(t, func(ctx context.Context, tx pgx.Tx) {
				seSeedWorld(t, ctx, tx)
				scSeedClassGrant(t, ctx, tx, "acb-se-"+class, class)
				scForms(t, ctx, tx, "v_get", []scSpeaker{
					{"user:usr-1", true},
					{"service_account:sva-se-live", true},
					{"user:usr-se-ghost", false},
					{"service_account:sva-se-ghost", false},
					// Контроль классу самому по себе: аноним читает выданное
					// анониму и не читает выданного вошедшим (SC-10).
					{"system_class:anonymous", class == "anonymous"},
				}, "выдача "+class)
			})
		})
	}
}

// TestSpeakerClass_RemovedPrincipalLosesIt — снятая учётка теряет класс тем же
// вопросом: строка учётки — единственное, что меняется между двумя замерами.
func TestSpeakerClass_RemovedPrincipalLosesIt(t *testing.T) {
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		seSeedWorld(t, ctx, tx)
		scSeedClassGrant(t, ctx, tx, "acb-se-auth", "authenticated")
		scForms(t, ctx, tx, "v_get", []scSpeaker{{"service_account:sva-se-live", true}}, "до снятия")
		exec(t, ctx, tx, `DELETE FROM kaname.service_accounts WHERE id = 'sva-se-live'`)
		scForms(t, ctx, tx, "v_get", []scSpeaker{{"service_account:sva-se-live", false}}, "после снятия")
	})
}
