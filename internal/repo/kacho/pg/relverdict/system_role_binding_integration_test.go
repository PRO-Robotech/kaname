// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package relverdict_test

// system_role_binding_integration_test.go — выдача СИСТЕМНОЙ роли доходит до
// вердикта формы E.
//
// # Почему проба именно на системной роли, а не на любой
//
// Роль пользовательская и роль системная различаются НЕ содержанием, а тем,
// каким путём заведены: первая проходит через use-case, который пишет обе
// стороны правила (селекторы и проекцию глаголов), вторая заводится сырым SQL
// миграции и этим путём не проходит никогда. Проба, сеющая проекцию руками,
// доказывает работу запроса на данных, которых в проде не бывает, — и молчит
// ровно о том разрыве, ради которого написана.
//
// Здесь обе стороны кладёт ПРОДУКТ: досев старта (`seed.SyncAllSystemRoleSelectors`)
// над ролями, посеянными миграциями. Утверждается вердикт, а не строка таблицы.
//
// # Что это воспроизводит
//
// Самый крупный «глагольный» класс расхождения теневой формы с движком: арендатор
// с выдачей роли-редактора на проект получал от движка «да» на удаление своего
// ресурса и от формы E «нет» — потому что проекция глаголов у системной роли была
// пуста, а у роли с подстановкой пуста вдвойне.

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho/internal/pgtest"
	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/seed"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg/relverdict"
	"github.com/PRO-Robotech/kacho/services/iam/internal/testsupport/catalogfixture"
)

// systemRoleEdit / systemRoleAdmin — идентификаторы посеянных миграцией ролей.
// Выражение то же, каким их сеет миграция; воспроизводить его здесь приходится
// потому, что имя роли — не идентификатор, а вопрос задаётся по нему.
const (
	systemRoleEdit  = "rolde95b43bceeb4b998" // 'rol' || substr(md5('edit'), 1, 17)
	systemRoleAdmin = "rol21232f297a57a5a74" // 'rol' || substr(md5('admin'), 1, 17)
)

func withSeededPool(t *testing.T, fn func(ctx context.Context, tx pgx.Tx)) {
	t.Helper()
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, pgtest.NewDB(t))
	if err != nil {
		t.Fatalf("пул: %v", err)
	}
	pgtest.ClosePoolAtEnd(t, pool)
	// Обе стороны правила системной роли кладёт продукт, а не фикстура. Полос
	// ДВЕ, и зовутся они порознь: у пересчёта проекции глаголов свой вход (порт
	// записи), своя зернистость и своя полоса отказа, поэтому досев селекторов
	// его не зовёт. Позвать одну и утверждать о вердикте значило бы спрашивать
	// про строки, которых нет: роль с одними селекторами адресует объект и не
	// разрешает на нём ничего.
	if err := seed.SyncAllSystemRoleSelectors(ctx, pool); err != nil {
		t.Fatalf("досев селекторов системных ролей: %v", err)
	}
	if _, err := seed.ReseedSystemRoleVerbs(ctx, kachopg.New(pool, nil), pool, catalogfixture.Facts(), nil); err != nil {
		t.Fatalf("досев проекции глаголов системных ролей: %v", err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("транзакция: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	fn(ctx, tx)
}

// seedBindingOnProject кладёт арендную обвязку, ресурс под проектом и выдачу
// роли на проект — ровно ту форму, какую производит выдача прав арендатору.
func seedBindingOnProject(t *testing.T, ctx context.Context, tx pgx.Tx, roleID, objType, objID string) {
	t.Helper()
	seedTenant(t, ctx, tx)
	// Служебная учётка — НАСТОЯЩЕЙ строкой: выдача ссылается на неё внешним
	// ключом, и фикстура, обходящая его, доказывала бы работу запроса на данных,
	// которых в проде не бывает.
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.service_accounts (id, account_id, name)
		 VALUES ('sva-1', 'acc-1', 'sva-one') ON CONFLICT DO NOTHING`)
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.resource_parent_edge (object_type, object_id, parent_type, parent_id, depth)
		 VALUES ($1, $2, 'project', 'prj-1', 1)`, objType, objID)
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.access_bindings
		   (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
		 VALUES ('acb-sys', 'service_account', 'sva-1', $1, 'project', 'prj-1', 'ACTIVE')`, roleID)
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.access_binding_subjects (binding_id, subject_type, subject_id)
		 VALUES ('acb-sys', 'service_account', 'sva-1')`)
}

// Роль-редактор: правка влечёт удаление на листе — движок это материализует, и
// форма E обязана отвечать так же.
func TestAsk_SystemEditorRoleGrantsWhatTheEngineMaterialises(t *testing.T) {
	withSeededPool(t, func(ctx context.Context, tx pgx.Tx) {
		seedBindingOnProject(t, ctx, tx, systemRoleEdit, "nlb_network_load_balancer", "nlb-1")

		for _, relation := range []string{"v_update", "v_delete"} {
			got, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
				Subject: "service_account:sva-1", ObjectType: "nlb_network_load_balancer",
				ObjectID: "nlb-1", Relation: relation,
			})
			if err != nil {
				t.Fatalf("запрос %s: %v", relation, err)
			}
			if got != relverdict.Allow {
				t.Errorf("роль-редактор не дала %s: %v — движок на этом же вопросе отвечает "+
					"«да», и расхождение читается как дефект прав", relation, got)
			}
		}

		// Отрицание рядом: чужая учётка права не получает — иначе «да» выше
		// зеленело бы и на проекции, разрешающей всем.
		other, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
			Subject: "service_account:sva-2", ObjectType: "nlb_network_load_balancer",
			ObjectID: "nlb-1", Relation: "v_delete",
		})
		if err != nil {
			t.Fatalf("запрос: %v", err)
		}
		if other != relverdict.Deny {
			t.Errorf("чужая учётка получила право: %v", other)
		}
	})
}

// Роль-администратор объявлена ПОДСТАНОВКОЙ (`verbs: ["*"]`). Именно на ней
// проекция была пуста целиком: подстановка отбрасывалась, а набор типа знает
// каталог, а не домен.
func TestAsk_SystemAdminRoleWildcardVerbsReachTheVerdict(t *testing.T) {
	withSeededPool(t, func(ctx context.Context, tx pgx.Tx) {
		seedBindingOnProject(t, ctx, tx, systemRoleAdmin, "vpc_network", "net-1")

		for _, relation := range []string{"v_get", "v_delete"} {
			got, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
				Subject: "service_account:sva-1", ObjectType: "vpc_network",
				ObjectID: "net-1", Relation: relation,
			})
			if err != nil {
				t.Fatalf("запрос %s: %v", relation, err)
			}
			if got != relverdict.Allow {
				t.Errorf("роль с подстановкой не дала %s: %v", relation, got)
			}
		}
	})
}

// ЗАКОННЫЙ БЛИЗНЕЦ: роль-наблюдатель удаления НЕ даёт.
//
// Без него две пробы выше зеленели бы на досеве, раздающем все глаголы всем
// ролям, — то есть на расширении доступа, а не на его восстановлении.
func TestAsk_SystemViewerRoleDoesNotGrantDelete(t *testing.T) {
	withSeededPool(t, func(ctx context.Context, tx pgx.Tx) {
		const systemRoleView = "rol1bda80f2be4d3658e" // 'rol' || substr(md5('view'), 1, 17)
		seedBindingOnProject(t, ctx, tx, systemRoleView, "vpc_network", "net-1")

		read, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
			Subject: "service_account:sva-1", ObjectType: "vpc_network",
			ObjectID: "net-1", Relation: "v_get",
		})
		if err != nil {
			t.Fatalf("запрос: %v", err)
		}
		// Положительный контроль: роль вообще действует.
		if read != relverdict.Allow {
			t.Fatalf("роль-наблюдатель не дала чтения: %v — отрицание ниже было бы вакуумным", read)
		}

		del, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
			Subject: "service_account:sva-1", ObjectType: "vpc_network",
			ObjectID: "net-1", Relation: "v_delete",
		})
		if err != nil {
			t.Fatalf("запрос: %v", err)
		}
		if del != relverdict.Deny {
			t.Errorf("роль-наблюдатель дала удаление: %v", del)
		}
	})
}
