// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// role_withdrawal_mark_integration_test.go — ФОРМА пометки снятия у
// `kacho_iam.roles` и КЛЮЧИ, которые держат порядок её постановки.
//
// Приёмка `services/iam/docs/engineering/acceptance/role-withdrawal-has-a-producer.md`
// (APPROVED круга 4), §2.1 и §2.3; сценарии IAM-RW-1-02, IAM-RW-1-03,
// IAM-RW-1-12, IAM-RW-1-13. Задача продукта #1913.
//
// # Почему проба по ЖИВОЙ схеме, а не по тексту миграции
//
// Утверждается ИСХОД накатанной цепи, а не намерение одного файла: колонку,
// ограничение и ключ переопределяет любая поздняя миграция, и текст файла об
// этом не знает. Каталог живой базы говорит о том, что примут и что отвергнут.
//
// # Что здесь ДОКАЗЫВАЕТСЯ парой, а не одним утверждением
//
// «Порядок держит ключ» неотличимо от «роль снять нельзя никогда», если
// утверждать только отказ. Поэтому у каждого отрицания рядом стоит его
// положительный близнец: снять проекции — и та же пометка ПРОХОДИТ.
package migrations_test

import (
	"database/sql"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/stretchr/testify/require"
)

// roleWithdrawalProjections — проекции роли, чья живость обязана запирать
// пометку. Перечень взят у §2.3 приёмки дословно и назван здесь одним местом:
// две из четырёх колонку живости уже несут, две получают её этой работой.
var roleWithdrawalProjections = []struct {
	table string
	key   string
}{
	{"role_verb", "role_verb_role_live_fk"},
	{"role_rule_ref", "role_rule_ref_role_live_fk"},
	{"role_rule_selectors", "role_rule_selectors_role_live_fk"},
	{"access_binding_target_members", "access_binding_target_members_role_live_fk"},
}

// TestIntegration_RoleWithdrawalMarkHasItsForm — IAM-RW-1-02 и IAM-RW-1-03.
//
// Пометка объявлена четырьмя элементами, и каждый проверяется своим вопросом к
// каталогу: колонки существуют · состояние «снята и жива» неконструируемо ·
// референт живости объявлен · на него ссылается хотя бы один ключ проекции.
//
// Последнее — положительный контроль формы: уникальность, на которую не
// ссылается никто, заведена «на будущее» и не проверяет ничего.
func TestIntegration_RoleWithdrawalMarkHasItsForm(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}
	db := freshIamSchema(t)

	// ── колонки ──────────────────────────────────────────────────────────────
	wantCols := map[string]string{
		"retired_at":     "timestamp with time zone",
		"retired_reason": "text",
		"retired_by":     "text",
		"live":           "boolean",
	}
	seen := 0
	for col, typ := range wantCols {
		var got, nullable string
		err := db.QueryRow(`
			SELECT data_type, is_nullable
			  FROM information_schema.columns
			 WHERE table_schema = 'kacho_iam' AND table_name = 'roles' AND column_name = $1`,
			col).Scan(&got, &nullable)
		require.NoErrorf(t, err, "колонки kacho_iam.roles.%s нет: пометка снятия не объявлена", col)
		require.Equalf(t, typ, got, "колонка %s объявлена не тем типом", col)
		seen++
	}
	t.Logf("перепись: колонок пометки осмотрено %d из %d", seen, len(wantCols))
	require.Equal(t, len(wantCols), seen, "перепись пуста — вердикт беспредметен")

	// `live` обязана быть NOT NULL с умолчанием: обратного заполнения у этой
	// работы нет ни одной строкой, и держится это умолчанием, а не удачей.
	var isNullable, colDefault sql.NullString
	require.NoError(t, db.QueryRow(`
		SELECT is_nullable, column_default
		  FROM information_schema.columns
		 WHERE table_schema = 'kacho_iam' AND table_name = 'roles' AND column_name = 'live'`).
		Scan(&isNullable, &colDefault))
	require.Equal(t, "NO", isNullable.String, "roles.live обязана быть NOT NULL")
	require.Contains(t, colDefault.String, "true",
		"умолчание roles.live обязано делать существующие строки живыми БЕЗ обратного заполнения")

	// ── согласие пометки: «снята и жива» НЕКОНСТРУИРУЕМО ─────────────────────
	var checkDef string
	require.NoError(t, db.QueryRow(`
		SELECT pg_get_constraintdef(oid)
		  FROM pg_constraint
		 WHERE conrelid = 'kacho_iam.roles'::regclass
		   AND conname  = 'roles_live_matches_retired'`).Scan(&checkDef),
		"проверки roles_live_matches_retired нет: состояние «снята и жива» остаётся представимым")
	t.Logf("согласие пометки: %s", checkDef)

	// ── референт живости ─────────────────────────────────────────────────────
	var uniqDef string
	require.NoError(t, db.QueryRow(`
		SELECT pg_get_constraintdef(oid)
		  FROM pg_constraint
		 WHERE conrelid = 'kacho_iam.roles'::regclass
		   AND contype  = 'u'
		   AND pg_get_constraintdef(oid) LIKE 'UNIQUE (id, live)%'`).Scan(&uniqDef),
		"уникальности (id, live) нет: ключам живости проекций не на что сослаться")
	t.Logf("референт живости: %s", uniqDef)

	// Положительный контроль: на референт кто-то ССЫЛАЕТСЯ.
	// Признак — СОСТАВ referenced-колонок ключа, а не подстрока его текста:
	// `pg_get_constraintdef` печатает имя таблицы с учётом `search_path`, и
	// сверка по строке молчала бы на верном ключе ровно тогда, когда путь поиска
	// иной. Здесь спрашивается каталог: ключ ведёт на `roles` И среди его
	// referenced-колонок есть `live`.
	var referrers int
	require.NoError(t, db.QueryRow(`
		SELECT count(*)
		  FROM pg_constraint c
		 WHERE c.contype = 'f'
		   AND c.confrelid = 'kacho_iam.roles'::regclass
		   AND EXISTS (
		         SELECT 1
		           FROM unnest(c.confkey) AS k(attnum)
		           JOIN pg_attribute a
		             ON a.attrelid = c.confrelid AND a.attnum = k.attnum
		          WHERE a.attname = 'live')`).Scan(&referrers))
	t.Logf("перепись: ключей живости, ссылающихся на roles(id, live) — %d", referrers)
	require.GreaterOrEqual(t, referrers, len(roleWithdrawalProjections),
		"референт живости объявлен, а ссылается на него меньше ключей, чем проекций: "+
			"уникальность, на которую никто не ссылается, не проверяет ничего")
}

// TestIntegration_RoleWithdrawalOrderIsHeldByTheKey — IAM-RW-1-12 и IAM-RW-1-13.
//
// Обе половины обязательны: пометка при живой проекции ОТВЕРГАЕТСЯ `23503`, и
// та же пометка ПОСЛЕ снятия проекций ПРОХОДИТ. Без второй половины «ключ держит
// порядок» неотличимо от «роль снять нельзя никогда».
func TestIntegration_RoleWithdrawalOrderIsHeldByTheKey(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}
	db := freshIamSchema(t)
	seedWithdrawalFixture(t, db)

	// ── отрицание: пометка при ЖИВОЙ проекции отвергается ────────────────────
	_, err := db.Exec(`
		UPDATE kacho_iam.roles
		   SET live = false, retired_at = now(), retired_reason = 'проба', retired_by = 'проба'
		 WHERE id = 'rol_rw_probe'`)
	require.Error(t, err, "пометка прошла при живой проекции — порядок ключом не держится")
	require.Contains(t, err.Error(), "23503",
		"отказ обязан прийти нарушением ссылочной целостности, а не иным классом: %v", err)

	// ── положительный близнец: сняли проекции — та же пометка ПРОХОДИТ ───────
	for _, p := range roleWithdrawalProjections {
		_, derr := db.Exec(`DELETE FROM kacho_iam.` + p.table + ` WHERE role_id = 'rol_rw_probe'`)
		require.NoErrorf(t, derr, "снятие проекции %s отказало", p.table)
	}
	_, err = db.Exec(`
		UPDATE kacho_iam.roles
		   SET live = false, retired_at = now(), retired_reason = 'проба', retired_by = 'проба'
		 WHERE id = 'rol_rw_probe'`)
	require.NoError(t, err,
		"пометка отвергнута и после снятия проекций: ключ запер роль навсегда")

	// ── IAM-RW-1-13: ведомости ПЕРЕЖИВАЮТ снятие ─────────────────────────────
	var orphans int
	require.NoError(t, db.QueryRow(
		`SELECT count(*) FROM kacho_iam.role_grant_orphan WHERE role_id = 'rol_rw_probe'`).Scan(&orphans))
	require.Positive(t, orphans,
		"ведомость сирот пуста после снятия: объяснение отобранного не пережило пометку")
	t.Logf("перепись: строк ведомости сирот у снятой роли — %d", orphans)

	// ── согласие: «жива при непустом моменте снятия» отвергается ─────────────
	_, err = db.Exec(`UPDATE kacho_iam.roles SET live = true WHERE id = 'rol_rw_probe'`)
	require.Error(t, err, "состояние «жива при непустом retired_at» оказалось конструируемым")
	require.Contains(t, err.Error(), "23514", "отказ обязан прийти нарушением CHECK: %v", err)
	require.Contains(t, err.Error(), "roles_live_matches_retired",
		"отказ обязан называть нарушенное ограничение: %v", err)
}

// seedWithdrawalFixture кладёт роль модуля со ВСЕМИ четырьмя проекциями и одной
// строкой ведомости.
//
// Фикстура нарочно полная: проба порядка, поставленная на роль без проекций,
// зеленела бы на любом ключе — отвергать было бы нечему.
func seedWithdrawalFixture(t *testing.T, db *sql.DB) {
	t.Helper()

	// Каталожные строки, на которые ссылаются проекции. Модуль и ресурс берутся
	// живыми: снятый референт отверг бы вставку раньше, чем проба дойдёт до
	// своего предмета, и красное пришло бы от соседа.
	var module, dotted string
	require.NoError(t, db.QueryRow(`
		SELECT cm.module, cr.dotted
		  FROM kacho_iam.catalog_resource cr
		  JOIN kacho_iam.catalog_module cm ON cm.module = cr.module
		 WHERE cr.live AND cm.live
		 ORDER BY cr.dotted
		 LIMIT 1`).Scan(&module, &dotted),
		"живого каталожного ресурса нет: фикстуре не на что сослаться")

	var resource, verb string
	require.NoError(t, db.QueryRow(`
		SELECT cv.resource, cv.verb
		  FROM kacho_iam.catalog_verb cv
		 WHERE cv.live AND cv.module = $1 AND cv.module || '.' || cv.resource = $2
		 ORDER BY cv.verb
		 LIMIT 1`, module, dotted).Scan(&resource, &verb),
		"живого каталожного глагола нет: фикстуре не на что сослаться")

	// Разрешение собирается из ЖИВОГО каталога, а не выписывается: форма
	// четырёхсегментная (`iam_permissions_valid`, 0005), и выписанный литерал
	// разошёлся бы с ней молча — проба покраснела бы на своей же фикстуре.
	perms := `["` + module + `.` + resource + `.*.` + verb + `"]`
	_, err := db.Exec(`
		INSERT INTO kacho_iam.roles (id, cluster_id, name, description, permissions, rules, owner_module)
		VALUES ('rol_rw_probe', 'cluster_kacho_root', $1, '', $3::jsonb, '[]'::jsonb, $2)`,
		module+".rwprobe", module, perms)
	require.NoError(t, err, "фикстура роли не легла")

	_, err = db.Exec(`
		INSERT INTO kacho_iam.role_verb (role_id, object_type, verb)
		VALUES ('rol_rw_probe', $1, $2)`, dotted, verb)
	require.NoError(t, err, "фикстура проекции глаголов не легла")

	_, err = db.Exec(`
		INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb)
		VALUES ('rol_rw_probe', $1, $2, $3)`, module, resource, verb)
	require.NoError(t, err, "фикстура проекции сегментов не легла")

	_, err = db.Exec(`
		INSERT INTO kacho_iam.role_rule_selectors
		       (role_id, rule_fp, arm, object_types, resource_names, match_labels)
		VALUES ('rol_rw_probe', 'fp-rw-probe', 'labels', ARRAY[$1], '{}', '{"k":"v"}'::jsonb)`,
		dotted)
	require.NoError(t, err, "фикстура проекции селекторов не легла")

	require.NoError(t, seedTargetMemberFixture(db), "фикстура состава цели не легла")

	_, err = db.Exec(`
		INSERT INTO kacho_iam.role_grant_orphan (role_id, object_type, verb, source, reason)
		VALUES ('rol_rw_probe', $1, $2, 'role_verb', 'проба')`, dotted, verb)
	require.NoError(t, err, "фикстура ведомости сирот не легла")
}

// seedTargetMemberFixture кладёт строку состава цели. Ей нужна выдача, а выдаче
// — субъект и якорь, поэтому она собирается отдельной функцией: перечень чужих
// предусловий не должен теряться среди предмета пробы.
func seedTargetMemberFixture(db *sql.DB) error {
	// Аккаунт и человек — чужие предусловия выдачи, а не предмет пробы. Кладутся
	// здесь, потому что без них отказ придёт от ключа субъекта и назовёт
	// невиновного.
	// Ключи между ними ВЗАИМНЫЕ и отложенные (`accounts_owner_fk`,
	// `users_account_fk`), поэтому обе строки ложатся ОДНОЙ транзакцией: по
	// одной их не вставить ни в каком порядке.
	if _, err := db.Exec(`
		BEGIN;
		INSERT INTO kacho_iam.accounts (id, name, owner_user_id)
		VALUES ('acc_rw_probe', 'rw-probe', 'usr_rw_probe');
		INSERT INTO kacho_iam.users (id, external_id, email, account_id)
		VALUES ('usr_rw_probe', 'ext-rw-probe', 'rw-probe@example.test', 'acc_rw_probe');
		COMMIT;`); err != nil {
		return err
	}
	if _, err := db.Exec(`
		INSERT INTO kacho_iam.access_bindings
		       (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
		VALUES ('acb_rw_probe', 'user', 'usr_rw_probe', 'rol_rw_probe', 'cluster',
		        'cluster_kacho_root', 'ACTIVE')`,
	); err != nil {
		return err
	}
	if _, err := db.Exec(`
		INSERT INTO kacho_iam.access_binding_subjects (binding_id, subject_type, subject_id)
		VALUES ('acb_rw_probe', 'user', 'usr_rw_probe')`,
	); err != nil {
		return err
	}
	_, err := db.Exec(`
		INSERT INTO kacho_iam.access_binding_target_members
		       (binding_id, role_id, rule_fp, object_type, object_id)
		VALUES ('acb_rw_probe', 'rol_rw_probe', 'fp-rw-probe', 'iam_role', 'rol_rw_probe')`)
	return err
}

// TestIntegration_NewGrantOnARetiredRoleIsRefused — IAM-RW-1-16 и IAM-RW-1-31.
//
// Три утверждения, и ни одно не выводимо из двух других:
//
//	новая выдача на СНЯТУЮ роль    отвергается 23000 с именем связи;
//	новая выдача на ЖИВУЮ роль     проходит — положительный контроль, без
//	                               которого отрицание зеленело бы на страже,
//	                               отвергающем всё;
//	пережившая выдача              остаётся ПРАВИМОЙ: правка, не меняющая
//	                               role_id, проходит, а перевод НА снятую роль
//	                               отвергается — это новая ссылка.
func TestIntegration_NewGrantOnARetiredRoleIsRefused(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}
	db := freshIamSchema(t)
	seedWithdrawalFixture(t, db)

	// Роль снимается: сперва проекции, потом пометка — порядок держит ключ.
	for _, p := range roleWithdrawalProjections {
		_, err := db.Exec(`DELETE FROM kacho_iam.` + p.table + ` WHERE role_id = 'rol_rw_probe'`)
		require.NoErrorf(t, err, "снятие проекции %s отказало", p.table)
	}
	_, err := db.Exec(`
		UPDATE kacho_iam.roles
		   SET live = false, retired_at = now(), retired_reason = 'проба', retired_by = 'проба'
		 WHERE id = 'rol_rw_probe'`)
	require.NoError(t, err, "пометка отказала — предмета для стража не создано")

	// ── отрицание: НОВАЯ выдача на снятую роль отвергается ───────────────────
	_, err = db.Exec(`
		INSERT INTO kacho_iam.access_bindings
		       (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
		VALUES ('acb_rw_new', 'user', 'usr_rw_probe', 'rol_rw_probe', 'cluster',
		        'cluster_kacho_root', 'ACTIVE')`)
	require.Error(t, err, "новая выдача на снятую роль прошла: продукт обещает право, "+
		"которого не даёт")
	require.Contains(t, err.Error(), "23000",
		"отказ обязан прийти классом integrity_constraint_violation, а не иным: "+
			"23514 отображается в INVALID_ARGUMENT и сказал бы «негоден ввод» там, где "+
			"негодно СОСТОЯНИЕ платформы: %v", err)
	require.Equal(t, "access_bindings_role_is_live", constraintNameOf(t, err),
		"отказ обязан называть связь ПОЛЕМ, а не текстом: по нему маппер выбирает "+
			"текст, называющий роль, и сообщение сервера наружу не эхается: %v", err)

	// ── положительный контроль: та же операция на ЖИВОЙ роли проходит ────────
	var liveRole string
	require.NoError(t, db.QueryRow(
		`SELECT id FROM kacho_iam.roles WHERE live AND is_system ORDER BY id LIMIT 1`).
		Scan(&liveRole), "живой системной роли нет — контроль беспредметен")
	_, err = db.Exec(`
		INSERT INTO kacho_iam.access_bindings
		       (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
		VALUES ('acb_rw_live', 'user', 'usr_rw_probe', $1, 'cluster',
		        'cluster_kacho_root', 'ACTIVE')`, liveRole)
	require.NoError(t, err,
		"выдача на ЖИВУЮ роль отвергнута: страж отвергает всё, и отрицание выше "+
			"зеленело бы на сломанном")

	// ── IAM-RW-1-31: пережившая выдача остаётся ПРАВИМОЙ ─────────────────────
	_, err = db.Exec(
		`UPDATE kacho_iam.access_bindings SET status = 'REVOKED', revoked_at = now()
		  WHERE id = 'acb_rw_probe'`)
	require.NoError(t, err,
		"пережившую выдачу нельзя отозвать: без раннего выхода стража она замерзает, "+
			"и §2.4 противоречит собственной следующей строке")

	// ── перевод ЖИВОЙ выдачи НА снятую роль — это НОВАЯ ссылка ───────────────
	_, err = db.Exec(
		`UPDATE kacho_iam.access_bindings SET role_id = 'rol_rw_probe' WHERE id = 'acb_rw_live'`)
	require.Error(t, err, "перевод выдачи на снятую роль прошёл: это новая ссылка")
	require.Equal(t, "access_bindings_role_is_live", constraintNameOf(t, err),
		"отказ перевода обязан прийти от стража и назвать связь: %v", err)
}

// constraintNameOf — имя нарушенной связи из ПОЛЯ отказа, а не из его текста.
//
// Различие несущее: текст сервера наружу не эхается (в нём значения и имя
// ограничения — разведка схемы), поэтому маппер выбирает полосу по ПОЛЮ. Проба,
// читающая текст, утверждала бы о том, чем продукт не пользуется, и молчала бы
// в день, когда сервер перестанет печатать имя в сообщении.
func constraintNameOf(t *testing.T, err error) string {
	t.Helper()
	var pgErr *pgconn.PgError
	require.ErrorAs(t, err, &pgErr, "отказ пришёл не от сервера: %v", err)
	return pgErr.ConstraintName
}
