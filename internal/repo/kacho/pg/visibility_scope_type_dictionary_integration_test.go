// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// visibility_scope_type_dictionary_integration_test.go — КЛЮЧ `GrantedObjects`
// ПРОИЗВОДИТСЯ ПЕРЕВОДОМ У ВЛАДЕЛЬЦА СЛОВАРЯ, А НЕ РАЗБОРОМ СТРОКИ
// (задача продукта kacho#2003, линия release:modules).
//
// # Предмет
//
// `ScopeOf` складывает кандидатов из ДВУХ словарей имени типа сразу, и это
// свойство запроса, а не случайность — оно закреплено схемой:
//
//	access_bindings.resource_type            — словарь МОДЕЛИ. Точки в нём нет
//	                                           by construction: CHECK
//	                                           `access_bindings_resource_ck`
//	                                           допускает `^[a-z][a-z0-9_]*$`;
//	access_binding_target_members.object_type — словарь КАТАЛОГА, точечный.
//	                                           Так объявляет миграция 0020
//	                                           («authzmap.ObjectType key») и так
//	                                           же — производитель
//	                                           (`reconcile.DesiredMember`:
//	                                           «ObjectType is the dotted
//	                                           closed-table key»).
//
// Свести их в один ключ ОБЯЗАНО переводом. Прежде здесь стояло ОТРЕЗАНИЕ
// последнего сегмента после точки, и оно не перевод: правило «отрезать» не
// следует ни из чего, а совпадает с переводом лишь там, где имя типа модели
// случайно равно имени ресурса.
//
// # Почему проба перечисляет ВСЕ СЕМЬ типов, а не один
//
// Отрезание сходилось с переводом ровно у `iam.account` и `iam.project` — и
// это ровно те два типа, которыми проверяют «работает ли вообще». Проба на
// одном из них зеленела бы на снятом дефекте, поэтому оба стоят здесь
// ПОЛОЖИТЕЛЬНЫМ КОНТРОЛЕМ рядом с пятью, на которых отрезание промахивалось:
//
//	точечный ключ        отрезание даёт      перевод даёт (= чего просит вызывающий)
//	iam.account          account             account                 ← совпадало
//	iam.project          project             project                 ← совпадало
//	iam.group            group               iam_group
//	iam.user             user                iam_user
//	iam.role             role                iam_role
//	iam.serviceAccount   serviceAccount      iam_service_account
//	iam.accessBinding    accessBinding       iam_access_binding
//
// Правая колонка — не выдумка пробы: это дословные значения констант
// `fgaAccountType` / `fgaProjectType` / `fgaGroupType` / `fgaUserType` /
// `fgaRoleObjectType` / `fgaServiceAccountType` / `fgaBindingObjectType`,
// которыми семь списочных путей сервиса зовут `Scope.Candidates(...)`. Их
// написание и есть контракт, объявленный портом: «GrantedObjects — objects
// named by a grant BY NAME, keyed by the model's spelling of the object type
// ("project", "iam_group", …)».
//
// # Что видел арендатор
//
// Субъект, чей единственный путь к группе / пользователю / роли / служебной
// учётке / выдаче — выдача, материализованная в `access_binding_target_members`
// (то есть выдача по меткам), кандидатом её НЕ получал: сложено под `group`,
// спрошено под `iam_group`. Право при этом не расширялось — промах сужает, а не
// открывает, — но выданное не работало, и снаружи это неотличимо от «прав не
// выдали».
//
// # Способность упасть
//
// Доказана инъекцией: перевод возвращён к отрезанию — проба краснеет и
// НАЗЫВАЕТ промахнувшийся тип вместе с обоими написаниями; возвращён перевод —
// молчит. Односторонним утверждением тут не обойтись, поэтому рядом стоят:
//
//   - положительный контроль на `iam.account`/`iam.project` — иначе утверждение
//     зеленело бы на прежнем совпадении;
//   - ОТРИЦАНИЕ по отрезанным написаниям (`group`, `user`, …): ключа, которого
//     не просит ни один вызывающий, в памятке быть не должно вовсе, иначе
//     «перевод добавили, отрезание оставили» прошло бы незамеченным;
//   - перепись осмотренного — строк каталога и членов выдачи. Оба утверждения
//     ниже истинны тождественно на пустых таблицах.

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// dictionaryCase — один тип каталога и то, ЧЕМ его спрашивает вызывающий.
type dictionaryCase struct {
	dotted    string // как пишет производитель (access_binding_target_members.object_type)
	modelName string // как просит вызывающий: константа fga*Type списочного пути
	truncated string // что давало снятое отрезание — стережётся отрицанием
	objectID  string
	konstanta string // имя константы, чтобы отказ называл координату, а не только строку
}

func TestIntegration_Issue2003_ScopeKeysComeFromTranslationNotTruncation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx, pool := kac127Setup(t)

	subject, subjectAccount := kac127SeedUserAndAccount(t, ctx, pool, "d2003")

	// Роль нужна двум внешним ключам сразу: у выдачи (`access_bindings.role_id`)
	// и у члена (`access_binding_target_members.role_id`).
	roleID := padOrTrim20("rol_d2003role")
	_, err := pool.Exec(ctx, `
		INSERT INTO kacho_iam.clusters (id, name) VALUES ('cluster_kacho_root', 'kacho')
		ON CONFLICT DO NOTHING`)
	require.NoError(t, err, "seed cluster")
	// `is_system` НЕ задаётся: с миграции 0056 это ПОРОЖДЁННАЯ колонка
	// (`cluster_id IS NOT NULL`), и явное значение отвергается 428C9. Имя
	// подчиняется формату системной роли (`roles_system_name_check`) —
	// подчёркивания в нём быть не может, поэтому оно не производится от `roleID`.
	_, err = pool.Exec(ctx, `
		INSERT INTO kacho_iam.roles (id, name, permissions, rules, cluster_id)
		VALUES ($1, $2, '[]'::jsonb,
		        jsonb_build_array(jsonb_build_object(
		            'module',    'test',
		            'resources', jsonb_build_array('*'),
		            'verbs',     jsonb_build_array('get'))),
		        'cluster_kacho_root')`,
		roleID, "kacho.d2003.viewer")
	require.NoError(t, err, "seed role")

	// Выдача, чьим субъектом назван наш человек. Её СОБСТВЕННАЯ область названа
	// словарём МОДЕЛИ (иначе CHECK не пропустит) и намеренно указывает на другой
	// аккаунт: так вклад самой выдачи отличим от вклада её членов.
	bindingID := padOrTrim20("abn_d2003bind")
	_, err = pool.Exec(ctx, `
		INSERT INTO kacho_iam.access_bindings
		  (id, subject_type, subject_id, role_id, resource_type, resource_id,
		   status, granted_by_user_id)
		VALUES ($1, 'user', $2, $3, 'account', $4, 'ACTIVE', $2)`,
		bindingID, subject, roleID, subjectAccount)
	require.NoError(t, err, "seed binding")

	_, err = pool.Exec(ctx, `
		INSERT INTO kacho_iam.access_binding_subjects (binding_id, subject_type, subject_id)
		VALUES ($1, 'user', $2)`,
		bindingID, subject)
	require.NoError(t, err, "seed binding subject")

	// Семь членов — по одному на каждый точечный тип iam. object_id — непрозрачная
	// мягкая ссылка без внешнего ключа (миграция 0020), поэтому значения выбраны
	// РАЗНЫМИ: одинаковые не позволили бы отличить «нашёлся свой» от «нашёлся чужой».
	cases := []dictionaryCase{
		{"iam.account", "account", "account", padOrTrim20("acc_d2003tgt"), "fgaAccountType"},
		{"iam.project", "project", "project", padOrTrim20("prj_d2003tgt"), "fgaProjectType"},
		{"iam.group", "iam_group", "group", padOrTrim20("grp_d2003tgt"), "fgaGroupType"},
		{"iam.user", "iam_user", "user", padOrTrim20("usr_d2003tgt"), "fgaUserType"},
		{"iam.role", "iam_role", "role", padOrTrim20("rol_d2003tgt"), "fgaRoleObjectType"},
		{"iam.serviceAccount", "iam_service_account", "serviceAccount", padOrTrim20("sa_d2003tgt"), "fgaServiceAccountType"},
		{"iam.accessBinding", "iam_access_binding", "accessBinding", padOrTrim20("abn_d2003tgt"), "fgaBindingObjectType"},
	}

	for i, c := range cases {
		_, err = pool.Exec(ctx, `
			INSERT INTO kacho_iam.access_binding_target_members
			  (binding_id, role_id, rule_fp, object_type, object_id,
			   verification_status, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, 'ACTIVE', $6, $6)`,
			bindingID, roleID, fmt.Sprintf("rulefp_d2003_%d", i),
			c.dotted, c.objectID, time.Now())
		require.NoError(t, err, "seed target member %s", c.dotted)
	}

	// ── Перепись осмотренного. Оба утверждения ниже истинны тождественно на
	// пустой таблице, поэтому объём назван ЧИСЛОМ, а не подразумевается.
	var membersSeen int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.access_binding_target_members WHERE binding_id = $1`,
		bindingID).Scan(&membersSeen))
	require.Equal(t, len(cases), membersSeen,
		"перепись: членов выдачи должно быть %d — иначе проба сравнивает две пустоты "+
			"(осмотрено членов: %d)", len(cases), membersSeen)

	// Перевод обязан приезжать ЖИВОЙ строкой каталога. Если каталог не посеян,
	// перевод не сможет состояться ни при какой реализации, и красное означало бы
	// «условие не создано», а не дефект — поэтому предпосылка утверждается ОТДЕЛЬНО.
	for _, c := range cases {
		var objectType string
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT object_type FROM kacho_iam.catalog_resource WHERE dotted = $1`,
			c.dotted).Scan(&objectType),
			"предпосылка пробы: строка каталога для %q обязана существовать — "+
				"без неё перевод невыполним, и красное означало бы несозданное условие", c.dotted)
		require.Equal(t, c.modelName, objectType,
			"предпосылка пробы: каталог обязан переводить %q в %q — именно этим "+
				"написанием списочный путь зовёт Candidates (константа %s)",
			c.dotted, c.modelName, c.konstanta)
	}

	// ── Утверждение #2003: каждый из семи кандидатов найден ПО СВОЕМУ имени модели.
	scope := scopeOfUser(t, ctx, pool, subject)

	for _, c := range cases {
		if c.modelName == "account" {
			// `account` — не ключ памятки: аккаунт есть ОБЛАСТЬ, и запрос кладёт
			// его в ScopedAccounts. Положительный контроль остаётся тем же: тип,
			// на котором отрезание совпадало, обязан доезжать и после перевода.
			require.Contains(t, scope.ScopedAccounts, c.objectID,
				"тип %q обязан доехать до ScopedAccounts как %q: на нём отрезание "+
					"СОВПАДАЛО с переводом, и он стоит здесь положительным контролем — "+
					"без него утверждение зеленело бы на прежнем совпадении",
				c.dotted, c.modelName)
			continue
		}

		candidates := scope.Candidates(c.modelName)
		require.NotNil(t, candidates,
			"сужение по %q не должно быть пустым указателем: nil означает "+
				"«не сужаем», то есть шире модели", c.modelName)
		require.Contains(t, candidates.ObjectIDs, c.objectID,
			"выдача на %q сложена не тем ключом: вызывающий спрашивает её как %q "+
				"(константа %s), а снятое отрезание клало её под %q. Кандидат теряется, "+
				"и снаружи это неотличимо от «прав не выдали» (kacho#2003)",
			c.dotted, c.modelName, c.konstanta, c.truncated)
	}

	// ── Отрицание: отрезанных написаний в памятке быть не должно ВОВСЕ.
	// Без него правка «добавили перевод, отрезание оставили» прошла бы молча.
	for _, c := range cases {
		if c.truncated == c.modelName {
			continue // account/project — там отрезание и перевод неотличимы by construction
		}
		require.NotContains(t, scope.GrantedObjects, c.truncated,
			"ключ %q не просит ни один вызывающий: он производился отрезанием %q. "+
				"Его присутствие означает, что отрезание осталось рядом с переводом",
			c.truncated, c.dotted)
	}

	// ── Посторонний: положительное и отрицательное рядом. Без положительного
	// «чужого не видит» удовлетворял бы и запрос, не отдающий вообще ничего.
	stranger, strangerAccount := kac127SeedUserAndAccount(t, ctx, pool, "s2003")
	strangerScope := scopeOfUser(t, ctx, pool, stranger)

	require.Contains(t, strangerScope.ScopedAccounts, strangerAccount,
		"положительный контроль: посторонний обязан видеть СВОЙ аккаунт — иначе "+
			"следующие утверждения зеленели бы на пустой памятке")
	for _, c := range cases {
		if c.modelName == "account" {
			require.NotContains(t, strangerScope.ScopedAccounts, c.objectID,
				"посторонний не назван субъектом выдачи и не вправе получить %q", c.objectID)
			continue
		}
		if candidates := strangerScope.Candidates(c.modelName); candidates != nil {
			require.NotContains(t, candidates.ObjectIDs, c.objectID,
				"посторонний не назван субъектом выдачи и не вправе получить %q "+
					"в кандидаты типа %q", c.objectID, c.modelName)
		}
	}
	require.False(t, strangerScope.Unrestricted,
		"посторонний без выдач не может стать неограниченным — иначе сужения нет вовсе")
}
