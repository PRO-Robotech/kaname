// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// six_withdrawn_kinds_leave_accounting_integration_test.go — шесть видов,
// которые НИКОГДА не списывались, уходят и из УЧЁТА, а не только из каталога.
//
// Задача `PRO-Robotech/kacho#2117`, приёмка `KAN-QUOTA-1`, сценарий `KAN-Q3-04`
// («ни одна строка учёта этих шести видов в базе службы доступа не остаётся»),
// условие готовности `DoD S3` п. 3.
//
// # Почему проба ИНТЕГРАЦИОННАЯ, а не по тексту миграции
//
// Соседняя проба `TestSixNeverChargedKindsAreNoLongerCountable` (пакет `domain`)
// держит ДРУГУЮ половину: что каталог их больше не принимает. Она читает
// объявление на Go и о базе не утверждает ничего.
//
// Здесь предмет — состояние БАЗЫ после применения всех миграций: величины,
// посеянные `0001_initial.sql`, обязаны быть сняты новой миграцией. Проверить
// это чтением текста нельзя — текст миграции скажет, что она удаляет, но не
// скажет, применилась ли она и не завела ли строки обратно чья-нибудь ещё.
//
// # Пара, а не одно утверждение
//
// Отрицание «строк снятых видов нет» зеленеет на ПУСТОЙ таблице величин —
// например, если миграция посева не применилась вовсе. Поэтому рядом стоит
// положительный контроль: у ТРЁХ действующих видов службы величины на месте.
// Он краснеет, если снятие ушло шире своего предмета, и он же доказывает, что
// таблица вообще наполнена.

package migrations_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/pgtest"
)

func TestSixWithdrawnKinds_LeaveTheAccountingAndTheThreeLiveOnesStay(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db := upAllIAMMigrations(t, pgtest.NewEmptyDB(t))
	defer db.Close()

	// Снятые — те, у кого списывающего триггера не было ни одного.
	withdrawn := []string{
		"iam.project",
		"iam.user",
		"iam.serviceAccount",
		"iam.group",
		"iam.role",
		"iam.accessBinding",
	}
	// Оставшиеся — те, чей вызов `kacho_quota_count` стоит в применённой миграции.
	kept := []string{
		"iam.account",
		"iam.user.credential",
		"iam.serviceAccount.credential",
	}

	for _, kind := range withdrawn {
		var ceilings, accounting int
		require.NoError(t, db.QueryRow(
			`SELECT count(*) FROM kaname.limits WHERE kind = $1`, kind).Scan(&ceilings))
		require.Zerof(t, ceilings,
			"величина вида «%s» осталась в `kaname.limits`: вид снят с каталога, "+
				"поэтому назначить её больше нельзя, а строка продолжала бы описывать "+
				"потолок, которого не существует", kind)

		require.NoError(t, db.QueryRow(
			`SELECT count(*) FROM kaname.project_resource_quotas WHERE kind = $1`, kind).Scan(&accounting))
		require.Zerof(t, accounting,
			"строка учёта вида «%s» осталась в `kaname.project_resource_quotas`: "+
				"без своей величины она описывает потолок, которого больше нет", kind)
	}

	// Положительный контроль: без него отрицание выше зеленело бы на базе, где
	// посев величин не применился вовсе.
	//
	// ИСТОЧНИК ВЕЛИЧИНЫ ТРЁХ ДЕЙСТВУЮЩИХ ПЕРЕЕХАЛ (приёмка `KAN-QUOTA-1`, `П25`;
	// задача #2117). Здесь стояло чтение `kaname.limits`, и предмет утверждения
	// СМЕНИЛСЯ: величину этих трёх больше не назначает авторитет — её объявляет
	// посадка службы, а миграция перенесла объявленное в проекцию.
	//
	// Само утверждение не ослаблено: «величина у вида ЕСТЬ» — то, чем этот
	// контроль отличает снятие своего предмета от снятия шире предмета. Сменилось
	// только место, где величина лежит, и второе утверждение ниже прямо требует,
	// чтобы у авторитета её больше НЕ БЫЛО: оставленная строка обещала бы
	// администратору управление величиной, которая ни на что не влияет.
	for _, kind := range kept {
		var stated int
		require.NoError(t, db.QueryRow(
			`SELECT count(*) FROM kaname.own_ceilings WHERE kind = $1`, kind).Scan(&stated))
		require.NotZerof(t, stated,
			"вид «%s» СПИСЫВАЕТСЯ и обязан сохранить свою величину: снятие вместе с "+
				"шестью означало бы, что потолок перестал наступать, и никто этого не решал", kind)

		var atAuthority int
		require.NoError(t, db.QueryRow(
			`SELECT count(*) FROM kaname.limits WHERE kind = $1`, kind).Scan(&atAuthority))
		require.Zerof(t, atAuthority,
			"величина вида «%s» осталась у авторитета: списание читает проекцию "+
				"посадки, значит назначенное здесь было бы принято и не применено ни разу", kind)
	}

	// И ЗАКОННЫЙ БЛИЗНЕЦ обоих утверждений: у ЧУЖОГО вида величина у авторитета
	// остаётся. Без него «у авторитета нет» зеленело бы на пустой таблице величин,
	// то есть на дереве, где пять потребителей потеряли свои потолки.
	var foreign int
	require.NoError(t, db.QueryRow(
		`SELECT count(*) FROM kaname.limits WHERE kind = 'vpc.network'`).Scan(&foreign))
	require.NotZero(t, foreign,
		"величина чужого вида снята вместе с собственными: роль потребителя сломана, "+
			"а снятие авторитета целиком — предмет стадии S4, не этой")

	t.Logf("перепись: снятых видов сверено %d, действующих %d, чужих контрольных 1",
		len(withdrawn), len(kept))
}
