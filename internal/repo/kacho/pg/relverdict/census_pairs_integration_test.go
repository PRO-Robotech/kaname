// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

// census_pairs_integration_test.go — #758, СТОРОНА ПРИБОРА: РАЗБОР ПАРАМЕТРА
// СЧИТАЕТ РОВНО ТО ЖЕ, ЧТО СЧИТАЛА СКЛЕЙКА.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Две точки прибора замера (`scalegrid.TakeCensus` и
// `scalegrid.TakeStrengthCensus`) отбирали строки субъекта выдачи склейкой
//
//	bs.subject_type || ':' || bs.subject_id = ANY($1::text[])
//
// и тем гасили `access_binding_subjects_subject_scope_idx` на КАЖДОЙ точке
// сетки. У второй из них комментарий при этом обещал «колонками, а не склейкой»
// — то есть прибор предостерегал от формы, которую сам исполнял.
//
// Обе переведены на разбор ПАРАМЕТРА: входной набор написаний разбирается на
// пары `(тип, идентификатор)`, и заход идёт голыми колонками.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ИМЕННО ОБЯЗАНА УТВЕРЖДАТЬ ЭТА ПРОБА
//
// НЕ стоимость. Прибор зовут единицы раз за прогон, и мерить его скорость
// незачем. Опасность правки прибора ровно одна и она противоположная: прибор,
// начавший считать ДРУГОЕ, тихо переопределяет все числа отчётов — и выглядит
// это как улучшение измеряемого кода.
//
// Поэтому утверждается РАВЕНСТВО двух форм на одной фикстуре, где обе дают
// НЕНОЛЬ. Ноль здесь — не «сошлось», а «сравнивать было нечего»: 0 == 0 верно
// при любой ошибке разбора, поэтому непустота проверяется отдельным
// утверждением, а не подразумевается.
//
// Прежняя форма живёт ЗДЕСЬ, в пробе, и это её законное место: в прод-коде она
// осталась бы вторым читателем того же предмета, а гейт
// `TestReadPathComparesColumnsNotConcatenations` — единственным, кто об этом
// знает.

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg/scalegrid"
)

// concatenatedFormSQL — ПРЕЖНЯЯ форма отбора, дословно.
//
// Оставлена как эталон сравнения: равенство доказывается против того, что
// стояло, а не против пересказа того, что стояло.
const concatenatedFormSQL = `
	SELECT count(*)::bigint
	  FROM kacho_iam.access_binding_subjects bs
	 WHERE bs.subject_type || ':' || bs.subject_id = ANY($1::text[])`

// TestCensus_ParsedPairsCountWhatConcatenationCounted — перепись выдач,
// называющих спрашиваемого, не изменилась от смены формы отбора.
func TestCensus_ParsedPairsCountWhatConcatenationCounted(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		seedCensusPairsFixture(t, ctx, tx)

		// ВХОД С ПОВТОРОМ — не педантизм, а единственное, что проверяет отбор
		// различных на разобранных парах. Склейка сравнивается с МНОЖЕСТВОМ
		// (`= ANY`), поэтому повтор написания её не трогает; соединение с
		// разобранными парами без отбора различных сосчитало бы строку выдачи
		// дважды. На входе без повторов обе формы согласны при любой ошибке.
		speakers := append(append([]string{}, probeSpeakers...), probeSpeakers[0])

		var byConcat int64
		if err := tx.QueryRow(ctx, concatenatedFormSQL, speakers).Scan(&byConcat); err != nil {
			t.Fatalf("прежняя форма отбора: %v", err)
		}
		got, err := scalegrid.TakeCensus(ctx, tx, speakers)
		if err != nil {
			t.Fatalf("перепись: %v", err)
		}

		t.Logf("перепись: написаний на входе %d (одно повторено), выдач, называющих спрашиваемого — "+
			"склейкой %d, разбором пары %d", len(speakers), byConcat, got.BindingsNamingSubject)

		// НЕПУСТОТА — отдельное утверждение. Без него равенство нулей объявило
		// бы формы согласными при любой ошибке разбора.
		if byConcat == 0 {
			t.Fatalf("прежняя форма насчитала ноль строк: фикстура не посеяла ни одной выдачи, " +
				"называющей спрашиваемого, и сравнивать было бы нечего")
		}
		if got.BindingsNamingSubject != byConcat {
			t.Fatalf("перепись РАЗОШЛАСЬ со склейкой: разбором пары %d, склейкой %d.\n"+
				"Прибор, начавший считать другое, тихо переопределяет числа всех отчётов, "+
				"и выглядит это как улучшение измеряемого кода.",
				got.BindingsNamingSubject, byConcat)
		}
	})
}

// TestStrengthCensus_ParsedPairsCountWhatConcatenationCounted — то же для второй
// точки прибора.
//
// ЗАЧЕМ ОТДЕЛЬНАЯ ТОЧКА: у неё СВОЙ текст запроса и свои дополнительные
// предикаты области. Инъекция это и показывает — возврат склейки во вторую
// точку оставляет первую пробу зелёной.
func TestStrengthCensus_ParsedPairsCountWhatConcatenationCounted(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		seedCensusPairsFixture(t, ctx, tx)

		var byConcat int64
		if err := tx.QueryRow(ctx, `
			SELECT count(*)::bigint
			  FROM kacho_iam.access_binding_subjects bs
			  JOIN kacho_iam.access_bindings b ON b.id = bs.binding_id
			 WHERE bs.subject_type || ':' || bs.subject_id = ANY($1::text[])
			   AND bs.resource_type = $2 AND bs.resource_id = $3
			   AND b.status = 'ACTIVE' AND b.revoked_at IS NULL`,
			probeSpeakers, "project", "prj-1").Scan(&byConcat); err != nil {
			t.Fatalf("прежняя форма отбора (прочность): %v", err)
		}
		got, err := scalegrid.TakeStrengthCensus(ctx, tx, scalegrid.StrengthCensusInput{
			Speakers:   probeSpeakers,
			MemberType: "user",
			MemberID:   "usr-1",
			ScopeType:  "project",
			ScopeID:    "prj-1",
			ObjectType: "vpc_network",
			ObjectID:   "net-0000000",
			RoleID:     "rol-cost",
			MaxDepth:   4,
		})
		if err != nil {
			t.Fatalf("перепись прочности: %v", err)
		}

		t.Logf("перепись прочности: строк (говорящий, область) — склейкой %d, разбором пары %d",
			byConcat, got.SpeakerScopeRows)

		if byConcat == 0 {
			t.Fatalf("прежняя форма насчитала ноль строк (говорящий, область): фикстура не " +
				"посеяла предмета, и сравнивать было бы нечего")
		}
		if got.SpeakerScopeRows != byConcat {
			t.Fatalf("перепись прочности РАЗОШЛАСЬ со склейкой: разбором пары %d, склейкой %d",
				got.SpeakerScopeRows, byConcat)
		}
	})
}

// seedCensusPairsFixture — выдача НА ПРОЕКТЕ, названная и лично, и через группу.
//
// Обе формы написания субъекта нужны сразу: разбор, потерявший групповое
// написание, остался бы согласен со склейкой на фикстуре, где выдача только
// личная, — и правка прибора уехала бы незамеченной.
func seedCensusPairsFixture(t *testing.T, ctx context.Context, tx pgx.Tx) {
	t.Helper()
	seedLabelledSet(t, ctx, tx, 1)
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.groups (id, account_id, name, description)
		 VALUES ($1, 'acc-1', 'census-pairs', '') ON CONFLICT DO NOTHING`, probeGroupID)
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.group_members (group_id, member_type, member_id)
		 VALUES ($1, 'user', 'usr-1') ON CONFLICT DO NOTHING`, probeGroupID)
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.access_bindings
		   (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
		 VALUES ('acb-grp', 'group', $1, 'rol-cost', 'project', 'prj-1', 'ACTIVE')
		 ON CONFLICT DO NOTHING`, probeGroupID)
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.access_binding_subjects (binding_id, subject_type, subject_id)
		 VALUES ('acb-grp', 'group', $1) ON CONFLICT DO NOTHING`, probeGroupID)
}
