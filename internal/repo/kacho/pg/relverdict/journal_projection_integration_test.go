// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

// journal_projection_integration_test.go — право, живущее ТОЛЬКО кортежем
// отношения, обязано быть видно форме E.
//
// # Предмет
//
// Движок отвечает по кортежам, и состояние его хранилища есть свёртка ОДНОГО
// журнала — `kacho_iam.fga_outbox`. Форма E отвечает по своим таблицам. Пока
// прямой факт не складывается из того же журнала, всякое право, которое никакая
// выдача не выводит (владение, поставленное при создании; указатель на предка;
// служебная учётка модуля; посев миграции), у формы E отсутствует — и форма
// отвечает «нет» там, где движок отвечает «да».
//
// Отвечает «нет» она МОЛЧА: пустая проекция не отличается от честного отказа ни
// одним признаком, поэтому теневое сравнение показывает расхождение, а не
// ошибку, и разбирать его начинают в правах, а не в наполнении.
//
// # Почему проба на ВЕРДИКТ, а не на строку таблицы
//
// Утверждение о строке пережило бы свой предмет: проекцию можно наполнять как
// угодно, а спрашивают у формы E вердикт. Здесь сеется то, что кладёт настоящий
// производитель (строка журнала ровно той формы, какую пишут и код, и миграции),
// и утверждается то, что читает настоящий потребитель.

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg/relverdict"
)

// enqueueTuple кладёт намерение доставки кортежа ровно так, как его кладут все
// производители: одна строка журнала, полезная нагрузка из трёх полей.
//
// Посев идёт ЖУРНАЛОМ, а не таблицей фактов, намеренно: фикстура, кладущая факт
// напрямую, доказывает работу запроса на данных, которых в проде не бывает, —
// ровно так дефект и дожил до находки на стенде.
func enqueueTuple(t *testing.T, ctx context.Context, tx pgx.Tx, event, user, relation, object string) {
	t.Helper()
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.fga_outbox (event_type, payload, created_at)
		 VALUES ($1, jsonb_build_object('user', $2::text, 'relation', $3::text, 'object', $4::text), now())`,
		event, user, relation, object)
}

// enqueueGrantSet кладёт ВТОРУЮ форму строки журнала — набор отношений одной
// выдачи, — ровно так, как её кладёт `fga_outbox.emitTx`: на выдаче рядом с
// набором едет совместимое эхо (первый элемент скаляром) для пода прежнего
// выпуска, на отзыве эха НЕТ намеренно.
//
// Фикстура повторяет производителя дословно и не снисходительнее его: положи
// она скаляр и на отзыве, проба зеленела бы на проекции, которая набора не
// читает вовсе, — то есть на том самом дефекте, ради которого написана.
func enqueueGrantSet(t *testing.T, ctx context.Context, tx pgx.Tx, event, user, object string, relations []string) {
	t.Helper()
	if event == "fga.tuple.write" {
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.fga_outbox (event_type, payload, created_at)
			 VALUES ($1, jsonb_build_object('user', $2::text, 'object', $3::text,
			                                'relations', to_jsonb($4::text[]),
			                                'relation', $4::text[] [1]), now())`,
			event, user, object, relations)
		return
	}
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.fga_outbox (event_type, payload, created_at)
		 VALUES ($1, jsonb_build_object('user', $2::text, 'object', $3::text,
		                                'relations', to_jsonb($4::text[])), now())`,
		event, user, object, relations)
}

func countFacts(t *testing.T, ctx context.Context, tx pgx.Tx, objectType, relation string) int {
	t.Helper()
	var n int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.relation_fact WHERE object_type = $1 AND relation = $2`,
		objectType, relation,
	).Scan(&n); err != nil {
		t.Fatalf("перепись фактов: %v", err)
	}
	return n
}

// Право служебной учётки модуля живёт ТОЛЬКО кортежем: его не выводит ни одна
// роль, и в проекцию оно попадает прямой строкой журнала.
//
// Объект вопроса — платформенный синглтон кластера: с #914 право писать кортежи
// объявлено кластерным отношением, а якорь вне иерархии, на котором оно висело
// прежде, снят вместе со своим типом. Предмет пробы от переезда не изменился —
// изменился объект, на котором он спрашивается.
func TestAsk_RightThatLivesOnlyAsARelationTupleIsAnswered(t *testing.T) {
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		enqueueTuple(t, ctx, tx, "fga.tuple.write",
			"service_account:sva-mod", "fga_writer", "cluster:cluster_kacho_root")

		got, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
			Subject: "service_account:sva-mod", ObjectType: "cluster",
			ObjectID: "cluster_kacho_root", Relation: "fga_writer",
		})
		if err != nil {
			t.Fatalf("запрос: %v", err)
		}
		if got != relverdict.Allow {
			t.Errorf("право, живущее кортежем, форме E невидимо: %v — движок на этом же "+
				"вопросе отвечает «да», и расхождение читается как дефект прав, а не как "+
				"ненаполненная проекция", got)
		}

		// Отрицание рядом: чужая учётка права не получает. Без него «да» выше
		// зеленело бы и на проекции, разрешающей всем.
		other, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
			Subject: "service_account:sva-other", ObjectType: "cluster",
			ObjectID: "cluster_kacho_root", Relation: "fga_writer",
		})
		if err != nil {
			t.Fatalf("запрос: %v", err)
		}
		if other != relverdict.Deny {
			t.Errorf("чужая учётка получила право: %v", other)
		}
	})
}

// Отзыв обязан доезжать той же дорогой: журнал несёт и снятие.
func TestAsk_WithdrawnRelationTupleStopsAnswering(t *testing.T) {
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		enqueueTuple(t, ctx, tx, "fga.tuple.write",
			"user:usr-1", "system_viewer", "cluster:cluster_kacho_root")

		granted, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
			Subject: "user:usr-1", ObjectType: "cluster",
			ObjectID: "cluster_kacho_root", Relation: "system_viewer",
		})
		if err != nil {
			t.Fatalf("запрос: %v", err)
		}
		// Положительный контроль: без него отрицание ниже зеленеет на проекции,
		// которая не наполняется вовсе.
		if granted != relverdict.Allow {
			t.Fatalf("выдача кортежем не дала права: %v", granted)
		}

		enqueueTuple(t, ctx, tx, "fga.tuple.delete",
			"user:usr-1", "system_viewer", "cluster:cluster_kacho_root")

		revoked, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
			Subject: "user:usr-1", ObjectType: "cluster",
			ObjectID: "cluster_kacho_root", Relation: "system_viewer",
		})
		if err != nil {
			t.Fatalf("запрос: %v", err)
		}
		if revoked != relverdict.Deny {
			t.Errorf("снятое право осталось у формы E: %v — проекция, не переживающая "+
				"отзыв, даёт доступ, которого движок уже не даёт", revoked)
		}
	})
}

// ЗАКОННЫЙ БЛИЗНЕЦ: кортеж-глагол в проекцию НЕ переносится.
//
// Глагол форма E выводит из выдачи (роль → тип × глагол → область), и это её
// предмет. Скопировать глагол фактом значило бы сделать форму E копией чужого
// хранилища: теневое сравнение стало бы тождеством и перестало бы что-либо
// доказывать — самая тихая из масок, потому что выглядит как согласие форм.
func TestFactProjection_DoesNotCopyVerbTuples(t *testing.T) {
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		enqueueTuple(t, ctx, tx, "fga.tuple.write",
			"user:usr-1", "v_get", "vpc_network:net-1")

		if n := countFacts(t, ctx, tx, "vpc_network", "v_get"); n != 0 {
			t.Errorf("глагол скопирован в проекцию прямых фактов (%d строк): сравнение "+
				"формы E с движком становится тождеством", n)
		}

		got, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
			Subject: "user:usr-1", ObjectType: "vpc_network", ObjectID: "net-1", Relation: "v_get",
		})
		if err != nil {
			t.Fatalf("запрос: %v", err)
		}
		if got != relverdict.Deny {
			t.Errorf("глагол дал право без выдачи: %v", got)
		}
	})
}

// Набор глаголов одной выдачи обязан ПРОХОДИТЬ и не проецироваться.
//
// Это регрессия на стык двух линий: проекция журнала (0098) читала одно поле
// `relation` и роняла вставку исключением, когда его нет, — а набор глаголов
// (0099 и её код) скалярного `relation` не несёт вовсе. Вместе это отвергало
// всякую выдачу и всякий отзыв, где у субъекта больше одного отношения на
// объекте: то есть ровно тот случай, ради которого вторая форма и заведена.
//
// Утверждается ИСХОД записи, а не форма строки: дефект проявлялся отказом
// транзакции вызывающего, и проба, смотрящая только в таблицу фактов, прошла бы
// мимо него — до таблицы дело не доходило.
func TestFactProjection_VerbSetPassesAndIsNotProjected(t *testing.T) {
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		verbs := []string{"v_get", "v_list", "v_update", "v_delete"}

		// Сама вставка и есть предмет: прежняя проекция роняла её здесь.
		enqueueGrantSet(t, ctx, tx, "fga.tuple.write", "user:usr-set", "vpc_network:net-set", verbs)
		enqueueGrantSet(t, ctx, tx, "fga.tuple.delete", "user:usr-set", "vpc_network:net-set", verbs)

		for _, verb := range verbs {
			if n := countFacts(t, ctx, tx, "vpc_network", verb); n != 0 {
				t.Errorf("глагол %s из набора скопирован в проекцию (%d строк): сравнение "+
					"формы E с движком становится тождеством", verb, n)
			}
		}
	})
}

// Набор НЕ-глаголов проецируется ЦЕЛИКОМ, а не первым элементом.
//
// Порядок чтения полей здесь и есть предмет. Строка выдачи набора несёт ОБА
// поля — весь набор и совместимое эхо (первый элемент скаляром). Проекция,
// прочитавшая скаляр первым, взяла бы из выдачи одно отношение из нескольких и
// молча потеряла остальные: своя БД знала бы о меньшем доступе, чем выдан
// движку. Отказа при этом не было бы ни одного — потому проба и утверждает
// КАЖДЫЙ элемент, а не факт непустоты.
//
// # Почему эхо — САМОЕ СЛАБОЕ отношение набора, а не первое попавшееся
//
// На типе `project` уровни выводят друг друга: `admin` даёт `editor`, тот даёт
// `viewer`. Набор, ведомый сильнейшим, прошёл бы и на проекции, читающей ОДНО
// эхо, — вывод довершил бы остальное, и проба зеленела бы ровно на том дефекте,
// ради которого написана. Поэтому эхо здесь `viewer`, а `admin` стоит дальше:
// при чтении одного эха `admin` и `editor` остаются без права, и проба краснеет.
func TestFactProjection_SetProjectsEveryRelationNotOnlyTheEcho(t *testing.T) {
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		// Эхо (первый элемент) — слабейшее; см. шапку.
		set := []string{"viewer", "admin"}
		// `editor` набором не назван и выводится из `admin`: он и различает
		// «спроецирован весь набор» от «спроецировано одно эхо».
		expect := []string{"viewer", "editor", "admin"}

		enqueueGrantSet(t, ctx, tx, "fga.tuple.write", "user:usr-multi", "project:prj-multi", set)

		for _, rel := range expect {
			got, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
				Subject: "user:usr-multi", ObjectType: "project",
				ObjectID: "prj-multi", Relation: rel,
			})
			if err != nil {
				t.Fatalf("запрос %s: %v", rel, err)
			}
			if got != relverdict.Allow {
				t.Errorf("отношение %s не получено из набора: %v — проекция взяла из выдачи "+
					"эхо вместо набора, и своя БД знает о меньшем доступе, чем выдан движку",
					rel, got)
			}
		}

		// Отрицание рядом: набор не раздаёт того, чего в нём нет. Глагол уровнями
		// НЕ выводится (см. модель), поэтому годится отрицательным контролем.
		absent, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
			Subject: "user:usr-multi", ObjectType: "project",
			ObjectID: "prj-multi", Relation: "v_get",
		})
		if err != nil {
			t.Fatalf("запрос v_get: %v", err)
		}
		if absent != relverdict.Deny {
			t.Errorf("набор дал отношение, которого не несёт: %v", absent)
		}

		// Отзыв набора снимает КАЖДОЕ отношение — иначе часть доступа пережила бы
		// собственное снятие, и это было бы не видно ни одному отказу. У отзыва эха
		// нет вовсе, поэтому проекция, читающая скаляр, не сняла бы ничего.
		enqueueGrantSet(t, ctx, tx, "fga.tuple.delete", "user:usr-multi", "project:prj-multi", set)
		for _, rel := range expect {
			got, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
				Subject: "user:usr-multi", ObjectType: "project",
				ObjectID: "prj-multi", Relation: rel,
			})
			if err != nil {
				t.Fatalf("запрос после отзыва %s: %v", rel, err)
			}
			if got != relverdict.Deny {
				t.Errorf("отношение %s пережило отзыв набора: %v", rel, got)
			}
		}
	})
}

// Перепись: сколько строк журнала осмотрено проекцией. «Ноль расхождений» без
// неё неотличимо от «ноль прочитанного».
func TestFactProjection_CountsWhatItProjected(t *testing.T) {
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		const facts = 3
		// Считается ПРИРОСТ: в проекции уже лежит свёртка журнала, накопленного
		// посевами миграций, и утверждать об абсолютном числе значило бы утверждать
		// о посевах, о которых эта проба ничего не знает.
		var before int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM kacho_iam.relation_fact`).Scan(&before); err != nil {
			t.Fatalf("перепись до: %v", err)
		}
		enqueueTuple(t, ctx, tx, "fga.tuple.write", "user:usr-1", "admin", "project:prj-a")
		enqueueTuple(t, ctx, tx, "fga.tuple.write", "user:usr-2", "admin", "project:prj-a")
		enqueueTuple(t, ctx, tx, "fga.tuple.write", "project:prj-a", "project", "vpc_network:net-1")
		// Глагол — не факт, и в перепись не идёт.
		enqueueTuple(t, ctx, tx, "fga.tuple.write", "user:usr-1", "v_get", "vpc_network:net-1")

		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM kacho_iam.relation_fact`).Scan(&n); err != nil {
			t.Fatalf("перепись: %v", err)
		}
		got := n - before
		if got != facts {
			t.Errorf("спроецировано строк %d, ожидалось %d (в базе было %d, стало %d)",
				got, facts, before, n)
		}
		t.Logf("осмотрено строк журнала 4, спроецировано фактов %d; "+
			"до пробы в проекции уже лежало %d — свёртка журнала, накопленного посевами миграций",
			got, before)
	})
}
