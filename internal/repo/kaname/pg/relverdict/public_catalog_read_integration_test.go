// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

// public_catalog_read_integration_test.go — ПУБЛИЧНОЕ ЧТЕНИЕ СПРАВОЧНИКА
// РАЗРЕШАЕТСЯ ВСЯКОМУ АУТЕНТИФИЦИРОВАННОМУ, И ЗАКРЫВАЕТСЯ СНЯТИЕМ ВЫДАЧИ.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ЭТА ПРОБА НЕСУЩАЯ
//
// Девять чтений глобального справочника (регионы, зоны, типы машин, типы дисков,
// словарь прав) вернулись из полосы «проверки нет» под настоящую проверку:
// отношение `viewer` на кластерном синглтоне. Весь этот перевод держится на ОДНОМ
// утверждении о вердикте — что подстановочный субъект системной выдачи выполняет
// это отношение за любого аутентифицированного. Пока утверждение не проверено
// вопросом к вердикту, оно остаётся допущением, а цена ошибки — арендатор не
// может выбрать ни зону, ни тип машины, то есть не может создать ничего.
//
// Гейт каталога проверяет, что у отношения ЕСТЬ производитель в дереве; он не
// спрашивает вердикт. Здесь спрашивается вердикт.
//
// ─────────────────────────────────────────────────────────────────────────────
// ТРИ УТВЕРЖДЕНИЯ, И НИ ОДНО НЕ СВОДИТСЯ К ДРУГОМУ
//
//	(а) субъект, которому НИЧЕГО не выдавали, читает справочник — разрешение
//	    приходит от подстановки, а не от его собственных прав;
//	(б) ЗАКОННЫЙ БЛИЗНЕЦ: тот же субъект НЕ получает административного отношения
//	    того же объекта — подстановка расширяет ровно одно отношение, а не всё;
//	(в) снятие факта, который производит системная выдача, ЗАКРЫВАЕТ доступ —
//	    то есть отзыв выдачи есть операция, а не выкатка.

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
)

func TestAsk_R893_PublicCatalogReadComesFromTheSystemGrant(t *testing.T) {
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		// Предпосылка: подстановочный факт заведён посевом, а не пробой. Проба,
		// сеющая его сама, утверждала бы о своей фикстуре, а не о платформе.
		var seeded int
		if err := tx.QueryRow(ctx, `
			SELECT count(*) FROM kaname.relation_fact
			 WHERE object_type = 'cluster' AND object_id = $1
			   AND relation = 'viewer' AND subject = 'user:*'`,
			domain.ClusterSingletonID).Scan(&seeded); err != nil {
			t.Fatalf("предпосылка не прочитана: %v", err)
		}
		if seeded != 1 {
			t.Fatalf("подстановочного основания публичного чтения нет (%d) — "+
				"системная выдача справочника не доехала, и всё, что утверждается ниже, "+
				"утверждалось бы о пустоте", seeded)
		}

		const nobody = "user:usr-nobody-has-granted-me-anything"

		// (а) Субъект без единой собственной выдачи читает справочник.
		got, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
			Subject: nobody, ObjectType: "cluster", ObjectID: domain.ClusterSingletonID,
			Relation: "viewer",
		})
		if err != nil {
			t.Fatalf("вопрос о публичном чтении справочника: %v", err)
		}
		if got != relverdict.Allow {
			t.Fatalf("публичное чтение справочника: вердикт = %s, ожидался %s.\n"+
				"Девять чтений каталогов гейтятся этим отношением; отказ здесь означает, "+
				"что арендатор не может выбрать ни зону, ни тип машины, ни тип диска — "+
				"то есть не может создать ни машину, ни том.", got, relverdict.Allow)
		}

		// (б) Законный близнец: подстановка расширяет ОДНО отношение, а не всё.
		// Без этого утверждения проба зеленела бы и на форме, разрешающей на
		// кластере что угодно кому угодно.
		admin, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
			Subject: nobody, ObjectType: "cluster", ObjectID: domain.ClusterSingletonID,
			Relation: "system_admin",
		})
		if err != nil {
			t.Fatalf("вопрос об административном отношении: %v", err)
		}
		if admin == relverdict.Allow {
			t.Fatalf("субъект без выдач получил на кластере отношение system_admin — "+
				"подстановка обязана расширять ровно то отношение, которое выдано, "+
				"а не всю кластерную поверхность (вердикт = %s)", admin)
		}

		// (в) Отзыв закрывает доступ. Снимается ФАКТ — ровно то, что снимает отзыв
		// системной выдачи (журнал → проекция); путь отзыва целиком проверяется
		// пробой репозитория, здесь — его СЛЕДСТВИЕ для решения о доступе.
		exec(t, ctx, tx, `
			DELETE FROM kaname.relation_fact
			 WHERE object_type = 'cluster' AND object_id = $1
			   AND relation = 'viewer' AND subject = 'user:*'`,
			domain.ClusterSingletonID)

		after, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
			Subject: nobody, ObjectType: "cluster", ObjectID: domain.ClusterSingletonID,
			Relation: "viewer",
		})
		if err != nil {
			t.Fatalf("вопрос после отзыва: %v", err)
		}
		if after == relverdict.Allow {
			t.Fatalf("после снятия основания публичное чтение справочника всё ещё "+
				"разрешено (вердикт = %s) — значит отзыв системной выдачи ничего не "+
				"закрывает, и доступ держится не тем, что показано на поверхности", after)
		}
	})
}
