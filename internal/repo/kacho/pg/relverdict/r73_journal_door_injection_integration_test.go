// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

// r73_journal_door_injection_integration_test.go — инъекция гейта Г7 В ОБЕ СТОРОНЫ.
//
// Гейт судится ПРОГОНОМ, а не чтением описания. Здесь доказывается, что
// `TestR7_3_27_JournalSurvivesTheDrainRemoval` СПОСОБЕН упасть — и падает на
// существе (обесточенный источник прямого факта), а не на форме.
//
// ЗАКОННЫЙ БЛИЗНЕЦ — сам гейт на этом дереве. Дренаж журнала уже снят, движка уже
// нет, и гейт ЗЕЛЁН: то есть «снятие дренажа при живом журнале» его не роняет, а
// роняет именно обесточенный журнал. Второй половиной инъекции служит он сам, и
// это сказано здесь прямо, чтобы её не искали отдельным файлом.

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho-iam/internal/clients"
	kachopg "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg/relverdict"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"
)

// TestR7_3_27_InjectionRedWhenTheJournalIsDeadened — сняли триггер журнала (то,
// что произошло бы от буквального «снять движок вместе с его очередью») → тракт
// обесточен, и утверждение гейта НЕ выполняется.
//
// Проба намеренно не зовёт сам гейт: она воспроизводит его ключевое утверждение
// на испорченном дереве и требует, чтобы оно НЕ ВЫПОЛНИЛОСЬ. Позови она гейт —
// пришлось бы ловить его `t.Fatal`, а это проверка механики testing, а не тракта.
func TestR7_3_27_InjectionRedWhenTheJournalIsDeadened(t *testing.T) {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, pgtest.NewDB(t))
	if err != nil {
		t.Fatalf("пул: %v", err)
	}
	pgtest.ClosePoolAtEnd(t, pool)

	// ИНЪЕКЦИЯ: обесточиваем проекцию ровно тем способом, каким её обесточило бы
	// буквальное исполнение команды «снять журнал вместе с дренажом».
	if _, derr := pool.Exec(ctx,
		`DROP TRIGGER IF EXISTS relation_fact_follows_journal ON kacho_iam.fga_outbox`); derr != nil {
		t.Fatalf("инъекция: снятие триггера проекции: %v", derr)
	}

	const (
		subject    = "user:usr_r73injection"
		objectType = "cluster"
		objectID   = "cluster_kacho_root"
		relation   = "system_admin"
	)

	asker := relverdict.NewAsker(pool)
	writer := kachopg.NewCreatorTupleWriter(pool)
	if asker == nil || writer == nil {
		t.Fatal("форма или продуктовый писатель не собраны")
	}

	if werr := writer.RecordTuples(ctx, []clients.RelationTuple{{
		User: subject, Relation: relation, Object: objectType + ":" + objectID,
	}}); werr != nil {
		t.Fatalf("запись намерения: %v", werr)
	}

	allowed, aerr := asker.Allowed(ctx, subject, objectType, objectID, relation, nil)
	if aerr != nil {
		t.Fatalf("форма не ответила: %v", aerr)
	}
	if allowed {
		t.Fatal("НА ОБЕСТОЧЕННОМ ТРАКТЕ ДОСТУП ВСЁ РАВНО ЕСТЬ — значит утверждение " +
			"гейта Г7 держится не на журнале, и его зелёный ничего не доказывает: " +
			"проекция наполняется чем-то ещё, либо вердикт приходит не из неё")
	}
	t.Log("инъекция подтверждена: без триггера журнала записанное намерение не даёт " +
		"доступа — утверждение гейта Г7 держится ИМЕННО на тракте «журнал → проекция → вердикт»")
}
