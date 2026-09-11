// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// grant_removal_trace_test.go — гейт: миграция, снимающая выдачи, оставляет
// след; и ни одна миграция не переносит выдачу с одной роли на другую.
//
// Предмет, единица счёта, довод в пользу храповика и граница разобраны в
// шапке `grant_removal_trace.go` — здесь они не пересказываются.
//
// Держатель `TestNoMigrationMovesGrantsBetweenRoles` назван приёмкой
// `docs/engineering/acceptance/seed-identity-names-its-own-service.md` §6 и до
// этого файла не существовал ни в одном файле дерева — только в комментариях
// (`internal/domain/constants_extended.go`, `internal/domain/seeded_ids.go`).
//
// Доказательство способности упасть и смолчать — в
// `grant_removal_trace_injection_test.go`.
//
// Корпус читается ЭМБЕДОМ (`migrations.FS`), а не индексом git: миграции —
// часть поставляемого двоичного (`cmd/migrator`), и их состав уже участвует в
// кеше сборки Go — второй, независимый от `git ls-files`, источник состава
// здесь не нужен и не заводится.
package migrations_test

import (
	"io/fs"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/migrations"
)

// grantRemovalCorpus — корпус миграций службы, взятый эмбедом.
func grantRemovalCorpus(t *testing.T) []migrations.GrantMigrationSource {
	t.Helper()
	entries, err := fs.ReadDir(migrations.FS, ".")
	if err != nil {
		t.Fatalf("ПРЕДПОСЫЛКА ЛОЖНА: каталог миграций не перечислен: %v", err)
	}
	var paths []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		paths = append(paths, e.Name())
	}
	corpus, err := migrations.ReadMigrationCorpus(paths, func(name string) ([]byte, error) {
		return fs.ReadFile(migrations.FS, name)
	})
	if err != nil {
		t.Fatalf("ПРЕДПОСЫЛКА ЛОЖНА: файл корпуса не читается: %v", err)
	}
	return corpus
}

// TestMigrationRemovingGrantsLeavesATrace — IAM-RM-1-11.
func TestMigrationRemovingGrantsLeavesATrace(t *testing.T) {
	corpus := grantRemovalCorpus(t)

	silent, c := migrations.AuditGrantRemovalTrace(corpus)
	mentions := migrations.GrantTableMentions(corpus)

	// Перепись печатается ДО вердикта: она обязана быть видна и на зелёном
	// прогоне, иначе «ноль находок» неотличимо от «ноль прочитанного».
	t.Logf("перепись: файлов корпуса прочитано %d; операторов, называющих таблицу выдач %d; "+
		"с удалением выдач где угодно %d; из них в накатной половине %d; "+
		"из них без следа %d (храповик %d)",
		c.FilesRead, mentions, c.WithDelete, c.InUpHalf, len(silent), migrations.GrantRemovalRatchet)
	if len(silent) > 0 {
		t.Logf("прощённые сегодня: %s", strings.Join(silent, ", "))
	}

	// ПРЕДПОСЫЛКИ. Каждая — факт, который может измениться и сделать вердикт
	// беспредметным, поэтому гейт проверяет их сам, а не подразумевает.
	if c.FilesRead == 0 {
		t.Fatalf("ПРЕДПОСЫЛКА ЛОЖНА: в корпусе миграций не прочитано ни одного файла")
	}
	if mentions == 0 {
		t.Fatalf("ПРЕДПОСЫЛКА ЛОЖНА: во всём корпусе таблица kaname.access_bindings не " +
			"названа НИ ОДНИМ оператором. Выдача существует только в схеме iam, поэтому " +
			"ноль означает либо нечитаемый корпус, либо разбор, разъехавшийся со схемой, — " +
			"и молчание вердикта было бы сказано о нём, а не о дереве")
	}

	if len(silent) != migrations.GrantRemovalRatchet {
		t.Error(migrations.GrantRemovalFinding(len(silent), silent))
	}
}

// TestNoMigrationMovesGrantsBetweenRoles — IAM-RM-1-13, характеризующий замок.
//
// Дерево уже даёт это поведение; проба обязана его ПЕРЕЖИТЬ, а не покраснеть.
// Требовать от неё красноты запрещено: она утверждает, что отвергнутый исход
// («перенести выдачи на роли-преемники») не исполнялся ни разу, а не что
// кто-то его исполнил.
func TestNoMigrationMovesGrantsBetweenRoles(t *testing.T) {
	corpus := grantRemovalCorpus(t)

	moves, statements := migrations.AuditGrantRoleReassignment(corpus)
	mentions := migrations.GrantTableMentions(corpus)
	t.Logf("перепись: файлов корпуса %d; операторов, называющих таблицу выдач %d; "+
		"операторов «UPDATE access_bindings … SET» в накатной половине %d; "+
		"из них переставляющих role_id %d",
		len(corpus), mentions, statements, len(moves))

	if mentions == 0 {
		t.Fatalf("ПРЕДПОСЫЛКА ЛОЖНА: во всём корпусе таблица kaname.access_bindings не " +
			"названа НИ ОДНИМ оператором — отрицание «переносов не бывает» выполняется " +
			"тождественно, и его молчание сказано о разборе, а не о дереве")
	}
	if len(moves) > 0 {
		t.Errorf("миграция переставляет выдачу с одной роли на другую: %s. "+
			"Это ТИХОЕ расширение прав: выдача на снятую роль дала бы доступ к ресурсу, "+
			"которого выдававший НЕ НАЗЫВАЛ, а согласия у него никто не спрашивал. "+
			"Законный путь — снять выдачу и оставить след",
			strings.Join(moves, ", "))
	}
}
