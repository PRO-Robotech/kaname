// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// own_lane_head_agrees_test.go — голова идентичности нашей полосы, по которой
// триггер темпа заведения узнаёт носителя (Ф4 Р5), записана в схеме тем же
// значением, что константа производителя `domain.OwnLaneSubjectHead`. Второе
// написание одного факта разошлось бы молча: триггер перестал бы узнавать нашу
// полосу и ключевал бы её отчеканенной идентичностью — свежей у каждого
// заведения, — то есть рубеж исчез бы без отказа.
package migrations_test

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/migrations"
)

// ownLaneHeadLiterals — литералы формы `LIKE '<голова>%'` рядом с `external_id`
// в накате миграций: все они обязаны нести голову производителя.
var ownLaneHeadLiterals = regexp.MustCompile(`external_id\s+LIKE\s+'([^']*)%'`)

func TestOwnLaneSubjectHeadAgreesWithTheSchema(t *testing.T) {
	var files, hits int
	var heads []string
	err := fs.WalkDir(migrations.FS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".sql") {
			return err
		}
		body, rerr := fs.ReadFile(migrations.FS, path)
		if rerr != nil {
			return rerr
		}
		files++
		up := migrations.MigrationUpSection(string(body))
		for _, m := range ownLaneHeadLiterals.FindAllStringSubmatch(up, -1) {
			hits++
			heads = append(heads, m[1])
		}
		return nil
	})
	require.NoError(t, err)
	t.Logf("перепись: миграций прочитано %d · голов полосы в накатах %d · производитель %q", files, hits, domain.OwnLaneSubjectHead)
	require.NotZero(t, files, "пустой обход — отказ, а не ноль находок")
	require.NotZero(t, hits, "ни одна миграция не судит голову полосы — триггер темпа не различает полос, и это находка")
	for _, h := range heads {
		require.Equal(t, domain.OwnLaneSubjectHead, h, "схема узнаёт нашу полосу по голове %q, производитель чеканит %q", h, domain.OwnLaneSubjectHead)
	}
	// Инъекция в обе стороны на синтетическом накате: чужая голова — красное,
	// та же — молчание.
	require.Equal(t, [][]string{{"external_id LIKE 'ext:%'", "ext:"}},
		ownLaneHeadLiterals.FindAllStringSubmatch("WHEN u.external_id LIKE 'ext:%' THEN", -1))
	require.Empty(t, ownLaneHeadLiterals.FindAllStringSubmatch("-- голова 'own:' в комментарии без LIKE", -1))
}
