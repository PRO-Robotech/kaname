// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/migrations"
)

// Инъекция гейта разреза секции: способность упасть и способность смолчать
// доказываются ПРОГОНОМ, а не прочтением.
//
// Каждый случай меняет РОВНО ОДИН факт против своего законного близнеца: иначе
// неизвестно, который из двух дал вердикт.
//
// Директива НИ РАЗУ не выписана здесь литералом — фикстуры собираются из
// константы владельца. Файл проб гейт не читает by construction (границу
// объявляет шапка ядра), поэтому запрет тут не действует; собранная фикстура
// нужна по другой причине: второе написание директивы в дереве не заводится
// даже там, где оно законно, — иначе гейт стерёг бы форму, которой сам
// противоречит.
const sectionUpMarker = migrations.SectionMarkerStem + "Up"

// sectionOwnerBody — тело файла-владельца: он объявляет директиву, и это его
// предмет.
func sectionOwnerBody() string {
	return "package migrations\n\nconst SectionMarkerStem = " +
		strconv.Quote(migrations.SectionMarkerStem) + "\n"
}

// sectionCopyBody — не-тестовый файл, выписавший директиву ЛИТЕРАЛОМ.
func sectionCopyBody(marker string) string {
	return fmt.Sprintf(`package other

import "strings"

func upHalf(body string) string {
	if i := strings.Index(body, %s); i >= 0 {
		return body[:i]
	}
	return body
}
`, strconv.Quote(marker))
}

// sectionLawfulBody — тот же разрез, взятый у владельца: литерала нет.
const sectionLawfulBody = `package other

import "github.com/PRO-Robotech/kaname/internal/migrations"

func upHalf(body string) string { return migrations.MigrationUpText(body) }
`

func sectionCorpus(files map[string]string) check.TreeCorpus {
	corpus := check.TreeCorpus{check.MigrationSectionOwnerRel: sectionOwnerBody()}
	for rel, body := range files {
		corpus[rel] = body
	}
	return corpus
}

// TestSectionSplitInjection_LiteralOfEitherMarkerIsAFinding — ДЕФЕКТ, обе
// половины популяции: и директива отката, и директива прямого хода.
func TestSectionSplitInjection_LiteralOfEitherMarkerIsAFinding(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		marker string
	}{
		{"директива отката", migrations.SectionDownMarker},
		{"директива прямого хода", sectionUpMarker},
	} {
		t.Run(tc.name, func(t *testing.T) {
			findings, census, err := check.AuditMigrationSectionSplit(sectionCorpus(
				map[string]string{"internal/other/up_half.go": sectionCopyBody(tc.marker)}))
			require.NoError(t, err)
			require.Len(t, findings, 1, "перепись: файлов %d, литералов %d, у владельца %d",
				census.FilesRead, census.Literals, census.OwnerLiterals)
			require.Contains(t, findings[0], "internal/other/up_half.go:6",
				"находка обязана называть координату, а не только факт")
			require.Contains(t, findings[0], check.MigrationSectionOwnerRel,
				"находка обязана называть, где предмет объявлен")
			t.Logf("нарушение названо с координатой: %s", findings[0])
		})
	}
}

// TestSectionSplitInjection_LawfulTwinsAreSilent — ЗАКОННЫЕ БЛИЗНЕЦЫ: каждый
// отличается от дефекта выше ровно одним фактом.
func TestSectionSplitInjection_LawfulTwinsAreSilent(t *testing.T) {
	t.Parallel()

	prose := "package other\n\n// Разрез делается по " + migrations.SectionDownMarker +
		": директива сама записана комментарием.\nfunc noop() {}\n"

	// Стем БЕЗ завершающего пробела — проза о директивах вообще, а не написание
	// маркера. Такой литерал в дереве уже есть (отпечаток сетки замера).
	stemOnly := fmt.Sprintf("package other\n\nvar why = %s\n",
		strconv.Quote("в комментариях живут директивы мигратора ("+
			strings.TrimSuffix(migrations.SectionMarkerStem, " ")+"), отделить их нельзя"))

	for _, tc := range []struct {
		name string
		body string
	}{
		{"разрез взят у владельца", sectionLawfulBody},
		{"директива стоит в комментарии", prose},
		{"проза о директивах без написания маркера", stemOnly},
	} {
		t.Run(tc.name, func(t *testing.T) {
			findings, census, err := check.AuditMigrationSectionSplit(sectionCorpus(
				map[string]string{"internal/other/up_half.go": tc.body}))
			require.NoError(t, err)
			require.Emptyf(t, findings, "законный близнец обязан молчать: %v", findings)
			require.Equal(t, 1, census.OwnerLiterals,
				"единственный литерал дерева обязан остаться у владельца")
			t.Logf("молчание при переписи: файлов %d, литералов %d, у владельца %d",
				census.FilesRead, census.Literals, census.OwnerLiterals)
		})
	}
}

// TestSectionSplitInjection_VoidIsRefusedNotGreen — ТРЕТИЙ ИСХОД: беспредметный
// обход не выдаётся за чистоту.
func TestSectionSplitInjection_VoidIsRefusedNotGreen(t *testing.T) {
	t.Parallel()

	t.Run("обход пуст", func(t *testing.T) {
		_, census, err := check.AuditMigrationSectionSplit(check.TreeCorpus{})
		require.Error(t, err, "пустой обход обязан быть ОТКАЗОМ, а не «находок ноль»")
		require.Zero(t, census.FilesRead)
		t.Logf("отказ назван: %v", err)
	})

	t.Run("владелец перестал объявлять директиву", func(t *testing.T) {
		_, _, err := check.AuditMigrationSectionSplit(check.TreeCorpus{
			check.MigrationSectionOwnerRel: "package migrations\n\nfunc noop() {}\n",
		})
		require.Error(t, err, "предпосылка гейта исчезла — молчание означало бы слепоту")
		require.Contains(t, err.Error(), check.MigrationSectionOwnerRel)
		t.Logf("отказ назван: %v", err)
	})

	t.Run("файл не разобран", func(t *testing.T) {
		_, _, err := check.AuditMigrationSectionSplit(sectionCorpus(
			map[string]string{"internal/other/broken.go": "это не Go"}))
		require.Error(t, err, "неразобранный файл — отказ: судить непрочитанное нельзя")
		require.Contains(t, err.Error(), "internal/other/broken.go")
		t.Logf("отказ назван: %v", err)
	})
}
