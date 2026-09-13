// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// migrator_showcase_name_injection_test.go — доказательство, что гейт имени
// накатчика на витрине СПОСОБЕН упасть и СПОСОБЕН смолчать (задача #17,
// семейство `kanamemigratorshowcase`).
//
// Гейт зелен на сегодняшнем дереве, и это не доказывает ничего: зелёным он был
// бы и с предикатом, который ничего не ищет. Инъекция зовёт ТУ ЖЕ функцию, что и
// гейт, а не её копию.
package supplyhygiene

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"
	"github.com/PRO-Robotech/kaname/internal/check"

	"github.com/stretchr/testify/require"
)

// injProducts — словарь имён продуктов, каким его отдаёт владелец имён.
var injProducts = []string{"kacho", "kaname"}

// injOwn — накатчик этого продукта, каким его читают у производителя.
const injOwn = "kaname-migrator"

func TestMigratorShowcaseScan_InjectionBothWays(t *testing.T) {
	cases := []struct {
		name string
		body string
		// wantToken — чужой токен, который обязан быть назван; пусто — гейт молчит.
		wantToken  string
		wantLine   int
		wantSeen   int
		wantJudged int
		wantOwn    int
		wantDiacr  int
	}{
		{
			// ДЕФЕКТ: витрина называет накатчик ЧУЖОГО продукта. Ровно тот
			// случай, ради которого семейство заведено.
			name:       "чужой накатчик — находка с координатой",
			body:       "Накатите схему:\n\n    kacho-migrator up\n",
			wantToken:  "kacho-migrator",
			wantLine:   3,
			wantSeen:   1,
			wantJudged: 1,
		},
		{
			// ЗАКОННЫЙ БЛИЗНЕЦ: та же форма записи, имя своё. Без него гейт
			// ловил бы форму, а не существо, и первый же законный документ
			// сделал бы его ложно-красным.
			name:       "свой накатчик — гейт молчит",
			body:       "Накатите схему:\n\n    kaname-migrator up\n",
			wantSeen:   1,
			wantJudged: 1,
			wantOwn:    1,
		},
		{
			// ОБЪЯВЛЕННАЯ ГРАНИЦА: цель сборки имени платформы не несёт и
			// предметом критерия не является. Судить её значило бы завести
			// гейт, у которого находки ложные, — такие отключают первым.
			name:     "цель сборки — встречена, но НЕ судится",
			body:     "make build-migrator\n",
			wantSeen: 1,
		},
		{
			// СЕГМЕНТОМ, А НЕ ПРИСТАВКОЙ: имя платформы стоит ВТОРЫМ словом от
			// конца. Распознаватель, читающий только приставку, такую запись не
			// отверг бы, а НЕ УВИДЕЛ — то есть дал бы молчание вместо находки.
			name:       "имя продукта НЕ первым сегментом — всё равно судится",
			body:       "command: [\"/usr/local/bin/kacho-nlb-migrator\", \"up\"]\n",
			wantToken:  "kacho-nlb-migrator",
			wantLine:   1,
			wantSeen:   1,
			wantJudged: 1,
		},
		{
			// ОБЕ ЛАТИНСКИЕ ФОРМЫ: предикат, знающий одну, недобирает МОЛЧА.
			name:       "диакритическая форма имени платформы — судится и считается",
			body:       "Запустите kachō-migrator up\n",
			wantToken:  "kachō-migrator",
			wantLine:   1,
			wantSeen:   1,
			wantJudged: 1,
			wantDiacr:  1,
		},
		{
			// Путь установки и путь сборки дают ТОТ ЖЕ токен, что голое имя.
			name:       "три написания — один токен",
			body:       "kacho-migrator up\n/usr/local/bin/kacho-migrator\nCOPY --from=b /bin/kacho-migrator /usr/local/bin/kacho-migrator\n",
			wantToken:  "kacho-migrator",
			wantLine:   1,
			wantSeen:   4,
			wantJudged: 4,
		},
		{
			// Голое слово продуктом не названо: судить его значило бы требовать
			// имени там, где о продукте речи нет.
			name:     "голое слово — встречено, не судится",
			body:     "инструмент migrator накатывает схему\n",
			wantSeen: 1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, census := MigratorShowcaseScan(
				map[string]string{"INSTALL.md": tc.body}, injProducts, injOwn)

			require.Equal(t, tc.wantSeen, census.TokensSeen,
				"токенов встречено %d, ожидалось %d — перепись обязана быть верна и там, где "+
					"находок нет: без неё «ноль находок» неотличимо от «ноль прочитанного»",
				census.TokensSeen, tc.wantSeen)
			require.Equal(t, tc.wantJudged, census.TokensJudged,
				"признано именем накатчика продукта %d, ожидалось %d", census.TokensJudged, tc.wantJudged)
			require.Equal(t, tc.wantOwn, census.TokensOwn,
				"своих насчитано %d, ожидалось %d — величина «судимых» без величины «своих» "+
					"скрывает ровно тот случай, ради которого гейт заведён",
				census.TokensOwn, tc.wantOwn)
			require.Equal(t, tc.wantDiacr, census.TokensDiacritic,
				"диакритической формой %d, ожидалось %d", census.TokensDiacritic, tc.wantDiacr)

			if tc.wantToken == "" {
				require.Empty(t, f, "законный вход объявлен находкой: %v — гейт судит форму, "+
					"а не существо", f)
				return
			}
			require.NotEmpty(t, f, "дефект внесён, а гейт молчит — он не способен упасть "+
				"по этой оси")
			require.Equal(t, tc.wantToken, f[0].Token, "назван не тот токен")
			require.Equal(t, tc.wantLine, f[0].Line, "находка обязана называть координату: "+
				"без неё читатель идёт искать сам")
			require.Contains(t, f[0].String(), "INSTALL.md:", "координата не напечатана")
			require.Contains(t, f[0].String(), injOwn, "находка обязана называть ЗАКОННОЕ имя, "+
				"иначе она говорит, что неверно, и не говорит, что верно")
		})
	}
}

// TestMigratorShowcaseExemption_InjectionBothWays — ИЗЪЯТИЕ: проба и запись
// ведомости изымаются, обычный файл витрины — нет.
func TestMigratorShowcaseExemption_InjectionBothWays(t *testing.T) {
	cases := []struct {
		rel  string
		want bool
	}{
		{"internal/supplyhygiene/migrator_showcase_name_injection_test.go", true},
		{"cmd/migrator/main_test.go", true},
		{"docs/engineering/acceptance/roles-come-as-data-not-migrations.md", true},
		// Витрина в чистом виде: изыми её — и гейт перестанет судить то, ради
		// чего заведён.
		{"INSTALL.md", false},
		{"deploy/helm/kaname/templates/deployment.yaml", false},
		{"cmd/migrator/main.go", false},
	}
	for _, tc := range cases {
		reason, got := migratorShowcaseExemptReason(tc.rel)
		require.Equal(t, tc.want, got, "%s: изъятие %v, ожидалось %v", tc.rel, got, tc.want)
		if got {
			require.NotEmpty(t, strings.TrimSpace(reason),
				"%s: изъятие без ПРИЧИНЫ — послабление, за которое никто не отвечает", tc.rel)
		}
	}
}

// TestMigratorShowcaseLedgerSelfExpiry_InjectionBothWays — САМОИСТЕЧЕНИЕ:
// записи, которой нечего изымать, быть не должно.
//
// Проверяется тем же вызовом, каким её проверяет гейт: файл без чужого токена
// обязан давать ноль находок, то есть запись о нём — находкой ведомости.
func TestMigratorShowcaseLedgerSelfExpiry_InjectionBothWays(t *testing.T) {
	withForeign := "см. бинарь kacho-migrator\n"
	withoutForeign := "см. бинарь kaname-migrator\n"

	f, _ := MigratorShowcaseScan(map[string]string{"x.md": withForeign}, injProducts, injOwn)
	require.NotEmpty(t, f, "предпосылка: файл с чужим токеном обязан давать находку — "+
		"иначе самоистечение ведомости проверялось бы предикатом, который всегда молчит")

	f, _ = MigratorShowcaseScan(map[string]string{"x.md": withoutForeign}, injProducts, injOwn)
	require.Empty(t, f, "файлу без чужого токена изымать нечего: запись ведомости о нём "+
		"пережила бы свой предмет и молча простила СЛЕДУЮЩУЮ находку в этом файле")
}

// --- #17: премиса пустого обхода доказана ИСПОЛНЕНИЕМ ------------------------

// TestMigratorShowcaseCorpus_EmptyTraversalIsRefused — обход витрины отказывает,
// когда витрины нет, и берёт её, когда она есть.
//
// Дерево строится `SyntheticTree`: временный каталог репозиторием не является,
// индекса у него нет вовсе. Конструктор выбран ЯВНО — молчаливый откат «нет git,
// иду по диску» внутри общего читал бы на боевом прогоне игнорируемые каталоги.
func TestMigratorShowcaseCorpus_EmptyTraversalIsRefused(t *testing.T) {
	t.Parallel()

	build := func(files map[string]string) *treecorpus.Tree {
		t.Helper()
		root := t.TempDir()
		for rel, body := range files {
			p := filepath.Join(root, filepath.FromSlash(rel))
			require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o750), "фикстура не собрана")
			require.NoError(t, os.WriteFile(p, []byte(body), 0o600), "фикстура не собрана")
		}
		tree, err := treecorpus.SyntheticTree(root)
		require.NoError(t, err, "фикстура не собрана")
		return tree
	}

	// ── КОНТРОЛЬ: витрина есть — обход её БЕРЁТ ─────────────────────────────
	//
	// Без него отказ ниже доказывал бы лишь то, что обход не берёт ничего
	// никогда: слепая витрина прошла бы эту пробу насквозь.
	corpus, err := migratorShowcaseCorpus(build(map[string]string{
		"deploy/values.yaml": "image: kaname-migrator\n",
		"internal/x_test.go": "package x\n",
	}))
	require.NoError(t, err, "КОНТРОЛЬ: на дереве С витриной обход объявлен пустым")
	require.Equal(t, []string{"deploy/values.yaml"}, corpus.Rels(),
		"КОНТРОЛЬ: изъятие по свойству (проба) обязано вычитать _test.go, иначе отказ "+
			"ниже значил бы не то")

	// ── ИНЪЕКЦИЯ: дерево НЕПУСТО, но всё изъято — ОТКАЗ ─────────────────────
	//
	// Дерево непустое намеренно: пустое ловится и грубым предикатом, а самый
	// частый вид слепоты другой — витрина ушла из-под отбора, а дерево на месте.
	_, err = migratorShowcaseCorpus(build(map[string]string{"internal/x_test.go": "package x\n"}))
	require.ErrorIs(t, err, check.ErrEmptyTraversal,
		"витрина изъята целиком, а обход отказа НЕ ДАЛ — «находок ноль» стало бы неотличимо "+
			"от «прочитано ноль»")

	// ── ИНЪЕКЦИЯ: дерево ПУСТО — тот же отказ ──────────────────────────────
	_, err = migratorShowcaseCorpus(build(nil))
	require.ErrorIs(t, err, check.ErrEmptyTraversal, "пустое дерево прочиталось без отказа")

	t.Log("осей 3: контроль · витрина изъята целиком · дерево пусто")
}
