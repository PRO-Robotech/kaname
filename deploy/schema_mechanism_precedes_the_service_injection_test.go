// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// schema_mechanism_precedes_the_service_injection_test.go — доказательство того,
// что соседняя проба СПОСОБНА упасть, и падает ровно на своём предмете.
//
// ПОЧЕМУ ЭТО ОТДЕЛЬНАЯ ПРОБА. Зелёное на целом дереве не говорит о проверке
// ничего: проверка, потерявшая способность краснеть, на целом дереве выглядит
// точно так же. Единственное, что различает две эти вещи, — внесённый дефект.
//
// ФОРМА ДОКАЗАТЕЛЬСТВА. Вход берётся НАСТОЯЩИЙ — чарт и Dockerfile iam
// копируются во временный каталог, — и каждый случай меняет против целой копии
// РОВНО ОДИН факт. Меняющий два не доказывает ничего: неизвестно, который из них
// дал красное.
//
// КОНТРОЛЬ В ОБРАТНУЮ СТОРОНУ ОБЯЗАТЕЛЕН. Отрицание, у которого нет
// положительного близнеца, зеленеет на всём сломанном и краснеет на всём
// исправном одинаково незаметно. Поэтому здесь есть случаи, где проба обязана
// МОЛЧАТЬ: целая копия, посторонний init-контейнер рядом с накатом, и та же
// ручка со включающим умолчанием.
package deploy_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// injectionCase — один случай: что изменено против целой копии и чего ждём.
type injectionCase struct {
	name string
	// mutate меняет РОВНО ОДИН факт во временной копии.
	mutate func(t *testing.T, root string)
	// wantSubstring — по какому признаку узнаём находку. Пусто — ждём молчания.
	wantSubstring string
}

// copyChartFixture кладёт во временный каталог настоящий чарт iam и его
// Dockerfile. Настоящий, а не синтетический: проверка, доказанная на выдуманном
// входе, доказывает работу на выдуманном входе.
func copyChartFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	src := filepath.Join("..", "..", "..", "services", "iam")
	dst := filepath.Join(root, "services", "iam")

	for _, rel := range []string{
		"Dockerfile",
		"deploy/values.yaml",
		"deploy/templates/deployment.yaml",
	} {
		raw, err := os.ReadFile(filepath.Join(src, rel))
		if err != nil {
			t.Fatalf("фикстура не собрана, %s не прочитан: %v", rel, err)
		}
		out := filepath.Join(dst, rel)
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			t.Fatalf("фикстура не собрана: %v", err)
		}
		if err := os.WriteFile(out, raw, 0o644); err != nil {
			t.Fatalf("фикстура не собрана: %v", err)
		}
	}
	return root
}

func fixturePath(root, rel string) string {
	return filepath.Join(root, "services", "iam", rel)
}

func readFixture(t *testing.T, root, rel string) string {
	t.Helper()
	raw, err := os.ReadFile(fixturePath(root, rel))
	if err != nil {
		t.Fatalf("%s не прочитан: %v", rel, err)
	}
	return string(raw)
}

func writeFixture(t *testing.T, root, rel, body string) {
	t.Helper()
	if err := os.WriteFile(fixturePath(root, rel), []byte(body), 0o644); err != nil {
		t.Fatalf("%s не записан: %v", rel, err)
	}
}

// replaceOnce меняет первое вхождение и ОТКАЗЫВАЕТ, если его нет. Молчаливая
// замена нуля вхождений дала бы случай, который ничего не внёс, — и его зелёное
// читалось бы как доказательство.
func replaceOnce(t *testing.T, body, old, new string) string {
	t.Helper()
	if !strings.Contains(body, old) {
		t.Fatalf("инъекция беспредметна: во входе нет %q", old)
	}
	return strings.Replace(body, old, new, 1)
}

const (
	migratorCommandLine = `          command: ["/usr/local/bin/kacho-migrator", "up"]`
	serviceCommandLine  = `          command: ["/usr/local/bin/kacho-iam", "serve"]`
	initImageLine       = `          image: "{{ .Values.image }}"`
	dockerfileCopyLine  = `COPY --from=builder /kacho-migrator /usr/local/bin/kacho-migrator`
)

func TestSchemaMechanismInjection(t *testing.T) {
	cases := []injectionCase{
		{
			// Положительный контроль. Без него все отрицания ниже зеленели бы
			// на входе, который проба вообще не читает.
			name:          "целая копия — молчание",
			mutate:        func(*testing.T, string) {},
			wantSubstring: "",
		},
		{
			// Несущий случай: снят ИСПОЛНЯЕМЫЙ вызов, а комментарий, называющий
			// тот же binary, оставлен на месте. Проверка по подстроке осталась бы
			// здесь зелёной — то есть удостоверяла бы прозу вместо механизма.
			name: "накат снят, комментарий о нём оставлен",
			mutate: func(t *testing.T, root string) {
				b := readFixture(t, root, "deploy/templates/deployment.yaml")
				b = replaceOnce(t, b, migratorCommandLine+"\n", "")
				writeFixture(t, root, "deploy/templates/deployment.yaml", b)
			},
			wantSubstring: "ни один init-контейнер не зовёт",
		},
		{
			name: "накат переехал в служебные контейнеры — порядок потерян",
			mutate: func(t *testing.T, root string) {
				b := readFixture(t, root, "deploy/templates/deployment.yaml")
				b = replaceOnce(t, b, serviceCommandLine, migratorCommandLine)
				writeFixture(t, root, "deploy/templates/deployment.yaml", b)
			},
			wantSubstring: "объявлен среди containers",
		},
		{
			name: "образ наката прибит литералом",
			mutate: func(t *testing.T, root string) {
				b := readFixture(t, root, "deploy/templates/deployment.yaml")
				b = replaceOnce(t, b, initImageLine, `          image: "postgres:16"`)
				writeFixture(t, root, "deploy/templates/deployment.yaml", b)
			},
			wantSubstring: "образ наката задан литералом",
		},
		{
			name: "образ по названному пути ничего не кладёт",
			mutate: func(t *testing.T, root string) {
				b := readFixture(t, root, "Dockerfile")
				b = replaceOnce(t, b, dockerfileCopyLine, dockerfileCopyLine+"-renamed")
				writeFixture(t, root, "Dockerfile", b)
			},
			wantSubstring: "неисполнимая возможность",
		},
		{
			// Законный близнец той же формы: посторонний init-контейнер с прибитым
			// образом стоит рядом с накатом. Проба судит контейнер НАКАТА, а не
			// всякий init-контейнер, — иначе первый же законный сосед сделал бы её
			// источником ложных находок, и её отключили бы.
			name: "посторонний init-контейнер рядом — молчание",
			mutate: func(t *testing.T, root string) {
				b := readFixture(t, root, "deploy/templates/deployment.yaml")
				b = replaceOnce(t, b, "      initContainers:\n",
					"      initContainers:\n"+
						"        - name: wait-for-db\n"+
						"          image: \"busybox:1.36\"\n"+
						"          command: [\"/bin/sh\", \"-c\", \"sleep 1\"]\n")
				writeFixture(t, root, "deploy/templates/deployment.yaml", b)
			},
			wantSubstring: "",
		},
		{
			// Ручка с ВКЛЮЧАЮЩИМ умолчанием — законна и обязана молчать.
			name: "механизм обёрнут ручкой, умолчание true — молчание",
			mutate: func(t *testing.T, root string) {
				b := readFixture(t, root, "deploy/templates/deployment.yaml")
				b = replaceOnce(t, b, "      initContainers:\n",
					"      {{- if .Values.migrator.enabled }}\n      initContainers:\n")
				writeFixture(t, root, "deploy/templates/deployment.yaml", b)
				v := readFixture(t, root, "deploy/values.yaml")
				writeFixture(t, root, "deploy/values.yaml", v+"\nmigrator:\n  enabled: true\n")
			},
			wantSubstring: "",
		},
		{
			// Тот же вход, изменён РОВНО ОДИН факт против случая выше — умолчание
			// ручки. Установка с умолчаниями перестаёт создавать схему.
			name: "та же ручка, умолчание false — находка",
			mutate: func(t *testing.T, root string) {
				b := readFixture(t, root, "deploy/templates/deployment.yaml")
				b = replaceOnce(t, b, "      initContainers:\n",
					"      {{- if .Values.migrator.enabled }}\n      initContainers:\n")
				writeFixture(t, root, "deploy/templates/deployment.yaml", b)
				v := readFixture(t, root, "deploy/values.yaml")
				writeFixture(t, root, "deploy/values.yaml", v+"\nmigrator:\n  enabled: false\n")
			},
			wantSubstring: "не умалчивает true",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := copyChartFixture(t)
			tc.mutate(t, root)

			audits, findings, err := auditSchemaMechanism(root)
			if err != nil {
				t.Fatalf("обход не состоялся: %v", err)
			}
			// Предпосылка каждого случая: обход что-то прочитал. Инъекция над
			// пустым обходом доказывала бы молчание отсутствием предмета.
			if len(audits) != 1 {
				t.Fatalf("осмотрено чартов %d, ожидался 1 — фикстура не собрана", len(audits))
			}

			joined := make([]string, 0, len(findings))
			for _, f := range findings {
				joined = append(joined, f.String())
			}
			all := strings.Join(joined, "\n")

			if tc.wantSubstring == "" {
				if len(findings) != 0 {
					t.Fatalf("ожидалось молчание, получено находок %d:\n%s", len(findings), all)
				}
				t.Logf("молчание подтверждено: осмотрено 1 чарт, находок 0")
				return
			}
			if len(findings) == 0 {
				t.Fatalf("ожидалась находка по признаку %q — проба смолчала на внесённом дефекте", tc.wantSubstring)
			}
			if !strings.Contains(all, tc.wantSubstring) {
				t.Fatalf("находка есть, но не та: ждали %q, получили:\n%s", tc.wantSubstring, all)
			}
			// Координата обязательна: находка без места посылает читателя искать
			// не там.
			if !strings.Contains(all, "deployment.yaml") && !strings.Contains(all, "Dockerfile") {
				t.Fatalf("находка не называет координату:\n%s", all)
			}
			t.Logf("находка подтверждена: %s", all)
		})
	}
}

// TestSchemaMechanismEmptyTraversalIsNotGreen — обход, которому нечего читать,
// обязан быть отличим от обхода без находок.
func TestSchemaMechanismEmptyTraversalIsNotGreen(t *testing.T) {
	audits, findings, err := auditSchemaMechanism(t.TempDir())
	if err != nil {
		t.Fatalf("обход не состоялся: %v", err)
	}
	if len(audits) != 0 || len(findings) != 0 {
		t.Fatalf("на пустом корне ожидались нули, получено чартов %d, находок %d", len(audits), len(findings))
	}
	t.Logf("подтверждено: пустой корень даёт 0 осмотренных — сама проба на таком обходе падает (см. соседний Fatalf)")
}
