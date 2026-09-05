// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// present_test.go — документы, без которых службу нельзя ни поставить, ни
// распространять, ЛЕЖАТ В ДЕРЕВЕ и ведут туда, куда обещают.
//
// # Что стережётся
//
// Снятие или переименование одного из пяти документов молча. Каждый из них —
// точка входа стороннего оператора: у него нет ни нашего репозитория целиком,
// ни нашего стенда, ни нас, и отсутствующий документ он обнаружит тем, что
// сделает неверно.
//
// # Чего гейт НЕ судит, и это граница, а не пропуск
//
// Он не судит, ПРАВДУ ли говорит проза: «понятно» и «полно» машинного предиката
// не имеют. Он судит наличие, непустоту, объявленный предмет и разрешимость
// ссылок между документами — то есть ровно то, что от прозы отделимо.
//
// Правдивость двух перечней при этом держится СОСЕДНИМИ гейтами и держится
// по-настоящему: перечень третьих сторон и перечень обязательных величин
// порождаются и сверяются (operatordocs_test.go), а таблица стража доказывается
// прогоном (пакет настройки, required_settings_test.go).
package operatordocs

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// operatorDoc — один документ и признак того, что он о своём предмете.
type operatorDoc struct {
	Name string
	// Subject — подстрока, без которой документ не о том. Выбрана так, чтобы
	// пережить правку прозы: это предмет, а не формулировка.
	Subject string
	Why     string
}

var operatorDocs = []operatorDoc{
	{InstallFile, "Обязательные величины",
		"без него оператор ставит службу вслепую и узнаёт перечень из текстов отказа, по одному за перезапуск"},
	{NoticesFile, "третьих сторонах",
		"перечень чужого в поставке: распространение чужого кода разрешает только его лицензия"},
	{"SECURITY.md", "Куда сообщать",
		"нашедшему уязвимость некуда сообщить, и он сообщит публично"},
	{"CHANGELOG.md", "Как читать",
		"оператор не может понять, что меняется между версиями и требует ли обновление действий"},
	{"MODEL-MANIFEST.md", "манифест",
		"модель доступов подаётся оператором, и форма подачи должна быть где-то названа"},
}

// linkRe — ссылка на соседний документ в теле разметки.
var linkRe = regexp.MustCompile(`\]\(([A-Za-z0-9._-]+\.md)\)`)

// auditPresence разбирает корень и ВОЗВРАЩАЕТ находки: разбор, обращающийся к
// `*testing.T`, инъекции не поддаётся — падение подставного корня уронило бы
// саму пробу способности падать.
func auditPresence(root string) (findings []string, read, links int) {
	if len(operatorDocs) == 0 {
		return []string{"перечень документов пуст — гейт судил бы о непрочитанном"}, 0, 0
	}
	for _, d := range operatorDocs {
		body, err := os.ReadFile(filepath.Join(root, d.Name))
		if err != nil {
			findings = append(findings, d.Name+" не прочитан: "+err.Error()+
				"\n    чем это стоит оператору: "+d.Why)
			continue
		}
		read++
		text := string(body)

		if len(strings.TrimSpace(text)) < 200 {
			findings = append(findings, d.Name+" почти пуст — заведённый и не написанный документ хуже "+
				"отсутствующего: он читается как «здесь уже всё сказано»")
		}
		if !strings.Contains(text, d.Subject) {
			findings = append(findings, d.Name+" не содержит "+strconv.Quote(d.Subject)+
				" — документ перестал быть о своём предмете.\n    чем это стоит оператору: "+d.Why)
		}

		// Ссылки между документами обязаны разрешаться: ссылка в никуда
		// отправляет читателя искать то, чего нет, — и он решает, что не туда
		// смотрит он, а не документ.
		for _, m := range linkRe.FindAllStringSubmatch(text, -1) {
			links++
			if _, err := os.Stat(filepath.Join(root, m[1])); err != nil {
				findings = append(findings, d.Name+" ссылается на "+m[1]+", которого в дереве нет")
			}
		}
	}
	if read == 0 {
		findings = append(findings, "обход пуст: не прочитано ни одного документа — "+
			"«находок 0» неотличимо от «прочитано 0»")
	}
	return findings, read, links
}

func TestOperatorDocs_ArePresentAndOnTheirSubject(t *testing.T) {
	findings, read, links := auditPresence(iamRoot)
	for _, f := range findings {
		t.Error(f)
	}
	if read == 0 {
		t.Fatal("обход пуст — гейт судил бы о непрочитанном")
	}
	t.Logf("перепись: документов объявлено %d · прочитано %d · ссылок между ними проверено %d · находок %d",
		len(operatorDocs), read, links, len(findings))
}

// ─────────────────────────────────────────────────────────────────────────────
// Доказательство способности упасть. Инъекция идёт по КОПИИ дерева: правка
// настоящего корня ради пробы оборвала бы соседнюю сессию, работающую в том же
// дереве.

func TestOperatorDocsPresence_CanFailAndStaysSilent(t *testing.T) {
	cases := []struct {
		name    string
		breakIt func(t *testing.T, root string)
		want    string
		why     string
	}{
		{
			name:    "законный близнец: полная копия дерева",
			breakIt: func(*testing.T, string) {},
			why:     "положительный контроль: без него всякое красное ниже могло бы приходить от самого разбора",
		},
		{
			name: "документ снят",
			breakIt: func(t *testing.T, root string) {
				if err := os.Remove(filepath.Join(root, "SECURITY.md")); err != nil {
					t.Fatal(err)
				}
			},
			want: "SECURITY.md не прочитан",
			why:  "нашедшему уязвимость некуда сообщить, и он сообщит публично",
		},
		{
			name: "документ выпотрошен до заголовка",
			breakIt: func(t *testing.T, root string) {
				if err := os.WriteFile(filepath.Join(root, "CHANGELOG.md"), []byte("# Изменения\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			want: "CHANGELOG.md почти пуст",
			why:  "пустой документ читается как «здесь уже всё сказано» — хуже отсутствующего",
		},
		{
			name: "документ перестал быть о своём предмете",
			breakIt: func(t *testing.T, root string) {
				body, err := os.ReadFile(filepath.Join(root, "SECURITY.md"))
				if err != nil {
					t.Fatal(err)
				}
				out := strings.ReplaceAll(string(body), "Куда сообщать", "Прочее")
				if err := os.WriteFile(filepath.Join(root, "SECURITY.md"), []byte(out), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			want: "не содержит",
			why:  "раздел о канале сообщения снят, а документ на вид цел",
		},
		{
			name: "ссылка ведёт в никуда",
			breakIt: func(t *testing.T, root string) {
				if err := os.Remove(filepath.Join(root, "MODEL-MANIFEST.md")); err != nil {
					t.Fatal(err)
				}
			},
			want: "ссылается на MODEL-MANIFEST.md",
			why: "снятый документ обязан краснить не только сам себя, но и всех, кто на него ссылается: " +
				"иначе читатель решит, что не туда смотрит он, а не документ",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := copyDocs(t)
			tc.breakIt(t, root)
			findings, read, _ := auditPresence(root)

			if tc.want == "" {
				if len(findings) != 0 {
					t.Fatalf("разбор нашёл на законной копии то, чего в ней нет — первое же ложное "+
						"срабатывание снимает гейт.\nнаходки:\n  %s", strings.Join(findings, "\n  "))
				}
				if read != len(operatorDocs) {
					t.Fatalf("прочитано %d документов из %d — копия неполна, и контроль ничего не доказывает",
						read, len(operatorDocs))
				}
				return
			}
			if len(findings) == 0 {
				t.Fatalf("разбор смолчал на инъекции — он НЕ способен упасть по этой оси.\n"+
					"что должно было ловиться: %s", tc.why)
			}
			named := false
			for _, f := range findings {
				if strings.Contains(f, tc.want) {
					named = true
					break
				}
			}
			if !named {
				t.Fatalf("находка есть, а КООРДИНАТЫ %q в ней нет — читатель пойдёт чинить не туда.\n"+
					"находки:\n  %s", tc.want, strings.Join(findings, "\n  "))
			}
		})
	}
}

// copyDocs делает копию пяти документов во временном каталоге.
func copyDocs(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, d := range operatorDocs {
		body, err := os.ReadFile(filepath.Join(iamRoot, d.Name))
		if err != nil {
			t.Fatalf("копия не собрана, %s не прочитан: %v", d.Name, err)
		}
		if err := os.WriteFile(filepath.Join(root, d.Name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}
