// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// keyset_paths_named_by_profiles_test.go — КОММЕНТАРИИ ПРОФИЛЕЙ И ЖУРНАЛ
// НАЗЫВАЮТ ОДИН НАБОР ОБСЛУЖИВАЕМЫХ ПУТЕЙ НАБОРА КЛЮЧЕЙ (kaname#808).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Журнал (`CHANGELOG.md`) говорит: запись зеркала прежнего издателя снята,
// канонический путь `/.well-known/jwks.json` слушатель больше не отдаёт, а
// обмен у прежнего издателя снят вместе с его ручками. Профили чарта говорили
// обратное: путь нашей записи обосновывался тем, что по каноническому «тот же
// слушатель отдаёт зеркало прежнего издателя», слушатель назывался зеркалом, а
// карта `env` — местом «адреса контура обмена у поставщика (`Resolve*`)».
// Проверяющий токены, настроенный по такому комментарию, шёл на путь, которого
// нет.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО СУДИТСЯ
//
//	журнал    снятый путь и путь нашей записи ВЫВОДЯТСЯ из записи журнала, а не
//	          выписаны здесь: выписанные разошлись бы с журналом молча;
//	исход     маршрутизатор публикатора, собранный из пути профиля, отдаёт
//	          запись по пути профиля и 404 — по снятому пути;
//	профиль   блок комментария над `keySetPath` называет снятый путь и его
//	          исход (404); ни одна строка комментария не называет слушатель
//	          зеркалом и не обещает контур обмена, если та же строка не
//	          говорит, что это снято.
//
// Отрицание стоит в паре с положительным: блок над `keySetPath` обязан
// существовать и называть оба пути — иначе молчание о зеркале было бы зелёным
// и на профиле без единого комментария.
package deploy_test

import (
	"bufio"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/PRO-Robotech/kaname/internal/handler/jwksproxyhttp"
)

// keySetJournalHeading — заголовок записи журнала о снятии зеркала.
const keySetJournalHeading = "### Слушатель наборов ключей публикует одну запись — свою"

// exchangeJournalHeading — заголовок записи журнала о снятии обмена у
// прежнего издателя.
const exchangeJournalHeading = "### Докерный контур выдаёт только своей чеканкой — дорога к прежнему издателю снята"

// journalSection — текст записи журнала от заголовка до следующего заголовка
// того же уровня.
func journalSection(t *testing.T, journal, heading string) string {
	t.Helper()
	i := strings.Index(journal, heading+"\n")
	if i < 0 {
		t.Fatalf("в CHANGELOG.md нет записи %q — сверять профили не с чем", heading)
	}
	rest := journal[i+len(heading)+1:]
	if j := strings.Index(rest, "\n### "); j >= 0 {
		rest = rest[:j]
	}
	return rest
}

// journalKeySetPaths выводит из записи журнала снятый путь и путь нашей записи.
func journalKeySetPaths(t *testing.T) (retired, served string) {
	t.Helper()
	raw, err := os.ReadFile("../CHANGELOG.md")
	if err != nil {
		t.Fatalf("журнал не прочитан: %v", err)
	}
	journal := string(raw)
	sec := journalSection(t, journal, keySetJournalHeading)
	retiredRe := regexp.MustCompile("путь `(/[^`]+)` на\\s+внутреннем слушателе[^.]*больше не обслуживается")
	m := retiredRe.FindStringSubmatch(sec)
	if m == nil {
		t.Fatalf("запись журнала %q не называет снятый путь формой «путь `…` … больше не обслуживается»", keySetJournalHeading)
	}
	servedRe := regexp.MustCompile("умолчание `(/[^`]+)`")
	s := servedRe.FindStringSubmatch(sec)
	if s == nil {
		t.Fatalf("запись журнала %q не называет путь нашей записи («умолчание `…`»)", keySetJournalHeading)
	}
	// Предпосылка второй оси: обмен у прежнего издателя журнал объявляет снятым.
	ex := journalSection(t, journal, exchangeJournalHeading)
	if !strings.Contains(ex, "Снята последняя дорога службы к внешнему поставщику") {
		t.Fatalf("запись журнала %q не объявляет обмен снятым — ось обмена судить не по чему", exchangeJournalHeading)
	}
	return m[1], s[1]
}

// profileKeySetPath — величина `authn.tokenSigning.keySetPath` профиля.
func profileKeySetPath(t *testing.T, file string) string {
	t.Helper()
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("%s не прочитан: %v", file, err)
	}
	var doc struct {
		AuthN struct {
			TokenSigning struct {
				KeySetPath string `yaml:"keySetPath"`
			} `yaml:"tokenSigning"`
		} `yaml:"authn"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("%s не разобран: %v", file, err)
	}
	return doc.AuthN.TokenSigning.KeySetPath
}

// profileComments — строки комментария профиля с номерами и блок комментария
// непосредственно над ключом `keySetPath:`.
func profileComments(t *testing.T, file string) (lines map[int]string, keySetBlock string) {
	t.Helper()
	f, err := os.Open(file)
	if err != nil {
		t.Fatalf("%s не открыт: %v", file, err)
	}
	defer f.Close()
	lines = map[int]string{}
	var block []string
	n := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		n++
		trimmed := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(trimmed, "#") {
			lines[n] = trimmed
			block = append(block, trimmed)
			continue
		}
		if strings.HasPrefix(trimmed, "keySetPath:") && keySetBlock == "" {
			keySetBlock = strings.Join(block, "\n")
		}
		block = nil
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("%s не дочитан: %v", file, err)
	}
	return lines, keySetBlock
}

// retiredClaims — подстроки, которыми комментарий обещает снятое. Строка, в
// которой есть и «снят», говорит о снятии, а не обещает.
var retiredClaims = []string{"зеркал", "контур обмена", "контура обмена", "`resolve*`"}

func TestProfileCommentsNameTheKeySetPathsTheListenerServes(t *testing.T) {
	retired, served := journalKeySetPaths(t)

	for _, file := range []string{"values.yaml", "values.prod.yaml"} {
		t.Run(file, func(t *testing.T) {
			path := profileKeySetPath(t, file)
			if path == "" {
				t.Fatalf("%s не объявляет authn.tokenSigning.keySetPath — судить нечего", file)
			}
			if path != served {
				t.Errorf("%s: keySetPath=%q, а журнал называет путь нашей записи %q", file, path, served)
			}

			// Исход: маршрутизатор публикатора из пути профиля.
			b, err := jwksproxyhttp.NewBinding([]jwksproxyhttp.Record{{
				Issuer: "https://access.example.invalid", Path: path,
				Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }),
			}})
			if err != nil {
				t.Fatalf("привязка из пути профиля не строится: %v", err)
			}
			mux, err := jwksproxyhttp.NewMux(b)
			if err != nil {
				t.Fatalf("маршрутизатор публикатора не строится: %v", err)
			}
			for _, c := range []struct {
				p    string
				want int
			}{{path, http.StatusOK}, {retired, http.StatusNotFound}} {
				rec := httptest.NewRecorder()
				mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, c.p, nil))
				if rec.Code != c.want {
					t.Errorf("GET %s на публикаторе: %d, ожидался %d", c.p, rec.Code, c.want)
				}
			}

			lines, block := profileComments(t, file)
			t.Logf("%s: строк комментария %d, блок над keySetPath — %d строк", file, len(lines), strings.Count(block, "\n")+1)
			if len(lines) == 0 {
				t.Fatalf("%s: ни одной строки комментария прочитано — проба слепа", file)
			}
			if !strings.Contains(block, retired) || !strings.Contains(block, "404") {
				t.Errorf("%s: блок комментария над keySetPath не называет снятый путь %s и его исход 404:\n%s", file, retired, block)
			}
			for n, l := range lines {
				low := strings.ToLower(l)
				if strings.Contains(low, "снят") {
					continue
				}
				for _, claim := range retiredClaims {
					if strings.Contains(low, claim) {
						t.Errorf("%s:%d обещает снятое (%q), а журнал объявляет его снятым: %s", file, n, claim, l)
					}
				}
			}
		})
	}
}
