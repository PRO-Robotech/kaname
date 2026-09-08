// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// challengebinding_test.go — подсказка аутентификации объявлена ОДИН раз, и
// сквозная проба утверждает ЕЁ, а не свою копию (задача продукта #2188, находка
// по дороге #2319).
//
// # Предмет
//
// Значение подсказки живёт теперь в трёх местах: константа этого пакета —
// ПРОИЗВОДИТЕЛЬ; кейс сквозного набора, который её утверждает; фикстура гейта
// вакуума, которая её моделирует. Импортировать Go-константу ни из кейса, ни из
// фикстуры нечем — обе на Python, — поэтому расхождение не удержать ни одной
// строкой прозы: оно наступит молча, и молча же обесценит утверждение.
//
// Здесь оно держится с той стороны, с которой держится: ИСКОМОЕ СТРОИТСЯ ИЗ
// КОНСТАНТЫ. Сменил производитель значение — игла перестала находиться, и проба
// краснеет, называя обе величины.
//
// # Почему читается ПОРОЖДЁННАЯ коллекция, а не модуль кейса
//
// Исполняется на стенде именно она. Кейс мог бы объявлять константу и не
// доводить её до утверждения — тогда проверка модуля зеленела бы на объявлении,
// которого никто не читает. Порождённый JavaScript такой лазейки не оставляет.
//
// # Чем это отличается от `challenge_test.go`
//
// Тот отвечает на вопрос «верна ли обёртка» и подаёт ей синтетический
// обработчик. Этот — на вопрос «утверждает ли кто-нибудь ту же величину там, где
// проверяется поднятый фронт». Ни один не заменяет другого.
package restfront

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// probeCollection — порождённая коллекция набора собственных фронтов.
const probeCollection = "../../tests/newman/collections/kaname-own-rest-front.postman_collection.json"

// vacuumFixture — фикстура гейта вакуума: она моделирует ответы стенда, и
// заголовок в ней обязан совпадать с тем, что ставит производитель.
const vacuumFixture = "../../tests/newman/scripts/own_front_vacuum_control_test.py"

// collectionNode — узел коллекции. Папки несут `item`, шаги — `event`.
type collectionNode struct {
	Name  string           `json:"name"`
	Item  []collectionNode `json:"item"`
	Event []struct {
		Listen string `json:"listen"`
		Script struct {
			Exec []string `json:"exec"`
		} `json:"script"`
	} `json:"event"`
}

// probeScripts — тест-скрипты всех шагов коллекции, по имени шага.
func probeScripts(raw []byte) (map[string]string, error) {
	var root collectionNode
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, fmt.Errorf("коллекция не разбирается: %w", err)
	}
	out := map[string]string{}
	var walk func(nodes []collectionNode)
	walk = func(nodes []collectionNode) {
		for _, n := range nodes {
			if len(n.Item) > 0 {
				walk(n.Item)
				continue
			}
			for _, ev := range n.Event {
				if ev.Listen == "test" {
					out[n.Name] = strings.Join(ev.Script.Exec, "\n")
				}
			}
		}
	}
	walk(root.Item)
	return out, nil
}

// challengeBindingAudit — судящая функция. Возвращает перепись и находки.
//
// Искомое строится из аргументов, а не выписано: подмена значения обязана
// уводить иглу мимо, иначе проба сверяла бы сама с собой.
func challengeBindingAudit(scripts map[string]string, fixture, header, value string) (map[string]int, []string) {
	census := map[string]int{"скриптов прочитано": len(scripts)}
	findings := []string{}

	readsHeader := fmt.Sprintf("pm.response.headers.get('%s')", header)
	assertsValue := fmt.Sprintf(".to.eql('%s')", value)

	steps, asserting := 0, 0
	for _, src := range scripts {
		if !strings.Contains(src, readsHeader) {
			continue
		}
		steps++
		if strings.Contains(src, assertsValue) {
			asserting++
		}
	}
	census["шагов читают заголовок"] = steps
	census["из них утверждают величину"] = asserting

	if steps == 0 {
		findings = append(findings, fmt.Sprintf(
			"ни один шаг набора не читает %q: подсказку на развёрнутой посадке "+
				"не утверждает никто, и обёртка держится только модульной пробой "+
				"с синтетическим обработчиком", header))
	}
	if steps > 0 && asserting == 0 {
		findings = append(findings, fmt.Sprintf(
			"заголовок %q читается, но величина %q не утверждается ни одним шагом: "+
				"проба смотрит на наличие и не смотрит на то, ЧЕМ предлагается назваться",
			header, value))
	}
	if !strings.Contains(fixture, fmt.Sprintf("%q: %q", header, value)) {
		findings = append(findings, fmt.Sprintf(
			"фикстура гейта вакуума не моделирует %q: %q — мир, в котором утверждение "+
				"о подсказке обязано ПРОХОДИТЬ, её не производит, и утверждение упало бы "+
				"по чужому предмету", header, value))
	}
	return census, findings
}

// TestProbeAssertsTheChallengeThisPackageProduces — несущее утверждение.
func TestProbeAssertsTheChallengeThisPackageProduces(t *testing.T) {
	raw, err := os.ReadFile(filepath.Clean(probeCollection))
	if err != nil {
		t.Fatalf("порождённой коллекции нет (%s): вердикт беспредметен — %v", probeCollection, err)
	}
	fixture, err := os.ReadFile(filepath.Clean(vacuumFixture))
	if err != nil {
		t.Fatalf("фикстуры гейта вакуума нет (%s): вердикт беспредметен — %v", vacuumFixture, err)
	}
	scripts, err := probeScripts(raw)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(scripts) == 0 {
		t.Fatal("в коллекции ноль тест-скриптов: «ноль находок» было бы неотличимо от «ноль прочитанного»")
	}

	census, findings := challengeBindingAudit(scripts, string(fixture), challengeHeader, AuthenticationChallenge)
	t.Logf("перепись: скриптов %d · читают заголовок %d · утверждают величину %d",
		census["скриптов прочитано"], census["шагов читают заголовок"],
		census["из них утверждают величину"])
	for _, f := range findings {
		t.Errorf("%s", f)
	}
}

// TestChallengeBindingCanFail — доказательство способности упасть и смолчать.
//
// Инъекция меняет РОВНО ОДИН факт против законного близнеца; иначе «упало
// проверяемое» неотличимо от «упал сосед».
func TestChallengeBindingCanFail(t *testing.T) {
	good := map[string]string{
		"malformed-credential": "pm.expect(pm.response.headers.get('WWW-Authenticate'), 'x')" +
			".to.eql('Bearer');",
	}
	goodFixture := `CHALLENGE = {"WWW-Authenticate": "Bearer"}`

	t.Run("legitimate_twin_is_silent", func(t *testing.T) {
		census, findings := challengeBindingAudit(good, goodFixture, "WWW-Authenticate", "Bearer")
		if len(findings) != 0 {
			t.Fatalf("законный близнец дал находки: %v", findings)
		}
		if census["из них утверждают величину"] != 1 {
			t.Fatalf("перепись не увидела предмета: %v", census)
		}
	})

	t.Run("nobody_reads_the_header", func(t *testing.T) {
		_, findings := challengeBindingAudit(
			map[string]string{"malformed-credential": "pm.expect(1).to.eql(1);"},
			goodFixture, "WWW-Authenticate", "Bearer")
		if len(findings) == 0 {
			t.Fatal("шаг без чтения заголовка обязан быть находкой")
		}
	})

	t.Run("header_read_but_value_not_asserted", func(t *testing.T) {
		_, findings := challengeBindingAudit(
			map[string]string{"malformed-credential": "const h = pm.response.headers.get('WWW-Authenticate');"},
			goodFixture, "WWW-Authenticate", "Bearer")
		if len(findings) == 0 {
			t.Fatal("чтение без утверждения величины обязано быть находкой")
		}
	})

	t.Run("producer_changed_the_value", func(t *testing.T) {
		// Производитель сменил величину, потребители остались прежними — ровно
		// то расхождение, ради которого проба заведена.
		_, findings := challengeBindingAudit(good, goodFixture, "WWW-Authenticate", "Bearer realm=\"kaname\"")
		if len(findings) == 0 {
			t.Fatal("смена величины у производителя обязана быть находкой")
		}
	})

	t.Run("fixture_models_something_else", func(t *testing.T) {
		_, findings := challengeBindingAudit(good, `CHALLENGE = {"WWW-Authenticate": "Basic"}`,
			"WWW-Authenticate", "Bearer")
		if len(findings) == 0 {
			t.Fatal("фикстура, моделирующая другую величину, обязана быть находкой")
		}
	})
}
