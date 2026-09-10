// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// own_ceilings_apply_wiring_injection_test.go — ДОКАЗАТЕЛЬСТВО, что гейт провязки
// СПОСОБЕН упасть, и падает ровно на своём предмете.
//
// Гейт, потерявший способность краснеть, на верном дереве выглядит В ТОЧНОСТИ так
// же, как исправный. Поэтому инъекция идёт по КАЖДОЙ оси отдельно, и рядом с ней
// стоит законный близнец: без него всякое красное могло бы приходить от самого
// разбора, а не от внесённого дефекта.
//
// Инъекция роняет ТОЛЬКО проверяемое: каждая фикстура снимает у верного корня
// РОВНО ОДИН факт. Форма «завести ещё один вызов» здесь не годилась бы — новый
// вызов нарушает всё, что требуется от вызовов вообще.

import (
	"os"
	"path/filepath"
	"testing"
)

// synthRoot — синтетический композиционный корень: минимальный, но с обеими
// координатами, которые судит гейт.
const synthRoot = `package main

func runServe() error {
	if err := assertConnBudgetFits(); err != nil {
		return err
	}
	if err := projectOwnCeilings(ctx, logger, repo, cfg.OwnCeilings); err != nil {
		return err
	}
	listener, err := net.Listen("tcp", addr)
	_ = listener
	return err
}
`

// writeSynthRoot кладёт синтетический корень в свой каталог и возвращает путь.
func writeSynthRoot(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "serve.go")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("синтетический корень не записан: %v", err)
	}
	return path
}

// TestKANQ25_WiringGateCanFailAndStaysSilent — три прогона, а не два.
func TestKANQ25_WiringGateCanFailAndStaysSilent(t *testing.T) {
	t.Run("законный близнец: верный корень", func(t *testing.T) {
		a := ownCeilingWiring(t, writeSynthRoot(t, synthRoot))
		if a.CallsSeen == 0 {
			t.Fatal("разбор синтетического корня не нашёл ни одного вызова — " +
				"инъекции ниже краснели бы от самого разбора, а не от дефекта")
		}
		if !a.Project.IsValid() {
			t.Error("на ВЕРНОМ корне гейт не нашёл проекции — первое же ложное " +
				"срабатывание снимает гейт целиком")
		}
		if !a.FirstListener.IsValid() {
			t.Error("на ВЕРНОМ корне гейт не нашёл открытия порта — предпосылка " +
				"проверки о порядке недостижима, и порядок судить нечем")
		}
		if a.Project > a.FirstListener {
			t.Error("на ВЕРНОМ корне гейт объявил неверный порядок")
		}
	})

	t.Run("инъекция: проекция не позвана", func(t *testing.T) {
		body := replaceOnce(t, synthRoot,
			"\tif err := projectOwnCeilings(ctx, logger, repo, cfg.OwnCeilings); err != nil {\n\t\treturn err\n\t}\n", "")
		a := ownCeilingWiring(t, writeSynthRoot(t, body))
		if a.Project.IsValid() {
			t.Error("гейт НАШЁЛ проекцию там, где её вызов снят — он не заметил бы " +
				"пустой проекции, при которой служба поднимается и отвергает каждое " +
				"создание аккаунта")
		}
		if !a.FirstListener.IsValid() {
			t.Error("инъекция уронила заодно вторую координату: значит красное могло " +
				"прийти не от проверяемого факта")
		}
	})

	t.Run("инъекция: проекция ПОСЛЕ открытия порта", func(t *testing.T) {
		body := `package main

func runServe() error {
	listener, err := net.Listen("tcp", addr)
	_ = listener
	if err := projectOwnCeilings(ctx, logger, repo, cfg.OwnCeilings); err != nil {
		return err
	}
	return err
}
`
		a := ownCeilingWiring(t, writeSynthRoot(t, body))
		if !a.Project.IsValid() || !a.FirstListener.IsValid() {
			t.Fatal("инъекция сняла координату вместо перестановки — она роняет не то, " +
				"что проверяет")
		}
		if a.Project < a.FirstListener {
			t.Error("гейт объявил порядок верным при проекции ПОСЛЕ открытия порта: " +
				"окно, в котором действует величина предыдущего пуска, он не заметит")
		}
	})
}

// replaceOnce — одно-фактная правка синтетического корня.
func replaceOnce(t *testing.T, body, old, new string) string {
	t.Helper()
	i := indexOf(body, old)
	if i < 0 {
		t.Fatalf("инъекция не нашла своего предмета в синтетическом корне — фикстура " +
			"пережила то, что ею вносилось")
	}
	return body[:i] + new + body[i+len(old):]
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
