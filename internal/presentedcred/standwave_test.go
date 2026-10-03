// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Пакет внутренний (а не presentedcred_test, как соседи): предмет пробы —
// неэкспортированная константа keySetTTL, и экспортировать её ради стенда
// значило бы расширить поверхность пакета под нужды проверки.
package presentedcred

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"
)

// standScript — сценарий автономного стенда, чья волна свёртки базы меряет
// тишину и окно сроком снимка набора ключей (kaname#558).
var standScript = filepath.Join("..", "..", ".github", "scripts", "stand-own.sh")

var standKeySetTTLLine = regexp.MustCompile(`(?m)^KEY_SET_TTL=(\S+)$`)

// standKeySetTTL — срок снимка, объявленный сценарием стенда. Строка обязана
// быть ровно одна: две дали бы волне значение, выбранное порядком чтения.
func standKeySetTTL(script []byte) (time.Duration, error) {
	m := standKeySetTTLLine.FindAllSubmatch(script, -1)
	if len(m) != 1 {
		return 0, fmt.Errorf("строк KEY_SET_TTL=… в сценарии стенда %d, ожидается ровно одна", len(m))
	}
	d, err := time.ParseDuration(string(m[0][1]))
	if err != nil {
		return 0, fmt.Errorf("KEY_SET_TTL=%s не разбирается длительностью: %w", m[0][1], err)
	}
	return d, nil
}

// mirrorsReader — находка, если объявленное стендом расходится с читателем.
func mirrorsReader(script []byte, want time.Duration) error {
	got, err := standKeySetTTL(script)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("стенд объявляет срок снимка %s, читатель держит %s — тишина волны "+
			"свёртки базы не покрывает снимок, и прогрев снова может оказаться попаданием", got, want)
	}
	return nil
}

// TestStandKeySetTTLMirrorsTheReader — волна свёртки базы автономного стенда
// (`stand-own.sh failclosed-prepare` и `failclosed-judge`) отмеряет тишину и
// окно сроком снимка набора ключей. Ручки у срока нет, поэтому стенд держит его отражение, и эта проба
// не даёт отражению разойтись с константой читателя.
func TestStandKeySetTTLMirrorsTheReader(t *testing.T) {
	script, err := os.ReadFile(standScript)
	if err != nil {
		t.Fatalf("сценарий стенда не прочитан (%s): %v — предпосылка пробы не выполнена", standScript, err)
	}
	if err := mirrorsReader(script, keySetTTL); err != nil {
		t.Fatal(err)
	}
}

// TestStandKeySetTTLMirrorInjection — проба выше способна упасть: каждая
// инъекция меняет один факт синтетического сценария, законный близнец молчит.
func TestStandKeySetTTLMirrorInjection(t *testing.T) {
	cases := []struct {
		name   string
		script string
		red    bool
	}{
		{"законный близнец: то же значение", "x=1\nKEY_SET_TTL=30s\n", false},
		{"законный близнец: та же длительность иной записью", "KEY_SET_TTL=0m30s\n", false},
		{"значение разошлось", "KEY_SET_TTL=20s\n", true},
		{"строки нет", "REVOCATION_CACHE_TTL=30s\n", true},
		{"строка внутри комментария не считается", "# KEY_SET_TTL=30s\n", true},
		{"строк две", "KEY_SET_TTL=30s\nKEY_SET_TTL=30s\n", true},
		{"не длительность", "KEY_SET_TTL=30sec\n", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := mirrorsReader([]byte(c.script), 30*time.Second)
			if c.red && err == nil {
				t.Fatalf("инъекция «%s» не обнаружена", c.name)
			}
			if !c.red && err != nil {
				t.Fatalf("законный близнец отвергнут: %v", err)
			}
		})
	}
}
