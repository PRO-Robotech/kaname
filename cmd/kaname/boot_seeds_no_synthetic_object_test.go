// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// boot_seeds_no_synthetic_object_test.go — СТАРТ НЕ ЗАВОДИТ СИНТЕТИЧЕСКИХ
// ОБЪЕКТОВ В БОЕВОМ ЗЕРКАЛЕ (#119).
//
// # Что наблюдалось
//
// Загрузочная дымовая проба прямого пути заводила внутри настоящего аккаунта
// объект ЧУЖОГО домена, сводила его, проверяла ведомость и снимала строку
// зеркала — но не строки ведомости, которые сама и вызвала. Следующий отчёт
// честно находил материализованное чтение на объекте, которого больше нет, и
// печатал на исправной установке отказ о СОБСТВЕННОЙ синтетике.
//
// # Почему гейт по КОМПОЗИЦИОННОМУ КОРНЮ, а не проба поведения
//
// Свойство здесь отрицательное: «старт этого НЕ делает». Проба поведения на
// снятом механизме молчит тождественно — она зелена и тогда, когда механизм
// вернут под другим именем, если только не знать имени заранее. Гейт же судит
// СОСТАВ композиционного корня и краснеет на возвращении вызова.
//
// # Что делать, если гейт покраснел
//
// Не снимать его. Дымовая проба на старте — это запись чужого домена в боевое
// зеркало поднятого кластера и отчёт, который ничего не гейтит. Свойство, ради
// которого она стояла, покрыто интеграционно против настоящего сведения. Нужна
// снова — значит нужен разговор о том, что она пишет и кто читает её вердикт.

import (
	"os"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"
)

// bootSmokeCallSites — имена, которыми старт заводил бы синтетический объект.
// Перечислены ВСЕ формы, которыми это выражалось: одного имени мало, снятый
// вызов вернулся бы под соседним.
var bootSmokeCallSites = []string{
	"RunBootForwardSmoke(",
	"ForwardSmoke(",
	"SeedSmokeMirrorObject(",
	"SmokeOwnerBindingCandidate(",
}

func TestBootDoesNotSeedASyntheticMirrorObject(t *testing.T) {
	root := iamServiceRoot(t)
	files, err := treecorpus.UnderWithSuffix(root+"/cmd", ".go")
	if err != nil {
		t.Fatalf("перечень файлов композиционного корня: %v", err)
	}

	var (
		filesRead int
		findings  []string
	)
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		body, rerr := os.ReadFile(path)
		if rerr != nil {
			t.Fatalf("читать %s: %v", path, rerr)
		}
		filesRead++
		text := string(body)
		for _, call := range bootSmokeCallSites {
			// Судится ВЫЗОВ, а не слово: имя механизма стоит и в объяснении,
			// почему его тут нет, и гейт по подстроке краснел бы на собственной
			// прозе. Вызов отличает открывающая скобка вплотную к имени — и
			// отсутствие двойной косой черты перед ним в той же строке.
			for _, line := range strings.Split(text, "\n") {
				idx := strings.Index(line, call)
				if idx < 0 {
					continue
				}
				if c := strings.Index(line, "//"); c >= 0 && c < idx {
					continue
				}
				findings = append(findings, path+": "+strings.TrimSpace(line))
			}
		}
	}

	if filesRead == 0 {
		t.Fatal("обход пуст: прочитано НОЛЬ файлов композиционного корня — " +
			"вердикт беспредметен, а «находок нет» неотличимо от «ничего не читали»")
	}
	t.Logf("перепись: файлов композиционного корня прочитано %d, форм вызова осмотрено %d",
		filesRead, len(bootSmokeCallSites))

	if len(findings) > 0 {
		t.Fatalf("старт снова заводит синтетический объект в боевом зеркале (#119): %v", findings)
	}
}
