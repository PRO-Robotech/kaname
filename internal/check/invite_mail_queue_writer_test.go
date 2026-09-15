// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

// invite_mail_queue_writer_test.go — очередь писем приглашения имеет ОДНОГО
// писателя, и он списывает частоту на адрес ДО того, как намерение ляжет
// (приёмка ID-MAIL-1, Р22 и §10 п. 17: «глагол, отправляющий письмо и не
// проходящий через ограничитель, — находка»).
//
// # Почему гейт судит писателя очереди, а не перечень глаголов
//
// Перечень глаголов, отправляющих письмо, пришлось бы вести руками, и следующий
// глагол завели бы мимо него молча. Письмо отправляет только то, что легло в
// очередь, а в очередь кладёт только писатель — значит, если писатель один и
// ограничен, ограничен и КАЖДЫЙ глагол, сколько бы их ни завели. Перечень
// выводится из дерева по построению: гейт краснеет на втором писателе, а не на
// втором глаголе.
//
// # Граница названа
//
// Гейт видит запись в очередь двумя формами: вызов общей эмиссии с ИМЕНЕМ
// очереди (константой пакета очереди, константой применителя либо литералом) и
// SQL-литерал вставки. Имя очереди, собранное из кусков, он не видит — это
// слепая зона всякого разбора по литералу. Безусловность списания он тоже не
// судит: её держит интеграционная проба «непровязанная величина отвергает письмо».

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"
	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// inviteMailQueueCensusFloor — ниже этого числа разобранных файлов «ноль
// посторонних писателей» означало бы «ноль прочитанного».
const inviteMailQueueCensusFloor = 300

func TestInviteMailQueueHasOneWriterAndItIsRated(t *testing.T) {
	t.Parallel()
	corpusRoot, modulePrefix := platformtree.RequireCorpus(t)
	ownDir := corpusRoot
	if modulePrefix != "" {
		ownDir = filepath.Join(corpusRoot, filepath.FromSlash(modulePrefix))
	}
	files, err := treecorpus.UnderWithSuffix(ownDir, ".go")
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: состав дерева не прочитан: %v", err)
	}

	var (
		read    int
		census  check.InviteMailQueueCensus
		writers []check.InviteMailQueueWrite
	)
	for _, abs := range files {
		if strings.HasSuffix(abs, "_test.go") {
			continue
		}
		rel, _ := filepath.Rel(ownDir, abs)
		rel = filepath.ToSlash(rel)
		src, rerr := os.ReadFile(abs) // #nosec G304 -- путь из индекса git своего дерева
		if rerr != nil {
			t.Fatalf("чтение %s: %v", rel, rerr)
		}
		scan, serr := check.ScanInviteMailQueueWrites(rel, src)
		if serr != nil {
			t.Fatalf("разбор %s: %v", rel, serr)
		}
		read++
		census.Add(scan.Census)
		writers = append(writers, scan.Writes...)
	}

	t.Logf("перепись: файлов разобрано %d · вызовов общей эмиссии %d · SQL-литералов %d · "+
		"записей в очередь писем %d", read, census.EmitCalls, census.SQLLiterals, len(writers))
	if read < inviteMailQueueCensusFloor {
		t.Fatalf("разобрано %d файлов при пороге %d — «ноль посторонних писателей» сказано ни о чём",
			read, inviteMailQueueCensusFloor)
	}
	if census.EmitCalls == 0 {
		t.Fatalf("вызовов общей эмиссии не найдено НИ ОДНОГО — форма «запись через эмиссию» "+
			"перестала распознаваться, и гейт ослеп на ней")
	}

	var legit []check.InviteMailQueueWrite
	for _, w := range writers {
		if w.Func == check.InviteMailQueueSoleWriter {
			legit = append(legit, w)
			continue
		}
		t.Errorf("%s:%d — %s кладёт намерение в очередь писем (%s) МИМО единственного писателя %s. "+
			"Письмо, легшее мимо него, не проходит ограничение частоты на адрес (Р14, Р22): глагол, "+
			"который его кладёт, становится способом слать письма без предела. Клади через %s.",
			w.File, w.Line, w.Func, w.Form, check.InviteMailQueueSoleWriter, check.InviteMailQueueSoleWriter)
	}
	if len(legit) == 0 {
		t.Fatalf("единственный писатель %s в дереве НЕ НАЙДЕН — либо он снят (тогда очередь писать "+
			"некому и гейт снимается вместе с ней), либо распознаватель перестал его видеть", check.InviteMailQueueSoleWriter)
	}
	for _, w := range legit {
		if !w.ChargedBefore {
			t.Errorf("%s:%d — единственный писатель очереди кладёт намерение, НЕ списав частоту на адрес "+
				"до этого (%s). Решение и его следствие обязаны быть одним путём: списание после записи "+
				"либо без неё пропускает письмо сверх предела.", w.File, w.Line, check.InviteMailRateCharge)
		}
	}
	t.Logf("писатель %s: записей %d, списание частоты перед каждой — %v",
		check.InviteMailQueueSoleWriter, len(legit), allCharged(legit))
}

func allCharged(ws []check.InviteMailQueueWrite) bool {
	for _, w := range ws {
		if !w.ChargedBefore {
			return false
		}
	}
	return true
}
