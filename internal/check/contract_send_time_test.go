// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package check_test

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Время сдачи письма ретранслятору остаётся живостью очереди и на контракт не
// выходит — решение записано `docs/engineering/architecture/known-divergences.md`, §20.
//
// # ПОЧЕМУ ГЕЙТ ДВУСТОРОННИЙ, А НЕ ПРОСТО «ПОЛЯ НЕТ»
//
// Одностороннее отрицание («в контракте нет `sent_at`») на исчезнувшем предмете
// НЕ КРАСНЕЕТ, а ЗАМОЛКАЕТ: снимут очередь писем целиком — образец перестанет
// совпадать навсегда, счётчик утверждений продолжит расти, вердикт останется
// зелёным. Отличить это от исправной работы нельзя ничем.
//
// Поэтому у гейта ДВЕ половины, и ни одна не выводится из другой:
//
//   - ПОЛОЖИТЕЛЬНАЯ — предмет записи ЖИВ: колонка объявлена миграцией очереди И
//     уборка доставленных для этой очереди провязана. Эфемерность величины и есть
//     довод §20; исчезнет уборка — исчезнет довод, и запись обязана быть
//     пересмотрена, а не молча пережить своё основание;
//   - ОТРИЦАТЕЛЬНАЯ — в контракте iam нет ПОЛЯ `sent_at`. Появится — §20 стала
//     ложью в тот же коммит.
//
// # ГРАНИЦА
//
// Гейт судит РАСКЛАДКУ, а не истинность прозы §20: написать в записке неверный
// довод он не помешает. Тот же предел, что у машинного чтения вердикта приёмки.
//
// Отдельно: гейт НЕ утверждает, что величина не должна доезжать до арендатора
// никогда. Он утверждает, что она не доезжает СЕГОДНЯ и что решение об этом
// записано. Появится durable-производитель (§20, предикат пересмотра) — красное
// здесь и будет тем самым зовом пересмотреть запись.

const (
	iamMigrationsRelDir = "services/iam/internal/migrations"
	iamMailWiringRelDir = "services/iam/cmd/kacho-iam"

	// inviteMailQueue — имя очереди писем приглашения без схемы.
	inviteMailQueue = "invite_mail_outbox"
	// sendTimeColumn — величина, о которой запись.
	sendTimeColumn = "sent_at"
	// queueSweepCall — провязка уборки доставленных строк.
	queueSweepCall = "StartQueueRetentionSweep"
)

// reSendTimeField — ОБЪЯВЛЕНИЕ поля, а не упоминание имени.
//
// Судить по подстроке нельзя: §20 и сама эта шапка называют `sent_at` прозой, и
// проверка по вхождению краснела бы на собственном объяснении — тот же класс,
// который ловится в гейтах по подстроке.
var reSendTimeField = regexp.MustCompile(`(?m)^\s*(?:repeated\s+)?[\w.]+\s+` + sendTimeColumn + `\s*=\s*\d+\s*;`)

// sendTimeCensus — объём осмотренного. Печатается всегда: «ноль находок» обязано
// быть отличимо от «ноль прочитанного».
type sendTimeCensus struct {
	migrations   int // файлов миграций прочитано
	contracts    int // файлов контракта прочитано
	queueDecls   int // миграций, объявляющих очередь вместе с колонкой
	sweepWirings int // провязок уборки для этой очереди
	contractHits int // объявлений поля в контракте
}

// auditSendTime — чистое ядро обеих проб: решает по текстам, а не по дереву.
func auditSendTime(migrations, contracts map[string]string, wiring string) ([]string, sendTimeCensus) {
	var findings []string
	c := sendTimeCensus{migrations: len(migrations), contracts: len(contracts)}

	for name, body := range migrations {
		if strings.Contains(body, inviteMailQueue) && strings.Contains(body, sendTimeColumn) {
			c.queueDecls++
			_ = name
		}
	}
	if c.queueDecls == 0 {
		findings = append(findings, fmt.Sprintf(
			"ПОЛОЖИТЕЛЬНАЯ ПОЛОВИНА: ни одна миграция не объявляет очередь %s вместе с колонкой %s — "+
				"предмет записи §20 исчез, и запись обязана быть пересмотрена, а не оставлена зелёной",
			inviteMailQueue, sendTimeColumn))
	}

	if strings.Contains(wiring, queueSweepCall) && strings.Contains(wiring, "InviteMailTable") {
		c.sweepWirings++
	} else {
		findings = append(findings, fmt.Sprintf(
			"ПОЛОЖИТЕЛЬНАЯ ПОЛОВИНА: уборка доставленных (%s) для очереди %s не провязана — "+
				"довод §20 об эфемерности величины держится именно ею; без уборки строка живёт вечно, "+
				"и вопрос о выносе на контракт открывается заново",
			queueSweepCall, inviteMailQueue))
	}

	for name, body := range contracts {
		for _, m := range reSendTimeField.FindAllString(stripProtoComments(body), -1) {
			c.contractHits++
			findings = append(findings, fmt.Sprintf(
				"ОТРИЦАТЕЛЬНАЯ ПОЛОВИНА: контракт %s объявляет поле %s (%q) — "+
					"§20 утверждает, что время сдачи письма на контракт не выходит, и стала ложью",
				name, sendTimeColumn, strings.TrimSpace(m)))
		}
	}
	return findings, c
}

// stripProtoComments снимает строчные комментарии: имя величины законно стоит в
// прозе контракта, и полем от этого не становится.
func stripProtoComments(body string) string {
	lines := strings.Split(body, "\n")
	out := make([]string, 0, len(lines))
	for _, ln := range lines {
		if strings.HasPrefix(strings.TrimSpace(ln), "//") {
			continue
		}
		out = append(out, ln)
	}
	return strings.Join(out, "\n")
}

// readDir читает файлы каталога с заданным расширением.
func readDir(t *testing.T, dir, ext string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	out := map[string]string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ext) {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name())) // #nosec G304 -- путь собран из корня собственного модуля
		require.NoError(t, err)
		out[e.Name()] = string(raw)
	}
	return out
}

// TestSendTimeStaysQueueLivenessAndOffTheContract — несущее утверждение.
func TestSendTimeStaysQueueLivenessAndOffTheContract(t *testing.T) {
	root := monorepoRoot(t)

	migrations := readDir(t, filepath.Join(root, iamMigrationsRelDir), ".sql")
	contracts := readDir(t, filepath.Join(root, iamContractDir), ".proto")

	wiringFiles := readDir(t, filepath.Join(root, iamMailWiringRelDir), ".go")
	var wiring strings.Builder
	for _, body := range wiringFiles {
		wiring.WriteString(body)
	}

	require.NotZerof(t, len(migrations), "обход миграций пуст — вердикт беспредметен (%s)", iamMigrationsRelDir)
	require.NotZerof(t, len(contracts), "обход контрактов пуст — вердикт беспредметен (%s)", iamContractDir)

	findings, c := auditSendTime(migrations, contracts, wiring.String())

	t.Logf("перепись: миграций прочитано %d · контрактов прочитано %d · "+
		"объявлений очереди с колонкой %d · провязок уборки %d · полей в контракте %d · находок %d",
		c.migrations, c.contracts, c.queueDecls, c.sweepWirings, c.contractHits, len(findings))

	require.Emptyf(t, findings,
		"решение §20 (время сдачи письма — живость очереди, а не факт для арендатора) разошлось с деревом:\n%s",
		strings.Join(findings, "\n"))
}
