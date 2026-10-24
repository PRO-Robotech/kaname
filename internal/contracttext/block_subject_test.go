// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package contracttext

// block_subject_test.go — Block и Unblock называют ОДИН предмет во всех местах
// контракта: личность целиком, на всей платформе (kaname#721).
//
// # Предмет
//
// Блокировка — свойство личности (решение владельца, вопрос В-8 приёмки
// IAM-ID-1): use-case `api/user/set_blocked.go` пишет состояние в строку
// `users`, которая одна на человека, и членства не трогает. Контракт при этом
// описывал Block про личность, а Unblock и оба запроса — про «User membership»:
// человек в двух аккаунтах после Unblock по контракту возвращался бы в один,
// а на деле — во все.
//
// # Что судится
//
// Четыре места: оба метода клиентского интерфейса и поле `user_id` обоих
// запросов. Каждое называет человека; ни одно не называет членство тем, что
// блокируется или снимается; оба метода называют радиус — всю платформу.
//
// # Граница
//
// Упоминание членства в прозе Block законно: оно объясняет, почему радиус —
// вся платформа. Находка — только членство как ОБЪЕКТ глагола.

import (
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	textBlock          = "UserServiceClient.Block"
	textUnblock        = "UserServiceClient.Unblock"
	textBlockRequest   = "BlockUserRequest.UserId"
	textUnblockRequest = "UnblockUserRequest.UserId"
)

var (
	// namesThePerson — текст называет человека либо личность.
	namesThePerson = regexp.MustCompile(`(?i)\b(person|identity)\b`)
	// namesThePlatform — текст называет радиус: вся платформа.
	namesThePlatform = regexp.MustCompile(`(?i)\b(anywhere|everywhere|whole|every Account)\b[^.]{0,40}\bplatform\b|\bplatform-wide\b`)
	// membershipAsObject — членство как объект блокировки: «User membership»,
	// «membership row to block», «block(s|ed|ing) a membership», «membership … suspended».
	membershipAsObject = regexp.MustCompile(`(?i)\bUser membership\b|\bmembership row to (un)?block\b|` +
		`\b(un)?block(s|ed|ing)?\s+(a|an|the)?\s*(active\s+|suspended\s+|blocked\s+)?membership\b|` +
		`\b(suspended|blocked)\s+membership\b|\bmembership\s+(was|is)\s+(suspended|blocked)\b`)
)

// blockSubjectFindings — находки; пусто = четыре места называют один предмет.
func blockSubjectFindings(texts stubTexts) []string {
	var found []string
	keys := []string{textBlock, textUnblock, textBlockRequest, textUnblockRequest}
	sort.Strings(keys)
	for _, k := range keys {
		text := oneLine(texts[k])
		if !namesThePerson.MatchString(text) {
			found = append(found, k+": предмет блокировки — человек — не назван")
		}
		if m := membershipAsObject.FindString(text); m != "" {
			found = append(found, k+": членство названо объектом блокировки: «"+m+"»")
		}
	}
	for _, k := range []string{textBlock, textUnblock} {
		if !namesThePlatform.MatchString(oneLine(texts[k])) {
			found = append(found, k+": радиус — вся платформа — не назван")
		}
	}
	return found
}

// TestBlockAndUnblockContractNameOneSubject — гейт на дереве.
func TestBlockAndUnblockContractNameOneSubject(t *testing.T) {
	texts := readStubTexts(t)
	requireTexts(t, texts, textBlock, textUnblock, textBlockRequest, textUnblockRequest)
	found := blockSubjectFindings(texts)
	require.Emptyf(t, found, "контракт Block/Unblock называет разные предметы:\n  %s\n"+
		"Правится proto/kaname/cloud/iam/v1/user_service.proto, заглушки — регенерацией.",
		strings.Join(found, "\n  "))
}

// TestBlockSubjectPredicateInjection — дефектный текст краснит, исправный молчит.
func TestBlockSubjectPredicateInjection(t *testing.T) {
	good := stubTexts{
		textBlock:          "Blocks the specified person: the identity may no longer authenticate anywhere on the platform.",
		textUnblock:        "Unblocks the specified person: the identity may authenticate anywhere on the platform again.",
		textBlockRequest:   "ID of the User — the person, one row for the whole platform — to block.",
		textUnblockRequest: "ID of the User — the person, one row for the whole platform — to unblock.",
	}
	require.Empty(t, blockSubjectFindings(good))

	for _, tc := range []struct{ key, text string }{
		{textUnblock, "Unblocks the specified User membership: it may authenticate into that Account again."},
		{textBlockRequest, "ID of the User membership row to block."},
		{textBlock, "Blocks the specified person on the platform-wide scope. Blocking a membership that is already blocked succeeds."},
		{textUnblock, "Unblocks the specified person: the identity may authenticate again."},
	} {
		bad := stubTexts{}
		for k, v := range good {
			bad[k] = v
		}
		bad[tc.key] = tc.text
		require.NotEmptyf(t, blockSubjectFindings(bad), "дефект не пойман: %s = %q", tc.key, tc.text)
	}
}
