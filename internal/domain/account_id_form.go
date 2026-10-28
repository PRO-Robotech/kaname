// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

// account_id_form.go — РАСПОЗНАВАТЕЛЬ ФОРМЫ ИДЕНТИФИКАТОРА АККАУНТА (задача
// kaname#1052, приёмка `docs/engineering/acceptance/account-id-may-be-supplied-at-create.md`,
// решения Р2 и Р10).
//
// # Что он судит
//
// Идентификатор аккаунта — строка, которую выбирает тот, кто заводит аккаунт
// (например логин площадки потребителя), либо выход генератора (`acc` и 17
// знаков его алфавита). Форма одна для создания и для каждой ссылки на аккаунт:
//
//   - (а) длина от 3 до 30 знаков;
//   - (б) знаки — строчные латинские буквы, цифры и дефис;
//   - (в) первый знак — буква, последний — буква или цифра;
//   - (г) двух дефисов подряд нет;
//   - (д) строка не в резерве (см. ниже).
//
// Нормализации нет: регистр не сворачивается, пробелы не срезаются. Одно
// значение выражается одним способом.
//
// # Резерв — функция самой строки
//
// Резерв не читает ни каталогов префиксов фундамента, ни ручек окружения, ни
// перечня посеянного: каталоги растут, ручки различаются между репликами, и
// резерв, зависящий от них, сузил бы форму у уже выданного идентификатора — это
// необратимо. Поэтому каждая строка резерва вычисляется из самой строки:
//
//   - (д1) слитная форма генератора ДРУГОГО вида: ровно 20 знаков, первые три —
//     строчные буквы или цифры и не `acc`, остальные 17 — знаки алфавита
//     генератора. Известен ли такой префикс фундаменту, не важно;
//   - (д2) дефисная форма генератора ЛЮБОГО вида, включая аккаунт: строка
//     оканчивается дефисом и 17 знаками алфавита генератора;
//   - (д3) литерал закрытого перечня этого файла (`reservedAccountIDLiterals`);
//   - (д4) пространство личных аккаунтов — начало `personal-cloud-` как есть или
//     после свёртки похожих знаков.
//
// Каталоги фундамента этот файл не зовёт и звать не должен: предикат приёмки
// AID-39 читает именно его.

import "strings"

// Пределы длины формы (а).
const (
	accountIDMinLen = 3
	accountIDMaxLen = 30
)

// generatorAlphabet — алфавит тела идентификатора, который чеканит генератор
// фундамента: Crockford без `i`, `l`, `o`, `u`. Перечислен ЯВНО, тем же списком,
// что функции формы в схеме.
const generatorAlphabet = "0123456789abcdefghjkmnpqrstvwxyz"

// generatorBodyLen — длина тела идентификатора генератора после префикса.
const generatorBodyLen = 17

// generatorPrefixLen — длина префикса слитной формы генератора.
const generatorPrefixLen = 3

// reservedAccountIDLiterals — закрытый перечень (д3): посеянные литералы, годные
// формой (а)–(г), которые идентификатором аккаунта стать не могут. Новый литерал
// посева обязан лежать вне формы (а)–(д) либо прийти правкой Р2 с переписью
// реестра выданных — перечень с посевом НЕ связан намеренно (проба AID-39 судит
// посев против этого перечня).
var reservedAccountIDLiterals = map[string]struct{}{
	"rol000000000sysviewer": {},
}

// AccountIDVerdict — исход распознавателя: принят, нарушена форма (а)–(г) или
// строка в резерве (д). Три исхода, а не «годно/негодно»: вход создания отвечает
// на них разными текстами (Р2).
type AccountIDVerdict int8

const (
	// AccountIDAccepted — строка есть идентификатор аккаунта.
	AccountIDAccepted AccountIDVerdict = iota + 1
	// AccountIDMalformed — нарушена форма (а)–(г).
	AccountIDMalformed
	// AccountIDReserved — форма (а)–(г) соблюдена, но строка в резерве (д).
	AccountIDReserved
)

// JudgeAccountID — вердикт распознавателя формы аккаунта. Единственное
// написание формы в Go: его зовут создание, каждая проверка ссылки на аккаунт и
// якорь области привязки (Р10).
func JudgeAccountID(s string) AccountIDVerdict {
	if !HasAccountIDSyntax(s) {
		return AccountIDMalformed
	}
	if accountIDIsReserved(s) {
		return AccountIDReserved
	}
	return AccountIDAccepted
}

// IsAccountID — строка есть идентификатор аккаунта формы Р2 (а)–(д).
func IsAccountID(s string) bool { return JudgeAccountID(s) == AccountIDAccepted }

// HasAccountIDSyntax — синтаксическая часть формы, (а)–(г). Её же судит схема
// (функция `kaname.account_id_has_account_form`): паритет держит проба
// AID-33 по таблицам AID-05/AID-06.
func HasAccountIDSyntax(s string) bool {
	if len(s) < accountIDMinLen || len(s) > accountIDMaxLen {
		return false
	}
	if !isLowerLetter(s[0]) {
		return false
	}
	if last := s[len(s)-1]; !isLowerLetter(last) && !isDigit(last) {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case isLowerLetter(c), isDigit(c):
		case c == '-':
			if s[i-1] == '-' {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// accountIDIsReserved — резерв (д1)–(д4) над строкой, уже прошедшей (а)–(г).
func accountIDIsReserved(s string) bool {
	if _, ok := reservedAccountIDLiterals[s]; ok {
		return true
	}
	if isFusedGeneratorFormOfAnotherKind(s) || isHyphenGeneratorForm(s) {
		return true
	}
	return strings.HasPrefix(FoldLookAlike(s), FoldLookAlike(PersonalAccountNamePrefix))
}

// isFusedGeneratorFormOfAnotherKind — (д1): 20 знаков, префикс из трёх строчных
// букв или цифр, не `acc`, и 17 знаков алфавита генератора.
func isFusedGeneratorFormOfAnotherKind(s string) bool {
	if len(s) != generatorPrefixLen+generatorBodyLen {
		return false
	}
	prefix := s[:generatorPrefixLen]
	if prefix == PrefixAccount {
		return false
	}
	for i := 0; i < generatorPrefixLen; i++ {
		if !isLowerLetter(prefix[i]) && !isDigit(prefix[i]) {
			return false
		}
	}
	return isGeneratorBody(s[generatorPrefixLen:])
}

// isHyphenGeneratorForm — (д2): строка оканчивается дефисом и 17 знаками
// алфавита генератора, при любом начале (форма (в) гарантирует, что начало
// непусто).
func isHyphenGeneratorForm(s string) bool {
	if len(s) < generatorBodyLen+2 {
		return false
	}
	cut := len(s) - generatorBodyLen
	return s[cut-1] == '-' && isGeneratorBody(s[cut:])
}

func isGeneratorBody(body string) bool {
	if len(body) != generatorBodyLen {
		return false
	}
	for i := 0; i < len(body); i++ {
		if strings.IndexByte(generatorAlphabet, body[i]) < 0 {
			return false
		}
	}
	return true
}

// FoldLookAlike — свёртка похожих знаков правила Р6а: `o` → `0`, `i` и `l` →
// `1`. Ровно те знаки, которые алфавит генератора исключает как неотличимые на
// глаз. Та же свёртка в схеме — функция `kaname.account_handle_fold`; паритет
// держит проба миграции.
func FoldLookAlike(s string) string {
	return lookAlikeFolder.Replace(s)
}

var lookAlikeFolder = strings.NewReplacer("o", "0", "i", "1", "l", "1")

func isLowerLetter(c byte) bool { return c >= 'a' && c <= 'z' }

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
