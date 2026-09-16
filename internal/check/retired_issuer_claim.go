// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// retired_issuer_claim.go — ГЕЙТ КЛАССА: утверждение, что прежний внешний
// OAuth-сервер ОСТАЁТСЯ подписантом либо издателем (или что служба сама не
// чеканит), законно только в форме надгробия (эпик kacho#2564, линия B).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Своя чеканка токенов действует на каждой предлагаемой цепочке установки
// (`deploy/values.prod.yaml`, `authn.tokenSigning.enabled: true`), и пять путей
// выдачи из шести чеканим мы. Но прозу об этом писали в разное время, и в
// дереве живут ДВЕ редакции одного утверждения:
//
//	«data-plane fetches verification keys from iam (Hydra stays the signer).»
//	«Здесь стояло „Hydra stays the issuer/signer“ — утверждение, пережившее…»
//
// Первая — утверждение, пережившее свой предмет (в дереве оно стояло без
// кавычек; здесь процитировано, потому что этот файл гейт читает тоже).
// Вторая — надгробие: та же фраза, но названная ПРЕЖНЕЙ и опровергнутая. Читатель, открывший первую,
// принимает её за действующее ограничение и строит на ней решение: «раз
// подписант чужой — ключницу здесь не ротировать, издателя здесь не сверять».
//
// Цена этого класса в этом же дереве уже платилась: одно и то же утверждение
// «Hydra remains the signer/issuer» жило в ПЯТИ файлах двух репозиториев, и в
// день, когда его опровергли в одном, четыре других продолжали читаться как
// норма — их нашла эта перепись, а не обзор диффа.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО СУДИТСЯ — УТВЕРЖДЕНИЕ О ДЕЙСТВУЮЩЕМ, А НЕ СЛОВО
//
// Слово «Hydra» в дереве законно во множестве мест: имена ручек посадки,
// колонка зеркала в применённой миграции, порт клиента к его админ-API, разбор
// самого переезда. Гейт по слову краснел бы на исправном дереве и был бы снят
// первым же обходом. Судится РОД утверждения — что прежний издатель остаётся
// (stays / remains / является) подписантом или издателем, что ключи проверки
// «его», что служба ничего не чеканит. Формы перечислены в `RetiredIssuerClaimForms`
// поимённо, и инъекция гоняет КАЖДУЮ.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЗАКОННЫЙ БЛИЗНЕЦ — НАДГРОБИЕ, И РАСПОЗНАЁТСЯ ОН ДВУМЯ ПРИЗНАКАМИ
//
//  1. утверждение стоит В КАВЫЧКАХ на той же строке («…», "…", “…”): корпус
//     цитирует снятое именно так — «Здесь стояло „…“»;
//  2. на той же строке стоит маркер прошедшего: «стояло», «It said»,
//     «пережившее», «no longer», «больше не».
//
// Любого одного достаточно. Надгробие, разнесённое на две строки так, что ни
// маркер, ни кавычка не попали на строку с утверждением, гейт назовёт находкой —
// и это верно: такое надгробие читается как утверждение с той же вероятностью,
// с какой его не узнал распознаватель.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕГО ГЕЙТ НЕ ВИДИТ — НАЗВАНО ВСЛУХ
//
// Описание полосы, названной по прежнему издателю («Hydra-issued token»,
// «via Hydra»), под ось НЕ подпадает: это описание происхождения, а не
// утверждение о том, кто подписывает сегодня. Часть таких описаний тоже
// пережила предмет, и правится она обзором — предикат «назван прежний издатель»
// от «утверждается, что он действует» машинно не отличает. Пробы и e2e-наборы
// из обхода исключены: там прежний издатель законно стоит фикстурой.
package check

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// RetiredIssuerName — имя снимаемого компонента, как его пишут в дереве.
const RetiredIssuerName = "hydra"

// RetiredIssuerClaimForms — формы утверждения «прежний издатель действует»,
// каждая — отдельный распознаватель. Перечень закрыт и гоняется инъекцией
// поимённо: форма, о которой распознаватель не знает, даёт не красное и не
// зелёное, а молчание.
var RetiredIssuerClaimForms = []struct {
	Name string
	Re   *regexp.Regexp
}{
	{"остаётся (stays/remains)", regexp.MustCompile(`(?i)\bhydra\s+(stays|remains)\b`)},
	{"является издателем/подписантом", regexp.MustCompile(
		`(?i)\bhydra\s+is\s+(still\s+)?the\s+(token\s+)?(issuer|signer)\b|\b(issuer|signer)\s+is\s+hydra\b`)},
	{"ключи проверки — его", regexp.MustCompile(`(?i)\b(keys?|kids?)\s+(are|is)\s+hydra's`)},
	{"служба не чеканит", regexp.MustCompile(
		`(?i)\b(iam|kaname|shim|service|it)\s+(mints\s+nothing|does\s+not\s+mint|doesn't\s+mint)\b|\(hydra\s+does\)|\b(iam|kaname|служба|шим)\s+(ничего\s+не\s+чеканит|не\s+чеканит\s+ничего)`)},
	{"остаётся (по-русски)", regexp.MustCompile(
		`(?i)\bhydra\s+оста[её]тся\b|(издател|подписант)[а-яё]*\s*[—–-]+\s*hydra\b|\bhydra\s*[—–-]+\s*(единственн[а-яё]+\s+)?(издател|подписант)`)},
}

// retiredIssuerTombstoneMarker — маркер прошедшего на той же строке.
var retiredIssuerTombstoneMarker = regexp.MustCompile(
	`(?i)(стояло|стояла|it said|formerly|пережившее|пережило|no longer|больше не|перестал)`)

// RetiredIssuerClaim — одно утверждение, пережившее предмет.
type RetiredIssuerClaim struct {
	File string
	Line int
	Form string
	Text string
}

func (c RetiredIssuerClaim) String() string {
	return fmt.Sprintf("%s:%d утверждает, что прежний OAuth-сервер действует (%s): %q — "+
		"своя чеканка объявлена каждой предлагаемой цепочкой, и читатель, приняв это за "+
		"норму, построит на ней решение. Либо приведите к факту, либо назовите прежним и "+
		"опровергните на той же строке (надгробие: в кавычках либо со словом «стояло»)",
		c.File, c.Line, c.Form, strings.TrimSpace(c.Text))
}

// RetiredIssuerClaimCensus — объём осмотренного. Печатается всегда: «ноль
// находок» обязано быть отличимо от «ноль прочитанного».
type RetiredIssuerClaimCensus struct {
	// Files — файлов корпуса прочитано.
	Files int
	// Mentions — строк, называющих прежний издатель хоть как-нибудь.
	Mentions int
	// Claims — из них утверждений о действующем (до вычета надгробий).
	Claims int
	// Tombstones — утверждений в форме надгробия (законный близнец).
	Tombstones int
	// Findings — утверждений, переживших предмет.
	Findings int
}

func (c RetiredIssuerClaimCensus) String() string {
	return fmt.Sprintf("перепись: файлов %d · строк с именем прежнего издателя %d · "+
		"утверждений о действующем %d · из них надгробий %d · находок %d",
		c.Files, c.Mentions, c.Claims, c.Tombstones, c.Findings)
}

// RetiredIssuerProseFile — файл, чью прозу гейт судит: всё отслеживаемое, кроме
// проб, e2e-наборов, порождённых стабов, замков зависимостей и двоичного.
//
// Документация ВХОДИТ намеренно: страница оператора — то место, где утверждение
// переживает предмет дольше всего, потому что её никто не компилирует.
func RetiredIssuerProseFile(rel string) bool {
	if strings.HasSuffix(rel, "_test.go") || strings.HasSuffix(rel, ".pb.go") ||
		strings.HasSuffix(rel, "package-lock.json") || strings.HasSuffix(rel, ".sum") {
		return false
	}
	for _, seg := range strings.Split(rel, "/") {
		switch seg {
		case ".git", ".claude", "node_modules", "vendor", "bin", "tests", "testdata":
			return false
		}
	}
	switch {
	case strings.HasSuffix(rel, ".png"), strings.HasSuffix(rel, ".jpg"),
		strings.HasSuffix(rel, ".ico"), strings.HasSuffix(rel, ".woff"),
		strings.HasSuffix(rel, ".woff2"), strings.HasSuffix(rel, ".wasm"),
		strings.HasSuffix(rel, ".pdf"), strings.HasSuffix(rel, ".gz"):
		return false
	}
	return true
}

// JudgeRetiredIssuerClaims — тело гейта над телами файлов. Вынесено, чтобы
// инъекция звала ТО ЖЕ, что исполняется на дереве.
//
// Пустой корпус — отказ, а не «находок нет».
func JudgeRetiredIssuerClaims(corpus map[string]string) ([]RetiredIssuerClaim, RetiredIssuerClaimCensus, error) {
	census := RetiredIssuerClaimCensus{Files: len(corpus)}
	if len(corpus) == 0 {
		return nil, census, fmt.Errorf("%w — судить нечего", ErrEmptyTraversal)
	}
	rels := make([]string, 0, len(corpus))
	for rel := range corpus {
		rels = append(rels, rel)
	}
	sort.Strings(rels)

	var out []RetiredIssuerClaim
	for _, rel := range rels {
		for i, line := range strings.Split(corpus[rel], "\n") {
			lower := strings.ToLower(line)
			if !strings.Contains(lower, RetiredIssuerName) &&
				!strings.Contains(lower, "чеканит") && !strings.Contains(lower, "mint") {
				continue
			}
			if strings.Contains(lower, RetiredIssuerName) {
				census.Mentions++
			}
			form, loc := retiredIssuerClaimAt(line)
			if form == "" {
				continue
			}
			census.Claims++
			if retiredIssuerTombstoneMarker.MatchString(line) || quotedSpan(line, loc[0], loc[1]) {
				census.Tombstones++
				continue
			}
			census.Findings++
			out = append(out, RetiredIssuerClaim{File: rel, Line: i + 1, Form: form, Text: line})
		}
	}
	return out, census, nil
}

// retiredIssuerClaimAt — первая форма, найденная на строке, и её положение.
func retiredIssuerClaimAt(line string) (string, []int) {
	for _, f := range RetiredIssuerClaimForms {
		if loc := f.Re.FindStringIndex(line); loc != nil {
			return f.Name, loc
		}
	}
	return "", nil
}

// quotedSpan — лежит ли отрезок [s,e) внутри пары кавычек на той же строке.
//
// Кавычки трёх видов: ёлочки корпуса, прямые и типографские. Открывающая
// ищется слева от отрезка, закрывающая — справа; пара обязана быть одного вида.
func quotedSpan(line string, s, e int) bool {
	pairs := [][2]string{{"«", "»"}, {`"`, `"`}, {"“", "”"}}
	for _, p := range pairs {
		if strings.Contains(line[:s], p[0]) && strings.Contains(line[e:], p[1]) {
			return true
		}
	}
	return false
}
