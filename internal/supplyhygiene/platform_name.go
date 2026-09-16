// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// platform_name.go — распознаватель ИМЕНИ ПЛАТФОРМЫ в тексте, общий для двух
// гейтов: клиентского сайта (`client_site_platform_name.go`) и переписи осей
// (`platform_name_axes.go`).
//
// ─────────────────────────────────────────────────────────────────────────────
// ОБЕ ЛАТИНСКИЕ ФОРМЫ, И ЭТО НЕСУЩЕЕ
//
// Имя платформы записывается в дереве двумя латинскими формами: обычной и с
// диакритическим знаком над последней гласной. Предикат, знающий одну, недобирает
// МОЛЧА: диакритическая форма обычным регистронезависимым поиском не находится.
// Замер клиентских страниц на `6e9b94ab`: страниц 29, несущих имя в любой форме
// 23, из них ДЕВЯТЬ несут только диакритическую — ASCII-предикат объявил бы их
// чистыми, а это ровно те страницы, где продукт называл себя чужим именем.
//
// Поэтому форма ищется посимвольно: основа сравнивается без регистра, последняя
// позиция принимает обе записи. Каждое вхождение возвращается с признаком формы,
// и перепись печатает обе величины врозь.
//
// ─────────────────────────────────────────────────────────────────────────────
// ВХОЖДЕНИЕ ВОЗВРАЩАЕТСЯ ВМЕСТЕ С ТОКЕНОМ
//
// Имя в дереве стоит и отдельным словом прозы, и внутри координаты: имени ряда
// общего измерителя, адреса соседнего репозитория, метки секрета, которую
// чеканит фундамент. Решение «своё или чужое» принимается о ТОКЕНЕ, а не о
// подстроке: одна и та же подстрока в `kacho-vpc` называет соседний сервис, а
// отдельным словом — продукт. Токен продолжают латиница, цифры и разделители
// координат; кириллица его НЕ продолжает, иначе имя склеилось бы с соседним
// словом русской прозы и каждое вхождение стало бы уникальным.
package supplyhygiene

import "strings"

// platformNameStem — основа имени платформы. Последняя гласная — предмет
// расхождения двух форм — проверяется отдельно (platformNameAt).
const platformNameStem = "kach"

// PlatformNameHit — одно вхождение имени платформы.
type PlatformNameHit struct {
	// Line — номер строки, с единицы.
	Line int
	// Token — токен целиком, в котором стоит имя.
	Token string
	// Diacritic — вхождение записано диакритической формой.
	Diacritic bool
}

// PlatformNameHits — все вхождения имени платформы в тексте, обе формы.
func PlatformNameHits(body string) []PlatformNameHit {
	var out []PlatformNameHit
	for idx, line := range strings.Split(body, "\n") {
		rs := []rune(line)
		for i := 0; i < len(rs); {
			n, diacritic := platformNameAt(rs, i)
			if n == 0 {
				i++
				continue
			}
			out = append(out, PlatformNameHit{
				Line:      idx + 1,
				Token:     tokenAround(rs, i, i+n),
				Diacritic: diacritic,
			})
			i += n
		}
	}
	return out
}

// platformNameAt — длина имени платформы в рунах с позиции i (ноль — имени здесь
// нет) и признак диакритической формы.
func platformNameAt(rs []rune, i int) (int, bool) {
	if i+len(platformNameStem) >= len(rs) {
		return 0, false
	}
	for k, want := range platformNameStem {
		if lowerASCIIRune(rs[i+k]) != want {
			return 0, false
		}
	}
	switch rs[i+len(platformNameStem)] {
	case 'o', 'O':
		return len(platformNameStem) + 1, false
	case 'ō', 'Ō':
		return len(platformNameStem) + 1, true
	}
	return 0, false
}

func lowerASCIIRune(r rune) rune {
	if r >= 'A' && r <= 'Z' {
		return r + ('a' - 'A')
	}
	return r
}

// isTokenRune — руна, продолжающая токен, в котором стоит имя.
func isTokenRune(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return true
	case r == 'ō', r == 'Ō':
		return true
	}
	return strings.ContainsRune("_-./:@#$", r)
}

// tokenTerminators — знаки, которые продолжают координату внутри, но в конце
// токена принадлежат прозе: «Kachō.» и «Kachō:» — одно и то же слово.
const tokenTerminators = ".:"

// tokenAround — токен, содержащий руны [from, to).
func tokenAround(rs []rune, from, to int) string {
	left := from
	for left > 0 && isTokenRune(rs[left-1]) {
		left--
	}
	right := to
	for right < len(rs) && isTokenRune(rs[right]) {
		right++
	}
	for right > to && strings.ContainsRune(tokenTerminators, rs[right-1]) {
		right--
	}
	return string(rs[left:right])
}
