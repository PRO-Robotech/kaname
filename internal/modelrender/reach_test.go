// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package modelrender_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/internal/authzplan"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho/services/iam/internal/manifest"
	"github.com/PRO-Robotech/kacho/services/iam/internal/modelrender"
)

// reach_test.go — ОСТАТОК называется числом, а не умалчивается (приёмка B-07).
//
// Побайтовое равенство достижимо ровно для тех блоков канона, чья форма выразима
// разделом `resources` СЕГОДНЯШНЕЙ схемы. Это не «качество рендера», а условие
// исполнимости сверки, и потому измеряется числом: «выражено не всё» обязано быть
// отличимо от «выражено всё».
//
// # Порог поднят с 12 до 27, и это перепись, а не обещание
//
// Прежняя редакция достигала 12 блоков из 27. Остаток делился на два: у 13 блоков
// форма не выражалась разделом вовсе (позиционированная проза, второй указатель,
// имя указателя ≠ тип, каскад вне умолчания, класс действия вне пятёрки, `v_*`
// сверх умолчания, место авторского отношения), у 2 — выражалась, а рендер её не
// воспроизводил. Формы заведены задачами #1845, #1846, #1853, #1858, #1860 и
// #1862; остатка не осталось ни в одной категории.

// derived — попытка вывести ресурс, порождающий данный блок. ok=false, когда форма
// блока разделом `resources` не выражается.
//
// Это НЕ второй рендер: вывод проверяется прогоном НАСТОЯЩЕГО Render и побайтовой
// сверкой с блоком. Вывод, ошибшийся в любую сторону, даёт неравенство и попадает
// в остаток, а не в достижимое.
func derived(block modelrender.Block) (manifest.Resource, bool) {
	lines := strings.Split(strings.TrimRight(string(block.Body), "\n"), "\n")
	if len(lines) < 2 || !strings.HasPrefix(lines[0], "type ") || lines[1] != "  relations" {
		return manifest.Resource{}, false
	}
	r := manifest.Resource{ObjectType: strings.TrimPrefix(lines[0], "type "), Producer: "authored"}

	// Примечание принадлежит отношению, ПЕРЕД которым стоит: строки комментария
	// копятся и отдаются якорю на первой же строке `define`.
	var pending []string
	type definition struct{ name, rhs string }
	var defs []definition
	for _, raw := range lines[2:] {
		body, ok := strings.CutPrefix(raw, "    ")
		if !ok {
			return manifest.Resource{}, false
		}
		if strings.HasPrefix(body, "#") {
			// Знак комментария принадлежит ТЕКСТУ: рендер воспроизводит строку
			// дословно, поэтому и обратный вывод её не раздевает.
			pending = append(pending, body)
			continue
		}
		rest, isDefine := strings.CutPrefix(body, "define ")
		if !isDefine {
			return manifest.Resource{}, false
		}
		name, rhs, cut := strings.Cut(rest, ": ")
		if !cut {
			return manifest.Resource{}, false
		}
		if len(pending) > 0 {
			r.Notes = append(r.Notes, manifest.Note{Before: name, Text: strings.Join(pending, "\n")})
			pending = nil
		}
		defs = append(defs, definition{name: name, rhs: rhs})
	}
	// Проза в конце блока якоря не имеет: примечание ставится ПЕРЕД отношением.
	if len(pending) > 0 {
		return manifest.Resource{}, false
	}

	i := 0
	// Указатели идут первыми: `define <имя>: [<тип>]`, где тип односоставный и не
	// является списком субъектов.
	for ; i < len(defs); i++ {
		d := defs[i]
		if d.name == manifest.SuperAdminRelation() {
			break
		}
		inner, isList := strings.CutPrefix(d.rhs, "[")
		if !isList || !strings.HasSuffix(inner, "]") {
			break
		}
		typ := strings.TrimSuffix(inner, "]")
		if strings.ContainsAny(typ, ", #:") {
			break
		}
		r.Parents = append(r.Parents, manifest.Parent{Name: d.name, Type: typ})
	}
	if len(r.Parents) == 0 || i >= len(defs) || defs[i].name != manifest.SuperAdminRelation() {
		return manifest.Resource{}, false
	}
	for _, term := range strings.Split(defs[i].rhs, " or ") {
		relation, from, cut := strings.Cut(term, " from ")
		if !cut {
			return manifest.Resource{}, false
		}
		r.Cascade = append(r.Cascade, manifest.CascadeTerm{Relation: relation, From: from})
	}
	i++

	tierNames := map[string]bool{"admin": true, "editor": true, "viewer": true}
	place := "beforeTiers"
	for _, d := range defs[i:] {
		switch {
		case strings.HasPrefix(d.name, "v_"):
			place = "afterVerbs"
			subjects, sources, ok := splitSubjectsAndSources(d.rhs)
			if !ok {
				return manifest.Resource{}, false
			}
			r.Verbs = append(r.Verbs, manifest.Verb{
				Name: strings.TrimPrefix(d.name, "v_"), Class: "get",
				Subjects: subjects, From: sources,
			})
		case tierNames[d.name] && strings.HasPrefix(d.rhs, "["):
			subjects, sources, ok := splitSubjectsAndSources(d.rhs)
			if !ok {
				return manifest.Resource{}, false
			}
			if len(r.Tiers) == 0 {
				r.Subjects = subjects
			} else if strings.Join(subjects, ",") != strings.Join(r.Subjects, ",") {
				return manifest.Resource{}, false
			}
			r.Tiers = append(r.Tiers, manifest.ResourceTier{Name: d.name, From: sources})
			place = "beforeVerbs"
		default:
			r.Relations = append(r.Relations, manifest.Relation{
				Name: d.name, Definition: d.rhs, Position: place,
			})
		}
	}
	return r, true
}

// splitSubjectsAndSources — правая часть вида `[субъекты] or источник or …`.
func splitSubjectsAndSources(rhs string) (subjects, sources []string, ok bool) {
	list, tail, cut := strings.Cut(rhs, "] or ")
	if !cut || !strings.HasPrefix(list, "[") {
		return nil, nil, false
	}
	return strings.Split(strings.TrimPrefix(list, "["), ", "), strings.Split(tail, " or "), true
}

// Исходы разбора блока. Их ТРИ, потому что «форма не выражается» и «рендер не
// воспроизводит» чинятся разными правками и разными задачами.
const (
	verdictReached = iota
	verdictUnexpressible
	verdictUnreproduced
)

// reproduces — доходит ли блок до побайтового равенства через НАСТОЯЩИЙ Render.
func reproduces(b modelrender.Block) int {
	r, ok := derived(b)
	if !ok {
		return verdictUnexpressible
	}
	got, err := modelrender.Render(r)
	if err != nil || string(got) != string(b.Body) {
		return verdictUnreproduced
	}
	return verdictReached
}

// blockWithoutProse — тот же блок со снятыми строками комментария.
//
// Нужен ровно для одного вопроса: «если снять из блока ВСЮ прозу, станет ли он
// достижим». Он и отделяет прозу без дома от расхождения структуры — иначе
// корзина называется по первому препятствию, а не по причине.
func blockWithoutProse(b modelrender.Block) modelrender.Block {
	var kept []string
	for _, line := range strings.Split(strings.TrimRight(string(b.Body), "\n"), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		kept = append(kept, line)
	}
	return modelrender.Block{Type: b.Type, Body: []byte(strings.Join(kept, "\n") + "\n")}
}

// TestB07TheUnreachableRemainderIsNamedByNumber — сколько блоков канона рендер
// достаёт побайтово, и сколько НЕ достаёт.
//
// Проба утверждает НЕ РЕГРЕСС, а не цель: цель достигнута, и порог равен числу
// модульных блоков. Число печатается всегда, поэтому «ноль находок» отличимо от
// «ноль прочитанного».
func TestB07TheUnreachableRemainderIsNamedByNumber(t *testing.T) {
	path, dsl, err := authzplan.ResolveCanonicalModel()
	if err != nil {
		t.Fatalf("канон не резолвится: %v", err)
	}
	owned := map[string]bool{}
	for _, e := range authzmap.Catalog() {
		if typ, ok := authzmap.ObjectType(e.Module, e.Resource); ok {
			owned[typ] = true
		}
	}

	var modular int
	var reachedNames, homelessProse, unexpressible, unreproduced []string
	for _, b := range modelrender.SplitCanon(dsl) {
		if !owned[b.Type] {
			continue
		}
		modular++
		switch reproduces(b) {
		case verdictReached:
			reachedNames = append(reachedNames, b.Type)
			continue
		case verdictUnexpressible:
			unexpressible = append(unexpressible, b.Type)
		default:
			unreproduced = append(unreproduced, b.Type)
		}
		// КАТЕГОРИЯ определяется вторым замером, а не первым препятствием.
		// Прежнее деление на «А» и «Б» называло корзину по тому, обо что
		// разборщик споткнулся ПЕРВЫМ: проза стоит в блоке раньше структуры,
		// поэтому в «форма не выражается» уезжало всё, что стоит за прозой, —
		// и предикат «остаток А равен нулю» прозу не измерял вовсе.
		if reproduces(blockWithoutProse(b)) == verdictReached {
			homelessProse = append(homelessProse, b.Type)
		}
	}
	reached := len(reachedNames)

	if modular == 0 {
		t.Fatalf("модульных блоков 0 — обход пуст, вердикт беспредметен (канон %s)", path)
	}
	// Порог ЗАМЕРЕН этой же пробой, а не выбран: первая редакция несла придуманное
	// 15 и покраснела на собственном замере — число, поставленное для веса, есть
	// украшение, а не довод.
	//
	// Порог — НЕ РЕГРЕСС, а не цель: он падает, когда рендер теряет уже
	// достигнутое. Сегодня он равен ЧИСЛУ МОДУЛЬНЫХ БЛОКОВ, то есть остатка нет
	// ни в одной категории; новый блок канона поднимает знаменатель, и порог
	// покраснеет на нём, пока его форма не выражена.
	const floor = 27
	if reached < floor {
		t.Errorf("достижимо %d из %d, было не меньше %d — рендер потерял форму", reached, modular, floor)
	}
	t.Logf("перепись: модульных блоков %d · достижимо побайтово %d · остаток %d",
		modular, reached, modular-reached)
	// Достижимые названы ПОИМЁННО, а не только сосчитаны: переезд блока с одного
	// механизма на другой прироста не даёт, и `13 + 2` от `12 + 2` число не
	// отличает. Поимённый перечень отличает — в нём виден `nlb_listener`,
	// единственный блок, чья проза работала на прежней форме.
	t.Logf("достижимы поимённо: %s", strings.Join(reachedNames, ", "))
	// Остаток РАЗДЕЛЁН на ТРИ категории, а не на две: это разные предметы, они
	// чинятся разными правками, и слитое число скрыло бы, ЧЕМ именно блок
	// недостижим.
	t.Logf("остаток 1 — проза без дома (снятие прозы делает блок достижимым): %d · %s",
		len(homelessProse), strings.Join(homelessProse, ", "))
	t.Logf("остаток 2 — структура не выражается разделом `resources`: %d · %s",
		len(unexpressible), strings.Join(unexpressible, ", "))
	t.Logf("остаток 3 — форма выражается, но рендер её не воспроизводит: %d · %s",
		len(unreproduced), strings.Join(unreproduced, ", "))
	if len(homelessProse) != 0 {
		t.Errorf("прозы без дома %d — форма примечания с якорем её не выразила: %s",
			len(homelessProse), strings.Join(homelessProse, ", "))
	}
}
