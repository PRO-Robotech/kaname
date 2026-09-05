// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package modelcompose

// compose.go — модель процесса СОБИРАЕТСЯ на старте из доставленных манифестов
// (#1969, §2 п. 1-5, 9).
//
// # Форма складывания — ВХОДНОЕ ТРЕБОВАНИЕ, а не наш выбор
//
// «Канон дословно + перевод строки + блоки». Оно записано §11 приёмки допуска и
// названо там невыразимым иначе: несущая клауза Д7(а) требует, чтобы текст
// канона присутствовал в собранной модели ПОБАЙТОВО. Перерендеренный канон
// байтам не равен — довольно иной расстановки пробелов, — и тогда сверка
// вернулась бы к сравнению ДВУХ РАЗБОРОВ, у которого слепая зона есть.
//
// # Что здесь НЕ делается
//
// Не судится ДОПУСК: он живёт в `authzmodel.Admit` и получает готовый текст.
// Разделение несущее — допуск чистая функция от текста и о происхождении текста
// не спрашивает; смешав их, мы получили бы судью, знающего, что он судит своё.

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/PRO-Robotech/kacho-iam/internal/authzplan"
	"github.com/PRO-Robotech/kacho-iam/internal/manifest"
	"github.com/PRO-Robotech/kacho-iam/internal/modelrender"
)

// Report — перепись композиции. Печатается ВСЕГДА, независимо от исхода: без неё
// «ноль добавленного» неотличимо от «ноль прочитанного».
type Report struct {
	// ManifestsSeen — сколько манифестов осмотрено.
	ManifestsSeen int
	// ResourcesSeen — сколько ресурсов осмотрено во всех манифестах.
	ResourcesSeen int
	// CanonTypes — типов в каноне образа.
	CanonTypes int
	// Composed — имена типов, блоки которых добавлены, отсортированно.
	Composed []string
	// Reaffirmed — имена типов, которые канон уже объявляет и рендер которых
	// совпал с каноническим блоком побайтово.
	Reaffirmed []string
}

// Census — перепись одной строкой.
func (r Report) Census() string {
	return fmt.Sprintf("манифестов %d, ресурсов %d, типов канона %d, добавлено %d %v, подтверждено %d",
		r.ManifestsSeen, r.ResourcesSeen, r.CanonTypes, len(r.Composed), r.Composed, len(r.Reaffirmed))
}

// Compose собирает текст модели процесса.
//
// Всякий отказ — отказ ПУСКА у вызывающего: мягкого прохода здесь не заводится,
// он дал бы контроль, который не откажет ни разу за свою жизнь.
func Compose(canon string, manifests []*manifest.Manifest) (string, Report, error) {
	rep := Report{ManifestsSeen: len(manifests)}

	canonBlocks := modelrender.SplitCanon([]byte(canon))
	rep.CanonTypes = len(canonBlocks)
	if rep.CanonTypes == 0 {
		return "", rep, fmt.Errorf("modelcompose: канон не дал ни одного блока типа — "+
			"собирать не с чем, и «добавлено 0» здесь неотличимо от «прочитано 0» (осмотрено %d Б)", len(canon))
	}
	byType := make(map[string]modelrender.Block, len(canonBlocks))
	for _, b := range canonBlocks {
		byType[b.Type] = b
	}

	var out bytes.Buffer
	out.WriteString(canon)
	seen := make(map[string]struct{})
	declared := make(map[string]struct{}, len(byType))
	for t := range byType {
		declared[t] = struct{}{}
	}

	for _, m := range manifests {
		for _, res := range m.Resources {
			rep.ResourcesSeen++
			blk, err := modelrender.Render(res)
			if err != nil {
				return "", rep, fmt.Errorf("modelcompose: модуль %q, ресурс %q: рендер блока: %w",
					m.Module, res.Name, err)
			}
			// НОРМА 3: ровно один блок ровно того типа — судится ИСХОДОМ, тем же
			// разбором, которым читается канон, а не формой входа.
			got := modelrender.SplitCanon(blk)
			if len(got) != 1 || got[0].Type != res.ObjectType {
				names := make([]string, 0, len(got))
				for _, g := range got {
					names = append(names, g.Type)
				}
				return "", rep, fmt.Errorf("modelcompose: модуль %q, ресурс %q объявил тип %q, "+
					"а его рендер даёт блоков %d %v — композируемый блок обязан быть РОВНО одним "+
					"блоком РОВНО того типа, иначе в модель уезжает посторонний тип либо теряется "+
					"законное действие", m.Module, res.Name, res.ObjectType, len(got), names)
			}
			if _, dup := seen[res.ObjectType]; dup {
				return "", rep, fmt.Errorf("modelcompose: тип %q объявлен доставкой дважды — "+
					"второе объявление молча перекрыло бы первое", res.ObjectType)
			}
			seen[res.ObjectType] = struct{}{}

			if cb, inCanon := byType[res.ObjectType]; inCanon {
				// НОРМА 2: канон неприкосновенен. Блок не композируется; расхождение
				// называет тип и ОБЕ длины.
				if !bytes.Equal(cb.Body, blk) {
					return "", rep, fmt.Errorf("modelcompose: тип %q объявлен и каноном, и модулем %q, "+
						"а их блоки расходятся побайтово (канон %d Б, рендер %d Б) — канон "+
						"неприкосновенен, и расхождение обязано быть решено, а не сглажено",
						res.ObjectType, m.Module, len(cb.Body), len(blk))
				}
				rep.Reaffirmed = append(rep.Reaffirmed, res.ObjectType)
				continue
			}
			out.WriteString("\n")
			out.Write(blk)
			rep.Composed = append(rep.Composed, res.ObjectType)
			declared[res.ObjectType] = struct{}{}
		}
	}
	sort.Strings(rep.Composed)
	sort.Strings(rep.Reaffirmed)

	// НОРМА 4: мощность И множество разобранной модели.
	m, err := authzplan.ParseModel(out.String())
	if err != nil {
		return "", rep, fmt.Errorf("modelcompose: разбор собранной модели: %w", err)
	}
	if len(m.Types) != len(declared) {
		return "", rep, fmt.Errorf("modelcompose: мощность разобранной модели %d, "+
			"а объявлено типов %d (канон ∪ доставленные) — %s",
			len(m.Types), len(declared), rep.Census())
	}
	got := make(map[string]struct{}, len(m.Types))
	for _, t := range m.Types {
		got[t.Name] = struct{}{}
	}
	for name := range declared {
		if _, ok := got[name]; !ok {
			return "", rep, fmt.Errorf("modelcompose: тип %q объявлен, а в разобранной модели его нет — %s",
				name, rep.Census())
		}
	}
	for name := range got {
		if _, ok := declared[name]; !ok {
			return "", rep, fmt.Errorf("modelcompose: разобранная модель несёт тип %q, которого не объявлял "+
				"ни канон, ни доставка — %s", name, rep.Census())
		}
	}
	return out.String(), rep, nil
}
