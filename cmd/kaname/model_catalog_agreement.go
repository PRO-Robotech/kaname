// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// model_catalog_agreement.go — шаг корня старта «модель против каталога»
// (kaname#865, приёмка `module-manifest-revision-only-moves-forward.md`, Д10,
// производитель P17).
//
// # Зачем
//
// Композиция модели процесса (`installComposedModel`) идёт РАНЬШЕ применителя
// каталога и собирает модель из ВСЕЙ доставки: тип, которого канон образа не
// объявляет (тип вне канона), получает блок, отрендеренный из документа
// доставки, — в том числе отношение `public_reader` по признаку контейнера.
// Применитель каталога тот же документ может пропустить как младшую редакцию
// либо отвергнуть конфликтом содержимого. Тогда каталог говорит одно, а модель
// процесса решает о доступе по документу, который каталог отверг.
//
// Шаг останавливает пуск, если хоть один не применённый модуль принёс в модель
// процесса тип вне канона. Не применённый модуль без таких типов пуск не
// останавливает: все его типы модель берёт из канона образа, и от документа
// она не зависит.
//
// # Ожидаемый отказ, который легко прочесть как ложный
//
// Шаг останавливает пуск и тогда, когда пропущенный документ несёт ТЕ ЖЕ блоки,
// что и применённый (доставка откачена к прежней редакции того же
// содержимого, например `R(3, true)` после `R(5, true)`). Это следствие
// решения: шаг судит происхождение модели (документ, который каталог отверг), а
// не равенство блоков. Выход у оператора один — доставить редакцию не меньше
// применённой либо новую большую.
//
// # Место
//
// Сразу за применителем каталога и ДО стража паритета, применителей ролей и
// посева: исход редакции становится известен только под замком каталога, роли
// и посев пишут, а страж назвал бы расхождение каталога, а не причину. Шаг
// операторов базы не добавляет — он сверяет в памяти перечень не применённых с
// отнесением типов композиции. Порядок и происхождение доводов держит гейт
// `model_catalog_agreement_wiring_test.go`, а не этот комментарий.

import (
	"errors"
	"log/slog"
	"strconv"
	"strings"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	"github.com/PRO-Robotech/kaname/internal/modelcompose"
)

// assertModelAgreesWithCatalog — шаг Д10. notApplied — модули, которые
// применитель каталога пропустил либо отверг, в порядке доставки; composed —
// отчёт ТОЙ композиции, которую корень поставил.
//
// Отказ — по строке на каждый такой модуль с типами вне канона, в порядке
// доставки (текст Д7). Перепись печатается ВСЕГДА: «не применённых 0» и «судить
// не о чем» иначе неразличимы.
func assertModelAgreesWithCatalog(
	logger *slog.Logger,
	notApplied []modulecatalog.RevisionSkip,
	composed modelcompose.Report,
) error {
	var lines []string
	for _, s := range notApplied {
		types := composed.ComposedOf(s.Module)
		if len(types) == 0 {
			continue
		}
		lines = append(lines, modelCatalogRefusalLine(s, types))
	}
	logger.Info("перепись шага модели доступа против каталога",
		slog.Int("not_applied", len(notApplied)),
		slog.Int("composed_types", len(composed.Composed)),
		slog.Int("refused_modules", len(lines)))
	if len(lines) == 0 {
		return nil
	}
	return errors.New(strings.Join(lines, "\n"))
}

// modelCatalogRefusalLine — строка отказа одного модуля (текст Д7). types
// отсортированы композицией по байтам имени.
func modelCatalogRefusalLine(s modulecatalog.RevisionSkip, types []string) string {
	var b strings.Builder
	b.WriteString("модель доступа: модуль ")
	b.WriteString(s.Module)
	b.WriteString(" каталог не применил — доставлена редакция ")
	b.WriteString(editionText(s.Declared))
	b.WriteString(", применена ")
	b.WriteString(editionText(s.Previous))
	b.WriteString("; его типы вне канона ")
	b.WriteString(strings.Join(types, ", "))
	b.WriteString(" собраны в модель процесса из этого документа — модель доступа не может быть собрана " +
		"из документа, который каталог отверг")
	return b.String()
}

// editionText — номер и отпечаток пары; пары нет — «не объявлена»: отпечаток
// без номера ничего не сравнивает (Д5). У не применённого модуля применённая
// пара есть всегда (решатель редакции иначе не пропускает и не отвергает), и
// ветка `nil` для неё недостижима; она пишет то же слово, а не ноль.
func editionText(e *modulecatalog.Edition) string {
	if e == nil {
		return "не объявлена"
	}
	return strconv.FormatInt(e.Revision, 10) + " (отпечаток " + e.Digest + ")"
}
