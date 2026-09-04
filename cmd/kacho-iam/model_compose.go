// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"fmt"
	"log/slog"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmodel"
	"github.com/PRO-Robotech/kacho/services/iam/internal/manifest"
	"github.com/PRO-Robotech/kacho/services/iam/internal/modelcompose"
)

// model_compose.go — модель процесса СОБИРАЕТСЯ из доставленного, СУДИТСЯ и
// СТАВИТСЯ до первого чтения (задачи продукта #1969, #2002).
//
// # Порядок несущий, а не стилистический
//
//	чтение доставки → композиция → допуск → установка → всё остальное
//
// Каждое звено опирается на предыдущее, и переставить их нельзя ни в одну
// сторону. Композиция собирается ИЗ доставленных манифестов, поэтому идёт после
// чтения. Установка запрещена после первого чтения модели — она была бы тихой
// заменой, при которой один вызывающий уже принял решение о доступе по одной
// модели, а следующий примет по другой, — поэтому идёт ДО всего, что модель
// читает.
//
// Провязка стоит здесь, а не в звеньях: композиция не знает о допуске, допуск не
// знает о происхождении текста. Разделение несущее — допуск есть чистая функция
// от текста, и, смешав их, мы получили бы судью, знающего, что он судит своё.
//
// # Почему отказ ФАТАЛЕН на каждом звене
//
// Мягкого прохода не заводится: он дал бы контроль, который не откажет ни разу
// за свою жизнь (`security.md` §Hardening, п. 8), и дал бы его там, где
// расхождение снаружи выглядит как «прав не выдали» — то есть в классе, который
// диагностируют часами и не по логу.

// installComposedModel собирает модель процесса из доставленных манифестов,
// проводит её через допуск и ставит.
//
// Перепись обеих ступеней печатается ВСЕГДА, независимо от исхода: без неё
// «добавлено 0» неотличимо от «прочитано 0», а «находок 0» — от «судить не о
// чем».
func installComposedModel(logger *slog.Logger, manifests []*manifest.Manifest) error {
	composed, rep, err := modelcompose.Compose(authzmodel.DSL, manifests)
	logger.Info("перепись композиции модели прав",
		slog.Int("manifests_seen", rep.ManifestsSeen),
		slog.Int("resources_seen", rep.ResourcesSeen),
		slog.Int("canon_types", rep.CanonTypes),
		slog.Any("composed", rep.Composed),
		slog.Any("reaffirmed", rep.Reaffirmed))
	if err != nil {
		return fmt.Errorf("композиция модели прав: %w", err)
	}

	admission, err := authzmodel.Admit(composed)
	logger.Info("перепись допуска собранной модели",
		slog.String("census", admission.Census()),
		slog.Bool("admitted", admission.Admitted()))
	if err != nil {
		// Ошибка допуска означает «судить не о чем»: канон образа не разобрался
		// либо собранный текст не разобрался. Это НЕ «находок ноль» — отчёт при
		// ней несуждён и отвечает «не допущено» сам (#2000), но проверяется err
		// ПЕРВЫМ: он называет стадию, а отчёт её назвать не может.
		return fmt.Errorf("допуск собранной модели прав: %w", err)
	}

	// Исходов допуска ТРИ, и здесь законны два — но по разным причинам, поэтому
	// они и разведены, а не схлопнуты в `!Admitted()`.
	switch {
	case len(admission.Findings) > 0:
		// Находка — отказ ПУСКА. Перечисляются ВСЕ: названная первая заставила
		// бы оператора чинить их по одной, по выкатке на каждую.
		return fmt.Errorf("допуск собранной модели прав отверг её (%s):%s",
			admission.Census(), formatFindings(admission.Findings))
	case admission.NothingToJudge:
		// Доставка не добавила НИ ОДНОГО типа: судить некого. Для допуска это
		// третий исход и в успех не засчитывается — а здесь состояние законное
		// и обычное: доставка посадкой не объявлена либо её манифесты ресурсов
		// не несут. Модель процесса тогда равна канону образа, и ставится она
		// всё равно — явно, чтобы «поставлено» перестало зависеть от того, кто
		// первым спросил.
		logger.Info("доставка не добавила ни одного типа — модель процесса равна канону образа")
	}

	if err := authzmodel.Install(composed); err != nil {
		return fmt.Errorf("установка модели процесса: %w", err)
	}
	logger.Info("модель процесса установлена",
		slog.Int("types_seen", admission.TypesSeen),
		slog.Int("types_new", admission.TypesNew))
	return nil
}

// formatFindings — находки допуска списком, каждая со своей строки.
//
// Порядок берётся у допуска и НЕ пересортировывается: он детерминирован по
// правилам и координатам, а вторая сортировка сделала бы текст отказа функцией
// этой функции.
func formatFindings(findings []authzmodel.Finding) string {
	var b []byte
	for _, f := range findings {
		b = append(b, "\n\t"...)
		b = append(b, f.String()...)
	}
	return string(b)
}
