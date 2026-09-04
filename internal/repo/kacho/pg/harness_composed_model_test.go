// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// harness_composed_model_test.go — МОДЕЛЬ ПРОЦЕССА этого прогона собирается из
// доставки, как её собирает старт (задача продукта #1969).
//
// # Зачем харнессу вообще модель
//
// Вердикт (`relverdict.sourcesOf`) строит план вывода у `authzmodel.Shared()` —
// у модели ПРОЦЕССА. В поднятой службе её ставит композиционный корень:
// `cmd/kacho-iam/serve.go` зовёт `installComposedModel` между чтением доставки и
// первым читателем модели. Прогон проб этого пакета корня не поднимает, поэтому
// до сих пор модель процесса оставалась ВШИТЫМ КАНОНОМ, и тип, объявленный
// только манифестом, до вердикта не доезжал НИКОГДА — независимо от того, работает
// провязка в продукте или нет.
//
// Это делало пробу измерением ОБСТАНОВКИ, а не продукта: её красное и её зелёное
// говорили о харнессе. Здесь обстановка приводится к продуктовой.
//
// # Почему те же три шага, а не «просто поставить текст»
//
// Установка в обход допуска дала бы фикстуру СНИСХОДИТЕЛЬНЕЕ ПРОДУКТА: проба
// утверждала бы вердикт над моделью, которую продукт отказался бы пустить, —
// то есть доказывала бы работу цепи на входе, которого в проде не бывает.
// Поэтому шаги те же и в том же порядке: композиция → допуск → установка, и
// всякий отказ здесь ФАТАЛЕН, как он фатален на старте.
//
// Согласие этой последовательности с последовательностью корня держит ГЕЙТ
// (`TestHarnessComposesTheModelTheCompositionRootWouldInstall` ниже), а не этот
// комментарий: два места об одном предмете расходятся молча, и разошлись бы они
// ровно там, где корень обзаведётся четвёртым шагом, а харнесс — нет.
//
// # Что доставкой объявлено, а что нет
//
// Доставка харнесса — ОДИН синтетический модуль с одним ресурсом
// (`verdictAppliedResource`), тем самым, который проба последней мили применяет к
// каталогу. Манифесты дерева (`services/*/manifest.yaml`) сюда НЕ подаются
// намеренно: их типы канон уже объявляет, композиция подтвердила бы их побайтово
// и не добавила бы ни одного блока — то есть цена чтения девяти файлов была бы
// заплачена за ноль добавленного, а всякий дрейф рендера, который держит свой
// гейт (`make -C services/iam model-canon-check`), приезжал бы сюда красным
// прогоном ВСЕГО пакета.

import (
	"fmt"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmodel"
	"github.com/PRO-Robotech/kacho/services/iam/internal/manifest"
	"github.com/PRO-Robotech/kacho/services/iam/internal/modelcompose"
)

// harnessDelivery — доставка этого прогона.
//
// Объявлена функцией, а не переменной пакета: переменная считалась бы при
// инициализации пакета, то есть ДО того, как `TestMain` получит управление, и
// порядок «доставка → композиция → установка» перестал бы быть наблюдаемым.
func harnessDelivery() []*manifest.Manifest {
	return []*manifest.Manifest{probeManifest(verdictAppliedResource())}
}

// installHarnessComposedModel собирает модель процесса из доставки харнесса,
// проводит её через допуск и ставит.
//
// Порядок шагов и фатальность каждого повторяют композиционный корень
// (`cmd/kacho-iam/model_compose.go`, `installComposedModel`); согласие держит
// гейт, а не эта строка.
//
// Отчёты возвращаются ВМЕСТЕ с ошибкой: «добавлено 0» обязано быть отличимо от
// «прочитано 0», и вызывающий печатает перепись независимо от исхода.
func installHarnessComposedModel() (modelcompose.Report, authzmodel.AdmissionReport, error) {
	composed, rep, err := modelcompose.Compose(authzmodel.DSL, harnessDelivery())
	if err != nil {
		return rep, authzmodel.AdmissionReport{}, fmt.Errorf("композиция модели прав: %w", err)
	}

	admission, err := authzmodel.Admit(composed)
	if err != nil {
		return rep, admission, fmt.Errorf("допуск собранной модели прав: %w", err)
	}
	if len(admission.Findings) > 0 {
		return rep, admission, fmt.Errorf(
			"допуск собранной модели прав отверг её (%s): %v",
			admission.Census(), admission.Findings)
	}

	if err := authzmodel.Install(composed); err != nil {
		return rep, admission, fmt.Errorf("установка модели процесса: %w", err)
	}
	return rep, admission, nil
}
