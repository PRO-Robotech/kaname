// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// shadow_port.go — порт теневого сравнения и его место в решении о доступе.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ СРАВНЕНИЕ ЖИВЁТ ЗДЕСЬ, А НЕ В ОБРАБОТЧИКЕ
//
// Сравнивать надо ОКОНЧАТЕЛЬНЫЙ вердикт. Он складывается здесь: к ответу движка
// добавляются плоский надзор администратора облака и структурный запасной путь по
// собственным строкам — и только после них известно, что получит вызывающий.
// Сравнение, поставленное раньше этого места, сверяло бы форму E с ПОЛОВИНОЙ
// ответа и записывало расхождение там, где расходятся не формы, а стадии.
//
// Место одно и на все вопросы. Пока сравнение стояло у одного обработчика, оно
// покрывало один вопрос из тех, что сервис отвечает: остальные — перечисление
// объектов, перечисление субъектов, разворот отношений — уходили движку без
// спрашивающего, и «формы сходятся» читалось шире, чем было измерено. Здесь
// каждый вопрос проходит через свой `askShadow*`, а гейт
// `TestEveryEngineAskingQuestionAlsoAsksTheShadowForm` требует этого от кода,
// которого ещё нет.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ВОПРОС УХОДИТ ДО ДВИЖКА
//
// Теневой вопрос задаётся ПЕРЕД обращением к движку и не зависит ни от одного его
// исхода: ответ из кэша, короткое замыкание, недоступность — сравнение всё равно
// состоялось либо честно попало в «не выполнилось». Сравнение, начатое после
// ответа движка, молчит ровно там, где движок ответил дёшево, — то есть на самом
// частом пути, — и доля сравнённого становится неизвестной.
//
// Ответ вызывающему теневой путь не меняет НИ ПРИ КАКОМ исходе: сведение ничего
// не возвращает by construction, а срок у теневого вызова свой.

package service

import (
	"context"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authztypes"
)

// ShadowComparator — узкий порт теневого сравнения (реализуется
// `internal_iam/shadowverdict.Comparator`, провязывается композиционным корнем).
//
// Каждый `Ask*` задаёт вопрос форме E СЕЙЧАС и отдаёт сведение исхода; сведение
// обязано быть вызвано на КАЖДОМ пути — иначе теневой вызов остаётся висеть со
// своим сроком. Отсюда `defer` на всех местах вызова.
//
// engineAnswered=false означает «движок ответа не дал»: сравнивать не с чем, и
// исход идёт в отдельную корзину, а не в согласие.
type ShadowComparator interface {
	Ask(ctx context.Context, subject, objectType, objectID, relation string,
		condCtx map[string]any) func(engineAllowed, engineAnswered bool)
	AskObjects(ctx context.Context, subject, objectType string,
		relations []string) func(engineIDs []string, engineComplete, engineAnswered bool)
	AskSubjects(ctx context.Context, objectType, objectID,
		relation string) func(engineSubjects []string, engineComplete, engineAnswered bool)
	AskSources(ctx context.Context, objectType, objectID,
		relation string) func(engineGrounds []string, engineComplete, engineAnswered bool)
	// Decides — принимает ли решение по этому типу ФОРМА.
	//
	// Рубильник живёт в сравнителе — единственном значении, которое держат ОБЕ
	// поверхности решения (край и обёртка собственных стражей). Край через
	// обёртку не проходит: композиционный корень выдаёт ему голый транспорт, и
	// это записанное решение. Рубильник у каждой поверхности разошёлся бы, и
	// один вопрос об одном объекте получил бы два действующих источника.
	Decides(objectType string) bool
	// Verdict — вердикт ФОРМЫ по переключённому типу; движок спрашивается РЯДОМ.
	//
	// `askEngine` обязана отдавать ОКОНЧАТЕЛЬНЫЙ вердикт движковой композиции
	// этой поверхности — у края это ответ движка плюс плоский надзор
	// администратора облака плюс структурный запасной путь. Сравнивать половину
	// значило бы записывать расхождение между стадиями одного решения, а не
	// между формами.
	//
	// Ошибка — «форма не ответила»: недоступность вызывающему, никогда не отказ
	// в доступе и никогда не ответ движка.
	Verdict(ctx context.Context, subject, objectType, objectID, relation string,
		condCtx map[string]any,
		askEngine func(context.Context) (engineAllowed, engineAnswered bool)) (bool, error)
	// Unaskable отмечает решение, которое форме E задать нельзя (объект не
	// разобран, область не названа). Существует ради знаменателя: пропуск, не
	// попавший в число решений, делает долю сравнённого лучше, ничего не улучшив.
	Unaskable(reason, objectType, relation string)
}

// askShadow — прямой вердикт. Непровязанное сравнение отдаёт дешёвый no-op, а не
// заставляет каждое место решения нести свой `if`.
func (s *AuthorizeService) askShadow(ctx context.Context, subject, objectType, objectID, relation string,
	condCtx map[string]any) func(engineAllowed, engineAnswered bool) {
	if s.shadow == nil {
		return func(bool, bool) {}
	}
	return s.shadow.Ask(ctx, subject, objectType, objectID, relation, condCtx)
}

// askShadowObjects — перечисление объектов, доступных субъекту.
func (s *AuthorizeService) askShadowObjects(ctx context.Context, subject, objectType string,
	relations []string) func([]string, bool, bool) {
	if s.shadow == nil {
		return func([]string, bool, bool) {}
	}
	return s.shadow.AskObjects(ctx, subject, objectType, relations)
}

// askShadowSubjects — перечисление субъектов, имеющих отношение на объекте.
func (s *AuthorizeService) askShadowSubjects(ctx context.Context, objectType, objectID,
	relation string) func([]string, bool, bool) {
	if s.shadow == nil {
		return func([]string, bool, bool) {}
	}
	return s.shadow.AskSubjects(ctx, objectType, objectID, relation)
}

// askShadowSources — разворот: из чего складывается право на объекте.
func (s *AuthorizeService) askShadowSources(ctx context.Context, objectType, objectID,
	relation string) func([]string, bool, bool) {
	if s.shadow == nil {
		return func([]string, bool, bool) {}
	}
	return s.shadow.AskSources(ctx, objectType, objectID, relation)
}

// shadowUnaskable отмечает решение, которое форме E задать нельзя.
func (s *AuthorizeService) shadowUnaskable(reason, objectType, relation string) {
	if s.shadow == nil {
		return
	}
	s.shadow.Unaskable(reason, objectType, relation)
}

// expandTreeSubjects собирает субъектов, названных деревом разворота.
//
// Две формы называют основания по-разному: движок отдаёт дерево наборов, форма E
// — плоский перечень оснований с носителем. Сверяется то единственное, что обе
// называют одинаково: КОГО основание наделяет правом. Усечённое дерево не
// сверяется вовсе (complete=false) — согласие двух обрезанных ответов согласием
// не является.
func expandTreeSubjects(t *authztypes.ExpandTree) (subjects []string, complete bool) {
	if t == nil {
		return nil, true
	}
	seen := make(map[string]struct{})
	complete = true
	var walk func(*authztypes.ExpandTree)
	walk = func(n *authztypes.ExpandTree) {
		if n == nil {
			return
		}
		if n.Truncated {
			complete = false
		}
		for _, leaf := range n.Leaves {
			if _, ok := seen[leaf]; ok {
				continue
			}
			seen[leaf] = struct{}{}
			subjects = append(subjects, leaf)
		}
		for i := range n.Computed {
			walk(n.Computed[i].Subtree)
		}
		for i := range n.TupleToUserset {
			walk(n.TupleToUserset[i].Subtree)
		}
	}
	walk(t)
	return subjects, complete
}

// decidesByForm — переключён ли источник вердикта для этого типа.
//
// Непровязанное сравнение отвечает «нет»: источник, которого нет, решать не
// может, и это тождество, а не осторожность.
func (s *AuthorizeService) decidesByForm(objectType string) bool {
	return s.shadow != nil && s.shadow.Decides(objectType)
}
