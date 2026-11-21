// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package grantcoverage

// Prove проверяет ВСЕ входные эффекты до включения. Неизвестный эффект даже
// в actor не исчезает из входа; это консервативный отказ только coverage-ветки.
// Срезы и карты принадлежат вызывающему и не изменяются. Параллельная запись
// вызывающего в них запрещена обычным контрактом Go.
func Prove(req Request) Result {
	if r := validate(req); r.Status != Proved {
		return r
	}
	if len(req.Proposed.Effects) == 0 {
		if req.Empty != ProveEmpty {
			return failure(NotProved, ReasonEmpty, ProposedSide, -1)
		}
		return success()
	}
	b := workBudget{remaining: MaxProofSteps}
	for i, wanted := range req.Proposed.Effects {
		// Конечное множество можно покрыть объединением разных атомов.
		// Для бесконечного региона нужен один доказанно более широкий терм;
		// перечисление сегодняшних объектов ничего о будущем не доказывает.
		if wanted.Kind == ResourceUse && wanted.Resource.Region.Objects.Kind == ObjectIDs {
			for _, id := range wanted.Resource.Region.Objects.IDs {
				if !covered(req.Actor.Effects, wanted, id, &b) {
					return uncovered(i, b.exhausted)
				}
			}
		} else if !covered(req.Actor.Effects, wanted, "", &b) {
			return uncovered(i, b.exhausted)
		}
	}
	return success()
}

func covered(actor []Effect, wanted Effect, id string, b *workBudget) bool {
	for _, held := range actor {
		if !b.take() {
			return false
		}
		if held.Kind != wanted.Kind || held.Anchor != wanted.Anchor {
			continue
		}
		switch wanted.Kind {
		case CreateBinding:
			return true
		case BindRole:
			if held.RoleID == wanted.RoleID {
				return true
			}
		case ResourceUse:
			h, w := held.Resource, wanted.Resource
			if h.Module != w.Module || h.Type != w.Type || !actionCovers(h.Action, w.Action) {
				continue
			}
			if regionCovers(h.Region, w.Region, id, b) {
				return true
			}
		}
		if b.exhausted {
			return false
		}
	}
	return false
}

func actionCovers(held, wanted Action) bool {
	return held == wanted || held.Kind == AllVerbs && wanted.Kind == Verb
}

func regionCovers(held, wanted Region, id string, b *workBudget) bool {
	if held.Objects.Kind == ObjectIDs {
		if wanted.Objects.Kind != ObjectIDs {
			return false
		}
		found := false
		for _, candidate := range held.Objects.IDs {
			if !b.take() {
				return false
			}
			if candidate == id {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if held.Creator.Kind == ExactCreator &&
		(wanted.Creator.Kind != ExactCreator || held.Creator.Subject != wanted.Creator.Subject) {
		return false
	}
	// Импликация wanted ⇒ held: каждое равенство actor обязано быть у wanted.
	if !b.takeN(len(held.Labels)) {
		return false
	}
	for key, value := range held.Labels {
		if actual, exists := wanted.Labels[key]; !exists || actual != value {
			return false
		}
	}
	return true
}

type workBudget struct {
	remaining int
	exhausted bool
}

func (b *workBudget) take() bool { return b.takeN(1) }
func (b *workBudget) takeN(n int) bool {
	if n > b.remaining {
		b.exhausted = true
		return false
	}
	b.remaining -= n
	return true
}
func uncovered(index int, exhausted bool) Result {
	if exhausted {
		return failure(NotProved, ReasonWorkLimit, ProposedSide, index)
	}
	return failure(NotProved, ReasonUncovered, ProposedSide, index)
}
func failure(status Status, reason Reason, side Side, index int) Result {
	return Result{Status: status, Reason: reason, Side: side, Index: index}
}
func success() Result { return Result{Status: Proved, Index: -1} }
