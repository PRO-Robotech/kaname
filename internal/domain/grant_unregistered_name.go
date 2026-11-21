// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

// WithoutOrdinaryResourceName не считает ссылку bind_role регистрацией зеркала.
// Снятие самой роли обслуживает FK/lifecycle producer. При смешанном правиле
// сужается только ordinary часть, meta ссылка сохраняется (kaname#1034).
func (rs Rules) WithoutOrdinaryResourceName(typ, id string) (Rules, int, bool) {
	apply := func(keepOrdinary bool) (Rules, int, bool) {
		var out Rules
		removed := 0
		changed := false
		for _, r := range rs {
			ordinary, caps, err := SplitGrantCapabilityRules(Rules{r})
			if err != nil || len(caps) == 0 {
				// kaname#1034: общий fallback запрещает split и ordinary ветви.
				next, n, hit := Rules{r}.withoutResourceName(typ, id, keepOrdinary)
				out = append(out, next...)
				removed += n
				changed = changed || hit
				continue
			}
			next, _, hit := ordinary.WithoutResourceName(typ, id)
			if !hit {
				out = append(out, cloneGrantRule(r))
				continue
			}
			changed = true
			if keepOrdinary {
				out = append(out, next...)
			}
			// Валидное meta правило не имеет children/labels/creator. Create и bind
			// с именами одновременно запрещены Split, поэтому здесь одна meta часть.
			meta := cloneGrantRule(r)
			if caps[0].Kind == GrantCapabilityBindRole {
				meta.Resources = []string{"role"}
				meta.Verbs = []string{"bind"}
			} else {
				meta.Resources = []string{"accessBinding"}
				meta.Verbs = []string{"create"}
			}
			out = append(out, meta)
		}
		return out, removed, changed
	}
	out, n, hit := apply(true)
	if len(out) > MaxRules {
		return apply(false)
	}
	return out, n, hit
}
