// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

// image_published_revision.go — ПРОВЯЗКА СВЕРКИ ОПУБЛИКОВАННОГО ОБРАЗА
// (задача PRO-Robotech/kaname#429, п.1 предиката).
//
// # ПРЕДМЕТ
//
// Первый пункт предиката — «в реестре есть тег `<линия>-<8 знаков головы>`, и
// ревизия, прочитанная из файла в образе, равна голове» — до этой провязки
// держался ВНИМАНИЕМ: его перемеряли руками, один раз на голову, когда о нём
// вспоминали. Шаг сборки отвечает «отправлено» и только: что под тегом лежит в
// реестре и из какого дерева оно собрано, он не спрашивает.
//
// Теперь спрашивает само задание образа: после отправки сверка
// (`ImagePublishedRevisionScript`) читает индекс тега у реестра и файл ревизии у
// каждой платформы. Как она это делает и почему так — в шапке самой сверки; её
// способность упасть доказывает её собственная самопроверка (`--self-test`).
//
// # ЧТО СУДИТ ЭТОТ ГЕЙТ — то, что ломается МОЛЧА
//
// Не работу сверки, а то, что она ОСТАЁТСЯ ЗВАНОЙ И СПРАШИВАЕТ О ТОМ, ЧТО
// ОПУБЛИКОВАНО:
//
//  1. сверку зовут — снятый шаг не краснеет, процесс идёт как шёл;
//  2. её самопроверку зовут безусловно и ДО неё — сверка, потерявшая
//     способность упасть, молчит так же, как исправная на верном образе;
//  3. сверка стоит ПОСЛЕ сборки — до неё спрашивать реестр не о чем;
//  4. условие сверки — условие ПУБЛИКАЦИИ, тем же выражением: без условия она
//     спросит реестр об образе, которого не отправляли (запрос на слияние и
//     ветка задачи собирают без публикации), и покрасит прогон ложной находкой;
//     с условием уже публикации — промолчит там, где образ ушёл в реестр;
//  5. ссылка, ревизия и набор платформ у сверки — ТЕ ЖЕ выражения, что у шага
//     сборки. Два объявления одной величины расходятся молча: тег поправят у
//     сборки, а сверка продолжит спрашивать о прежнем.
//
// # ЧЕГО ГЕЙТ НЕ ЗНАЕТ — сказано прямо
//
// Что реестр отвечает так, как отвечает двойник самопроверки, дерево не знает:
// это знает прогон по `push` на линии. Выражения `${{ … }}` сравниваются
// текстом после нормализации пробелов, а не вычисляются: равенство текста —
// достаточное условие равенства значений, но не необходимое, и законная
// перезапись того же выражения другими словами будет названа расхождением.
// Эта цена принята: второе написание одной величины и есть то, что здесь ловится.

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// ImagePublishedRevisionScript — сверка опубликованного образа. ОДНО объявление
// координаты: вторая копия разошлась бы с первой молча.
const ImagePublishedRevisionScript = ".github/scripts/image-published-revision.sh"

// ImageProducerJob — задание, производящее и публикующее образ.
const ImageProducerJob = "image"

// ImagePublishCondition — условие публикации. Его же несёт флаг отправки шага
// сборки (это проверяется как предпосылка), и им же обязана быть условлена
// сверка.
const ImagePublishCondition = "steps.gate.outputs.push == 'true'"

// imagePublishedArgs — доводы сверки в том порядке, в каком она их принимает.
const imagePublishedArgs = `"$IMAGE_REF" "$REVISION" "$PLATFORMS"`

// imagePublishedEnv — величины, которыми сверка обязана совпасть со сборкой.
var imagePublishedEnv = []string{"IMAGE_REF", "REVISION", "PLATFORMS"}

// imageProducerDoc — то немногое из объявления, что нужно этому гейту.
type imageProducerDoc struct {
	Jobs map[string]struct {
		Steps []struct {
			ID   string            `yaml:"id"`
			Name string            `yaml:"name"`
			If   string            `yaml:"if"`
			Run  string            `yaml:"run"`
			Env  map[string]string `yaml:"env"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
}

// ImagePublishedCensus — объём осмотренного: «ноль находок» обязано быть
// отличимо от «ноль прочитанного».
type ImagePublishedCensus struct {
	// Steps — шагов в задании образа; Build — номер шага сборки (с нуля).
	Steps int
	Build int
	// Checks, SelfTests — шагов, зовущих сверку и её самопроверку.
	Checks    int
	SelfTests int
	// EnvCompared — величин, сверенных с шагом сборки (по всем шагам сверки).
	EnvCompared int
}

// String — перепись одной строкой.
func (c ImagePublishedCensus) String() string {
	return fmt.Sprintf("шагов задания %q %d · сборка — шаг %d · шагов сверки %d · "+
		"шагов самопроверки %d · величин сверено со сборкой %d",
		ImageProducerJob, c.Steps, c.Build, c.Checks, c.SelfTests, c.EnvCompared)
}

// normalizeExpr — выражение условия без обёртки `${{ … }}` и с одним пробелом
// между словами: провайдер принимает обе записи, и различие написания не есть
// различие условия.
func normalizeExpr(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "${{") && strings.HasSuffix(s, "}}") {
		s = strings.TrimSpace(s[3 : len(s)-2])
	}
	return strings.Join(strings.Fields(s), " ")
}

// AuditImagePublishedRevision — вердикт о провязке сверки опубликованного.
//
// Вынесено ЧИСТОЙ функцией от текста объявления затем, чтобы способность гейта
// упасть доказывалась подачей входа, а не чтением. Ошибка — предпосылка ложна
// (вердикт беспредметен); находки — провязка нарушена.
func AuditImagePublishedRevision(raw string) ([]string, ImagePublishedCensus, error) {
	census := ImagePublishedCensus{Build: -1}
	var doc imageProducerDoc
	if err := yaml.Unmarshal([]byte(raw), &doc); err != nil {
		return nil, census, fmt.Errorf("объявление процесса не разобрано: %w", err)
	}
	job, ok := doc.Jobs[ImageProducerJob]
	if !ok {
		return nil, census, fmt.Errorf("предпосылка ложна: задания %q в объявлении нет — "+
			"сверять провязку не у чего", ImageProducerJob)
	}
	census.Steps = len(job.Steps)

	for i, st := range job.Steps {
		if strings.Contains(executableLines(st.Run), "docker buildx build") {
			if census.Build >= 0 {
				return nil, census, fmt.Errorf("предпосылка ложна: шагов сборки два (%d и %d) — "+
					"с каким из них сверять величины, не установлено", census.Build, i)
			}
			census.Build = i
		}
	}
	if census.Build < 0 {
		return nil, census, fmt.Errorf("предпосылка ложна: в задании %q нет шага сборки "+
			"(`docker buildx build` в исполняемой части) — сверке нечего сопоставлять", ImageProducerJob)
	}
	build := job.Steps[census.Build]
	for _, k := range imagePublishedEnv {
		if strings.TrimSpace(build.Env[k]) == "" {
			return nil, census, fmt.Errorf("предпосылка ложна: у шага сборки нет величины %s — "+
				"сверять её не с чем", k)
		}
	}
	// ПРЕДПОСЫЛКА: публикацию решает именно это условие. Иначе требование
	// «сверка условлена публикацией» сравнивало бы её с чужим условием.
	if !strings.Contains(normalizeExpr(build.Env["PUSH_FLAG"]), ImagePublishCondition) {
		return nil, census, fmt.Errorf("предпосылка ложна: флаг отправки шага сборки "+
			"(`PUSH_FLAG`) не условлен выражением %q — чем решается публикация, этот гейт "+
			"не знает", ImagePublishCondition)
	}

	var findings []string
	firstCheck := -1
	for i, st := range job.Steps {
		body := executableLines(st.Run)
		if !strings.Contains(body, ImagePublishedRevisionScript) {
			continue
		}
		where := fmt.Sprintf("шаг %d «%s»", i, st.Name)
		if strings.Contains(body, "--self-test") {
			census.SelfTests++
			if strings.TrimSpace(st.If) != "" {
				findings = append(findings, fmt.Sprintf("%s: самопроверка сверки условна (`if: %s`) — "+
					"там, где условие ложно, сверка выносит вердикт, не доказав, что способна упасть",
					where, st.If))
			}
			if firstCheck >= 0 {
				findings = append(findings, fmt.Sprintf("%s: самопроверка стоит ПОСЛЕ сверки (шаг %d) — "+
					"её молчанию поверили раньше, чем доказали, что оно что-то значит", where, firstCheck))
			}
			continue
		}

		census.Checks++
		if firstCheck < 0 {
			firstCheck = i
		}
		if i < census.Build {
			findings = append(findings, fmt.Sprintf("%s: сверка стоит ДО сборки (шаг %d) — реестр "+
				"спрашивают о том, чего ещё не отправили", where, census.Build))
		}
		switch got := normalizeExpr(st.If); {
		case got == "":
			findings = append(findings, fmt.Sprintf("%s: сверка без условия публикации — на запросе "+
				"слияния и на ветке задачи она спросит реестр об образе, которого не отправляли, "+
				"и покрасит прогон ложной находкой. Нужно `if: %s`", where, ImagePublishCondition))
		case got != ImagePublishCondition:
			findings = append(findings, fmt.Sprintf("%s: условие сверки «%s» разошлось с условием "+
				"публикации «%s» — где они расходятся, сверка либо спрашивает о неотправленном, "+
				"либо молчит об отправленном", where, got, ImagePublishCondition))
		}
		for _, k := range imagePublishedEnv {
			census.EnvCompared++
			if a, b := normalizeExpr(st.Env[k]), normalizeExpr(build.Env[k]); a != b {
				findings = append(findings, fmt.Sprintf("%s: сверяется не то, что собрано — %s у сверки "+
					"«%s», у сборки «%s». Два объявления одной величины расходятся молча", where, k, a, b))
			}
		}
		if !strings.Contains(body, ImagePublishedRevisionScript+" "+imagePublishedArgs) {
			findings = append(findings, fmt.Sprintf("%s: сверка зовётся не с доводами %s — "+
				"она спросит не о том теге, не о той ревизии или не о тех платформах",
				where, imagePublishedArgs))
		}
	}

	if census.Checks == 0 {
		findings = append(findings, fmt.Sprintf("сверки опубликованного НЕТ: ни один шаг задания %q "+
			"не зовёт %s с доводами — есть ли тег в реестре и та ли под ним ревизия, снова держится "+
			"вниманием (п.1 предиката #429)", ImageProducerJob, ImagePublishedRevisionScript))
	}
	if census.SelfTests == 0 {
		findings = append(findings, fmt.Sprintf("самопроверка %s --self-test не зовётся: сверка, "+
			"потерявшая способность упасть, молчит так же, как исправная на верном образе",
			ImagePublishedRevisionScript))
	}
	return findings, census, nil
}
