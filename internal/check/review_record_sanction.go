// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// review_record_sanction.go — запись ревью с санкционирующим вердиктом и
// исполненным событием полномочия утверждает выданную санкцию
// (`effective_approval.issued: true`), а не молчит о ней и не отрицает её.
//
// # Предмет
//
// Санкцию выдаёт не запись, а ВНЕШНЕЕ событие полномочия. Запись ревью
// (`docs/specs/reviews/<документ>/<отпечаток>.yaml`) несёт три поля об одном
// состоянии: вердикт рецензента (`verdict`), исход события (`event.status`) и
// утверждение о санкции (`effective_approval.issued`). Когда вердикт выдаёт
// санкцию и событие исполнено, утверждение обязано быть `true`; иначе запись
// противоречит уже состоявшемуся событию, и верно в ней то поле, о котором
// никто не спрашивает.
//
// Наблюдалось (PRO-Robotech/kaname#302): две записи десять часов сорок восемь
// минут несли `verdict: APPROVED` при опубликованном событии и
// `issued: false`, ещё тридцать три минуты — с дописанным
// `event.status: performed` и прежним `issued: false`. Закрыто руками: заметить
// было нечем.
//
// # Сосед, которого этот гейт не повторяет
//
// `.github/scripts/review-event-silence.py` судит запись БЕЗ исполненного
// события против трекера и сам называет этот инвариант чужим предметом. Здесь
// читается только дерево: обе половины противоречия лежат в одной записи.
//
// # Законные формы — словари закрыты
//
// Вердикт, выдающий санкцию, записывается в каталоге двумя словами (`APPROVED`
// и `ACCEPT`: запись ACCEPT сама объявляет, что «выдаёт санкцию только вместе с
// внешним событием»). Слово вне обоих словарей — отказ разбора, а не молчание:
// распознаватель, не знающий формы, иначе пропускал бы её как «не санкцию».
// То же у исхода события.
//
// Расхождение называется ФОРМОЙ, в которой запись не утверждает санкцию: блока
// `effective_approval` нет; поля `issued` в блоке нет; `issued: null`;
// `issued: false`; `issued` не логическое значение. Все пять — находки: запись
// обязана НЕСТИ `issued: true`, а не только не отрицать его.
//
// # Чего не судит — и это печатается числом
//
// Обратное направление (`issued: true` без исполненного события) — иной
// инвариант с иным исходом (там запись может честно нести отступление решением
// диспетчера); его счёт печатается справочной величиной и в вердикт не входит.
// Второй дом записей (`docs/changes/*/reviews/acceptance/`) блока
// `effective_approval` не несёт by construction и предметом не является.
package check

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// ReviewRecordsDir — дом записей ревью приёмок, ОТ КОРНЯ своего модуля.
const ReviewRecordsDir = "docs/specs/reviews"

// reviewRecordKind — единственный вид записи в доме; иной вид — отказ разбора.
const reviewRecordKind = "acceptance_review"

// Формы, в которых запись НЕ утверждает выданную санкцию.
const (
	ReviewSanctionBlockAbsent  = "блока effective_approval нет"
	ReviewSanctionIssuedAbsent = "поля effective_approval.issued нет"
	ReviewSanctionIssuedNull   = "effective_approval.issued: null"
	ReviewSanctionIssuedFalse  = "effective_approval.issued: false"
	// ReviewSanctionIssuedNotBool — префикс: за ним следует литерал значения.
	ReviewSanctionIssuedNotBool = "effective_approval.issued не логическое значение"
)

// reviewSanctioningVerdicts — вердикты, выдающие санкцию вместе с событием.
var reviewSanctioningVerdicts = map[string]bool{"APPROVED": true, "ACCEPT": true}

// reviewOtherVerdicts — вердикты, санкции не выдающие ни при каком событии.
var reviewOtherVerdicts = map[string]bool{
	"CHANGES_REQUESTED": true, "RETURN": true, "RETURNED": true, "SUPERSEDED": true,
}

// reviewEventStatusPerformed — исход события, после которого санкция выдана.
const reviewEventStatusPerformed = "performed"

// reviewEventStatuses — закрытый словарь исхода события. Пустое значение —
// блок события без поля исхода: исполненным оно не является.
var reviewEventStatuses = map[string]bool{
	"": true, reviewEventStatusPerformed: true, "not_performed": true, "pending": true,
}

// ReviewSanctionFinding — запись, противоречащая исполненному событию.
type ReviewSanctionFinding struct {
	Record      string
	Verdict     string
	EventStatus string
	Form        string
}

func (f ReviewSanctionFinding) String() string {
	return fmt.Sprintf(
		"%s: verdict %s и event.status %s, а %s. Санкцию выдало исполненное событие "+
			"полномочия, и запись обязана утверждать её (`effective_approval.issued: true`): "+
			"иначе два её поля об одном состоянии противоречат друг другу. Исход — привести "+
			"effective_approval к факту события отдельным коммитом поверх записи",
		f.Record, f.Verdict, f.EventStatus, f.Form)
}

// ReviewSanctionCensus — объём осмотренного.
//
// «Расхождений 0» различимо с «прочитано 0» и с «судимых 0»: печатаются все
// величины, а не одна.
type ReviewSanctionCensus struct {
	Documents   int
	RecordsRead int
	OtherFiles  int
	// Judged — записи с санкционирующим вердиктом и исполненным событием.
	Judged int
	// Issued — из судимых несущие `issued: true`.
	Issued int
	// ByForm — расхождения по форме.
	ByForm map[string]int
	// IssuedWithoutEvent — справочно: `issued: true` без исполненного события.
	IssuedWithoutEvent int
}

func (c ReviewSanctionCensus) String() string {
	forms := make([]string, 0, len(c.ByForm))
	for k, v := range c.ByForm {
		forms = append(forms, fmt.Sprintf("%s — %d", k, v))
	}
	sort.Strings(forms)
	byForm := "нет"
	if len(forms) > 0 {
		byForm = strings.Join(forms, "; ")
	}
	return fmt.Sprintf(
		"документов %d · записей прочитано %d (прочих файлов %d) · санкционирующий вердикт "+
			"и исполненное событие %d · из них issued: true %d · расхождений %d (%s) · "+
			"справочно, вне предмета: issued: true без исполненного события %d",
		c.Documents, c.RecordsRead, c.OtherFiles, c.Judged, c.Issued,
		c.Judged-c.Issued, byForm, c.IssuedWithoutEvent)
}

// reviewSanctionDoc — поля записи, о которых судит гейт.
type reviewSanctionDoc struct {
	Kind    string `yaml:"kind"`
	Verdict string `yaml:"verdict"`
	Event   *struct {
		Status string `yaml:"status"`
	} `yaml:"event"`
	// EffectiveApproval — значением, а не указателем: только поле типа
	// yaml.Node получает узел разбора как есть; указатель на него декодер
	// разворачивает и раскладывает отображение по полям самого Node, теряя
	// содержимое блока.
	EffectiveApproval yaml.Node `yaml:"effective_approval"`
}

// issuedForm — форма утверждения о санкции; пустая строка — `issued: true`.
func issuedForm(ea *yaml.Node) string {
	if ea == nil || ea.Kind == 0 || ea.Tag == "!!null" {
		return ReviewSanctionBlockAbsent
	}
	if ea.Kind != yaml.MappingNode {
		return ReviewSanctionBlockAbsent
	}
	for i := 0; i+1 < len(ea.Content); i += 2 {
		if ea.Content[i].Value != "issued" {
			continue
		}
		v := ea.Content[i+1]
		switch {
		case v.Tag == "!!null":
			return ReviewSanctionIssuedNull
		case v.Tag == "!!bool" && strings.EqualFold(v.Value, "true"):
			return ""
		case v.Tag == "!!bool" && strings.EqualFold(v.Value, "false"):
			return ReviewSanctionIssuedFalse
		default:
			return fmt.Sprintf("%s (%s %q)", ReviewSanctionIssuedNotBool, v.Tag, v.Value)
		}
	}
	return ReviewSanctionIssuedAbsent
}

// AuditReviewRecordSanction — вердикт о доме записей ревью.
//
// Ошибка — исход «не выполнилось»: дом не прочитан, запись не разобрана либо
// несёт слово вне закрытого словаря. Пустой дом — тоже ошибка: «расхождений 0»
// там означало бы «ноль прочитанного».
func AuditReviewRecordSanction(root, dir string) ([]ReviewSanctionFinding, ReviewSanctionCensus, error) {
	census := ReviewSanctionCensus{ByForm: map[string]int{}}
	var findings []ReviewSanctionFinding

	abs := filepath.Join(root, filepath.FromSlash(dir))
	docs, err := os.ReadDir(abs)
	if err != nil {
		return nil, census, fmt.Errorf("дом записей ревью %s не прочитан: %w — «расхождений 0» "+
			"здесь означало бы «ноль прочитанного»", dir, err)
	}
	for _, d := range docs {
		if !d.IsDir() {
			census.OtherFiles++
			continue
		}
		census.Documents++
		entries, rerr := os.ReadDir(filepath.Join(abs, d.Name()))
		if rerr != nil {
			return nil, census, fmt.Errorf("%s/%s: %w", dir, d.Name(), rerr)
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
				census.OtherFiles++
				continue
			}
			rel := dir + "/" + d.Name() + "/" + e.Name()
			src, ferr := os.ReadFile(filepath.Join(abs, d.Name(), e.Name())) // #nosec G304 -- путь из обхода своего дерева
			if ferr != nil {
				return nil, census, fmt.Errorf("%s: %w", rel, ferr)
			}
			var doc reviewSanctionDoc
			if uerr := yaml.Unmarshal(src, &doc); uerr != nil {
				return nil, census, fmt.Errorf("%s: запись ревью не разбирается: %w", rel, uerr)
			}
			census.RecordsRead++
			if doc.Kind != reviewRecordKind {
				return nil, census, fmt.Errorf("%s: вид записи %q вне словаря (%s) — о санкции "+
					"такой записи гейт судить не умеет, и молчание о ней было бы слепой зоной",
					rel, doc.Kind, reviewRecordKind)
			}
			verdict := strings.TrimSpace(doc.Verdict)
			sanctioning := reviewSanctioningVerdicts[verdict]
			if !sanctioning && !reviewOtherVerdicts[verdict] {
				return nil, census, fmt.Errorf("%s: вердикт %q вне закрытого словаря — неизвестно, "+
					"выдаёт ли он санкцию, и пропустить его как «не санкцию» значило бы не "+
					"прочитать запись", rel, verdict)
			}
			status := ""
			if doc.Event != nil {
				status = strings.TrimSpace(doc.Event.Status)
			}
			if !reviewEventStatuses[status] {
				return nil, census, fmt.Errorf("%s: event.status %q вне закрытого словаря — "+
					"исполнено ли событие, неизвестно", rel, status)
			}
			form := issuedForm(&doc.EffectiveApproval)
			performed := status == reviewEventStatusPerformed
			if !performed || !sanctioning {
				if form == "" {
					census.IssuedWithoutEvent++
				}
				continue
			}
			census.Judged++
			if form == "" {
				census.Issued++
				continue
			}
			census.ByForm[form]++
			findings = append(findings, ReviewSanctionFinding{
				Record: rel, Verdict: verdict, EventStatus: status, Form: form,
			})
		}
	}
	if census.RecordsRead == 0 {
		return nil, census, fmt.Errorf("дом записей ревью %s: прочитано 0 записей (%s) — "+
			"«расхождений 0» здесь означало бы «ноль прочитанного»", dir, census)
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Record < findings[j].Record })
	return findings, census, nil
}
