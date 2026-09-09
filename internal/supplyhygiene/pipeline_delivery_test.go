// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// pipeline_delivery_test.go — поставка несёт СВОЙ конвейер, и он разбираем.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Дерево службы живёт в монорепо, а посторонний достаёт её из отдельного
// репозитория: производитель поставки кладёт туда ровно `services/iam` и
// утверждает равенство наборов файлов. Значит всё, чего в этом дереве нет, в
// поставку НЕ ПОПАДАЕТ — и конвейера в нём не было. Он существовал в
// единственном экземпляре, отдельной веткой репозитория артефакта, у которой со
// стволом не оказалось даже общего предка; поставка была воспроизводима по коду
// и невоспроизводима по своей проверке (#2150).
//
// Конвейер лежит здесь именно затем, чтобы ехать вместе с деревом. В монорепо он
// НЕ ИСПОЛНЯЕТСЯ: провайдер читает объявления процессов только в `.github/workflows`
// КОРНЯ репозитория, а этот путь лежит на два уровня глубже. Ранеров он не занимает
// и вторых прогонов не создаёт.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЗАЧЕМ ГЕЙТ, А НЕ ОДНО РАЗМЕЩЕНИЕ
//
// Каталог, который в своём репозитории ничего не запускает, выглядит мёртвым
// ассетом — а мёртвое дерево вычищают. Снятие вернуло бы ровно тот дефект,
// который этим изменением закрыт, и вернуло бы ТИХО: поставка продолжала бы
// собираться, а проверки у неё просто не стало бы. Правило без механизма есть
// пожелание, поэтому предмет удержан утверждением, а не комментарием.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ИМЕННО УТВЕРЖДАЕТСЯ — три оси, и каждая закрывает свой отказ
//
//  1. ПРИСУТСТВИЕ. Объявление процесса и все файлы, которые оно зовёт, лежат в
//     дереве службы. Снятие любого — находка.
//  2. РАЗБИРАЕМОСТЬ. Объявление разбирается и несёт хотя бы одно задание.
//     Неразбираемое объявление даёт НОЛЬ прогонов, а ноль прогонов на запросе
//     слияния читается как «замечаний нет».
//  3. МАШИНОЧИТАЕМОСТЬ ИДЕНТИФИКАТОРА (ban #17). Ключ под `jobs:` и `id` шага —
//     латиница; подпись `name:` и комментарий кириллицей ЗАКОННЫ и под запрет не
//     подпадают. Кириллический ключ разбирается как YAML и отвергается
//     ПРОВАЙДЕРОМ: объявление не читается целиком, задания не исполняются вовсе.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ЭТО ВТОРОЕ МЕСТО ОБ ОДНОМ ПРЕДМЕТЕ — и почему иначе нельзя
//
// Ось 3 повторяет правило гейта монорепо `TestWorkflowJobAndStepIdentifiersAreMachineReadable`.
// Повтор вынужден границей модуля, а не выбран: служба — САМОСТОЯТЕЛЬНЫЙ модуль
// (`github.com/PRO-Robotech/kaname`), она не вправе импортировать `internal/`
// платформы, и её самодостаточность держится соседней пробой этого же пакета.
// Импорт был бы прямым её нарушением.
//
// Обойтись без повтора можно было бы, расширив обход того гейта: он собирает
// перечень через `os.ReadDir(".github/workflows")` КОРНЯ, поэтому конвейер
// службы для него невидим by construction — классическая слепая зона
// распознавателя, выросшая вместе с популяцией. Расширение затронуло бы все
// гейты, делящие тот обход, и часть их требований к объявлению корня для
// поставки неверна (сужение триггера по ветке: артефакт законно срабатывает на
// СВОЁМ стволе). Это отдельный предмет со своим замером и своей задачей;
// здесь он не решается, а называется.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕГО ЭТА ПРОВЕРКА НЕ ЗАКРЫВАЕТ — сказано прямо
//
// Она судит ОБЪЯВЛЕНИЕ, а не исход: разбираемость провайдером доказывается
// прогоном на площадке, а не чтением. Существование координат, которые конвейер
// называет, здесь НЕ утверждается: предикат «координата обязана резолвиться»
// был прототипирован на этом же конвейере и дал 4 ложные находки из 5 —
// названия действий, имя организации и путь монорепо в объяснительном
// комментарии координатами дерева не являются. Прибор, у которого находки
// ложные, перестают читать; поэтому ось не заведена, а не «заведена помягче».
package supplyhygiene

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"testing"

	"gopkg.in/yaml.v3"
)

// deliveredWorkflow — объявление процесса относительно корня службы.
const deliveredWorkflow = ".github/workflows/ci.yml"

// deliveredPipelineFiles — всё, что поставка обязана нести, чтобы конвейер
// исполнился у постороннего. Перечень ВЫПИСАН, а не выведен обходом: обход
// каталога отвечает «что там лежит», а вопрос здесь обратный — «чего не хватает».
// Пустой каталог обход прошёл бы молча.
var deliveredPipelineFiles = []string{
	deliveredWorkflow,
	".github/golangci.yml",
	".github/scripts/classify-integration-outcome.sh",
	".github/scripts/go-test-verdict.py",
	".github/scripts/gosec-gate.sh",
	".github/scripts/run-integration.sh",
}

// deliveredIdentifierForm — машиночитаемая форма идентификатора задания и шага.
var deliveredIdentifierForm = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]*$`)

// pipelineCensus — объём осмотренного: «ноль находок» обязано быть отличимо от
// «ноль прочитанного», а «ноль заданий» — от «разбор не дошёл до `jobs:`».
type pipelineCensus struct {
	filesWanted int
	filesFound  int
	jobs        int
	stepIDs     int
}

// scanDeliveredPipeline — разбор над ПРОИЗВОЛЬНЫМ корнем. Вынесено из пробы
// затем, чтобы способность гейта упасть доказывалась подачей входа, а не
// чтением.
func scanDeliveredPipeline(root string) (pipelineCensus, []string) {
	census := pipelineCensus{filesWanted: len(deliveredPipelineFiles)}
	var findings []string

	for _, rel := range deliveredPipelineFiles {
		info, err := os.Stat(filepath.Join(root, rel))
		switch {
		case err != nil:
			findings = append(findings, rel+": поставка его НЕ несёт — "+
				"производитель кладёт в артефакт ровно дерево службы, поэтому отсутствующее здесь "+
				"не попадает к постороннему вовсе, и конвейер остаётся без предмета (#2150)")
			continue
		case info.Size() == 0:
			findings = append(findings, rel+": файл пуст — присутствие имени не есть присутствие содержимого")
			continue
		}
		census.filesFound++
	}

	raw, err := os.ReadFile(filepath.Join(root, deliveredWorkflow))
	if err != nil {
		sort.Strings(findings)
		return census, findings
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		findings = append(findings, deliveredWorkflow+": не разобран YAML: "+err.Error()+
			" — объявление НЕ проверено, а у провайдера оно дало бы ноль прогонов")
		sort.Strings(findings)
		return census, findings
	}

	body := &doc
	if doc.Kind == yaml.DocumentNode && len(doc.Content) > 0 {
		body = doc.Content[0]
	}
	jobs := pipelineMappingValue(body, "jobs")
	if jobs == nil || jobs.Kind != yaml.MappingNode {
		findings = append(findings, deliveredWorkflow+": заданий не объявлено ни одного — "+
			"объявление без `jobs:` создаёт прогон, который ничего не проверяет")
		sort.Strings(findings)
		return census, findings
	}

	for i := 0; i+1 < len(jobs.Content); i += 2 {
		key, job := jobs.Content[i], jobs.Content[i+1]
		census.jobs++
		if !deliveredIdentifierForm.MatchString(key.Value) {
			findings = append(findings, pipelineIdentifierFinding(key.Line, "задания", key.Value))
		}
		if job == nil || job.Kind != yaml.MappingNode {
			continue
		}
		steps := pipelineMappingValue(job, "steps")
		if steps == nil || steps.Kind != yaml.SequenceNode {
			continue
		}
		for _, step := range steps.Content {
			if step.Kind != yaml.MappingNode {
				continue
			}
			id := pipelineMappingValue(step, "id")
			if id == nil || id.Kind != yaml.ScalarNode {
				continue
			}
			census.stepIDs++
			if !deliveredIdentifierForm.MatchString(id.Value) {
				findings = append(findings, pipelineIdentifierFinding(id.Line, "шага", id.Value))
			}
		}
	}

	sort.Strings(findings)
	return census, findings
}

// pipelineIdentifierFinding — текст находки. Называет предмет прямо: сообщение
// падения есть описание защищаемого свойства, и выхолащивать его нельзя —
// непонятную проверку следующий читатель снимет.
func pipelineIdentifierFinding(line int, what, id string) string {
	return deliveredWorkflow + ":" + strconv.Itoa(line) + ": идентификатор " + what + " `" + id +
		"` вне машиночитаемой формы " + deliveredIdentifierForm.String() + ". Провайдер проверяет " +
		"форму ДО исполнения: объявление с таким ключом не разбирается ЦЕЛИКОМ, поэтому прогон " +
		"получает ноль заданий, а поле `name` в ответе API приходит путём к файлу. Переименуй КЛЮЧ " +
		"латиницей — подпись `name:` и комментарий рядом под запрет не подпадают (ban #17)"
}

// pipelineMappingValue — значение по ключу отображения, либо nil.
func pipelineMappingValue(mapping *yaml.Node, key string) *yaml.Node {
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			return mapping.Content[i+1]
		}
	}
	return nil
}

func TestDeliveryCarriesItsOwnPipeline(t *testing.T) {
	t.Parallel()

	census, findings := scanDeliveredPipeline(serviceRoot)

	t.Logf("перепись: файлов конвейера требуется %d · найдено %d · заданий осмотрено %d · "+
		"шагов с объявленным id %d · находок %d",
		census.filesWanted, census.filesFound, census.jobs, census.stepIDs, len(findings))

	// Пустой обход — поломка гейта, а не чистота дерева.
	if census.filesWanted == 0 {
		t.Fatal("перечень файлов конвейера пуст — гейту нечего требовать, вердикт беспредметен")
	}

	for _, f := range findings {
		t.Error(f)
	}

	// Утверждение отдельно от находок: перечень выше говорит о НЕДОСТАЮЩЕМ, а это —
	// о том, что разбор вообще дошёл до заданий.
	if len(findings) == 0 && census.jobs == 0 {
		t.Fatal("находок ноль и заданий осмотрено ноль — разбор не дошёл до `jobs:`, " +
			"и зелёное здесь означало бы «ноль прочитанного», а не «ноль находок»")
	}
}
