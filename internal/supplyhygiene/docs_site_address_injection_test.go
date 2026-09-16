// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// docs_site_address_injection_test.go — доказательство, что гейт адреса сайта
// СПОСОБЕН упасть и способен СМОЛЧАТЬ.
//
// Инъекция подаёт вход, а не читает код. Каждый отрицательный случай меняет
// РОВНО ОДИН факт против своего положительного близнеца. Мир строится КОПИЕЙ
// настоящей конфигурации службы, а не выдумывается: синтетика, собранная из
// частей, доказывает работу механизма на синтетике.
package supplyhygiene

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/refusaldomain"
)

// docsSiteLiveURL — строка адреса, как она стоит в дереве. Предмет одно-фактных
// правок ниже.
const docsSiteLiveURL = "  url: 'https://iam.kaname.cloud',"

func docsSiteWorld(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	raw, err := os.ReadFile(filepath.Join(serviceRoot, docsSiteConfig))
	if err != nil {
		t.Fatalf("предпосылка инъекции не выполняется: %s не прочитан: %v", docsSiteConfig, err)
	}
	dst := filepath.Join(root, docsSiteConfig)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatalf("каталог не заведён: %v", err)
	}
	if err := os.WriteFile(dst, raw, 0o644); err != nil {
		t.Fatalf("файл не записан: %v", err)
	}
	return root
}

// docsSiteSubst — ОДНА текстовая подмена. Отсутствие образца — отказ подготовки,
// а не тихая правка нуля мест: инъекция, ничего не изменившая, доказала бы лишь
// то, что гейт молчит на нетронутом дереве.
func docsSiteSubst(t *testing.T, root, old, new string) {
	t.Helper()
	p := filepath.Join(root, docsSiteConfig)
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("подготовка не удалась: %v", err)
	}
	s := string(raw)
	if strings.Count(s, old) != 1 {
		t.Fatalf("подготовка не удалась: образец встречается %d раз, а не единожды — "+
			"инъекция перестала быть одно-фактной:\n%s", strings.Count(s, old), old)
	}
	if err := os.WriteFile(p, []byte(strings.Replace(s, old, new, 1)), 0o644); err != nil {
		t.Fatalf("подготовка не удалась: %v", err)
	}
}

// ── КОНТРОЛЬ ────────────────────────────────────────────────────────────────
func TestDocsSiteInjectionControl_UntouchedWorldIsSilent(t *testing.T) {
	t.Parallel()
	census, findings := scanDocsSiteAddress(docsSiteWorld(t))
	if len(findings) != 0 {
		t.Fatalf("контроль не прошёл: нетронутая копия дала находки — красное ниже будет от копии, "+
			"а не от дефекта:\n%s", strings.Join(findings, "\n"))
	}
	if census.urlFields != 1 {
		t.Fatalf("контроль не прошёл: полей `url` разобрано %d, ожидалось 1 — "+
			"молчание ниже было бы молчанием о непрочитанном", census.urlFields)
	}
}

// ── НАХОДКИ ─────────────────────────────────────────────────────────────────

// Дословное восстановление дефекта #57: адрес, стоявший на стволе.
func TestDocsSiteInjection_PlatformDomainIsFound(t *testing.T) {
	t.Parallel()
	root := docsSiteWorld(t)
	docsSiteSubst(t, root, docsSiteLiveURL, "  url: 'https://iam.kacho.cloud',")
	_, findings := scanDocsSiteAddress(root)
	requireFindingMentions(t, findings, "iam.kacho.cloud")
	requireFindingMentions(t, findings, refusaldomain.ProductSuffix)
}

// Домен, лишь ПОХОЖИЙ на наш: суффикс обязан совпадать по границе метки, иначе
// `kaname.cloud.example.org` прошёл бы как «содержит наш суффикс».
func TestDocsSiteInjection_LookalikeDomainIsFound(t *testing.T) {
	t.Parallel()
	root := docsSiteWorld(t)
	docsSiteSubst(t, root, docsSiteLiveURL, "  url: 'https://iam.kaname.cloud.example.org',")
	_, findings := scanDocsSiteAddress(root)
	requireFindingMentions(t, findings, "kaname.cloud.example.org")
}

// Суффикс как ПРИСТАВКА чужой метки: `notkaname.cloud` содержит нашу строку и
// нашим доменом не является.
func TestDocsSiteInjection_SuffixAsSubstringIsFound(t *testing.T) {
	t.Parallel()
	root := docsSiteWorld(t)
	docsSiteSubst(t, root, docsSiteLiveURL, "  url: 'https://iam.notkaname.cloud',")
	_, findings := scanDocsSiteAddress(root)
	requireFindingMentions(t, findings, "notkaname.cloud")
}

// Не абсолютный адрес: Docusaurus строит из поля АБСОЛЮТНЫЕ ссылки.
func TestDocsSiteInjection_RelativeURLIsFound(t *testing.T) {
	t.Parallel()
	root := docsSiteWorld(t)
	docsSiteSubst(t, root, docsSiteLiveURL, "  url: '/kaname',")
	_, findings := scanDocsSiteAddress(root)
	requireFindingMentions(t, findings, "не абсолютный адрес")
}

// Поле снято целиком — «ноль находок» обязано быть отличимо от «ноль прочитанного».
func TestDocsSiteInjection_MissingFieldIsFound(t *testing.T) {
	t.Parallel()
	root := docsSiteWorld(t)
	docsSiteSubst(t, root, docsSiteLiveURL, "  // адреса больше нет")
	census, findings := scanDocsSiteAddress(root)
	requireFindingMentions(t, findings, "поля `url` верхнего уровня не найдено")
	if census.urlFields != 0 {
		t.Fatalf("поля нет, а разобрано %d", census.urlFields)
	}
}

// Конфигурации нет вовсе.
func TestDocsSiteInjection_MissingConfigIsFound(t *testing.T) {
	t.Parallel()
	root := docsSiteWorld(t)
	if err := os.Remove(filepath.Join(root, docsSiteConfig)); err != nil {
		t.Fatalf("подготовка не удалась: %v", err)
	}
	census, findings := scanDocsSiteAddress(root)
	requireFindingMentions(t, findings, docsSiteConfig)
	if census.configsRead != 0 {
		t.Fatalf("файла нет, а прочитано %d", census.configsRead)
	}
}

// ── ЗАКОННЫЕ БЛИЗНЕЦЫ ───────────────────────────────────────────────────────

// Имя платформы как имя proto-пакета. Контракты доменов платформы ей и
// ПРИНАДЛЕЖАТ, и копия каталога прав края законно их называет; гейт по подстроке
// краснел бы здесь и был бы снят первым же читателем.
func TestDocsSiteInjection_PlatformProtoPackageInProseIsSilent(t *testing.T) {
	t.Parallel()
	root := docsSiteWorld(t)
	docsSiteSubst(t, root, docsSiteLiveURL,
		"  // ресурс сети — `kacho.cloud.vpc.v1`, он принадлежит платформе\n"+docsSiteLiveURL)
	_, findings := scanDocsSiteAddress(root)
	if len(findings) != 0 {
		t.Fatalf("гейт краснеет на ЗАКОННОМ близнеце (имя proto-пакета платформы в комментарии):\n%s",
			strings.Join(findings, "\n"))
	}
}

// Разбор СОБСТВЕННОЙ находки рядом с полем. Гейт, краснеющий на своём
// объяснении, — ровно тот класс, который корпус ловит; а объяснение здесь стоит
// и обязано остаться.
func TestDocsSiteInjection_ItsOwnExplanationIsSilent(t *testing.T) {
	t.Parallel()
	root := docsSiteWorld(t)
	docsSiteSubst(t, root, docsSiteLiveURL,
		"  // здесь стояло 'https://iam.kacho.cloud' — координата, пережившая переезд\n"+docsSiteLiveURL)
	_, findings := scanDocsSiteAddress(root)
	if len(findings) != 0 {
		t.Fatalf("гейт краснеет на СОБСТВЕННОМ объяснении:\n%s", strings.Join(findings, "\n"))
	}
}

// Вложенный ключ `url` чужого предмета (ссылка подвала, элемент панели) полем
// верхнего уровня не является и адреса сайта не называет.
func TestDocsSiteInjection_NestedURLKeyIsSilent(t *testing.T) {
	t.Parallel()
	root := docsSiteWorld(t)
	docsSiteSubst(t, root, docsSiteLiveURL,
		docsSiteLiveURL+"\n          url: 'https://docs.kacho.cloud/vpc',")
	_, findings := scanDocsSiteAddress(root)
	if len(findings) != 0 {
		t.Fatalf("гейт краснеет на ЗАКОННОМ близнеце (вложенный ключ чужого предмета):\n%s",
			strings.Join(findings, "\n"))
	}
}

// Полоса сайта иная, суффикс продукта тот же. Какую полосу занять — решение
// развёртывания; потребуй гейт определённой, он выражал бы мнение автора.
func TestDocsSiteInjection_OtherBandSameSuffixIsSilent(t *testing.T) {
	t.Parallel()
	root := docsSiteWorld(t)
	docsSiteSubst(t, root, docsSiteLiveURL, "  url: 'https://docs.kaname.cloud',")
	_, findings := scanDocsSiteAddress(root)
	if len(findings) != 0 {
		t.Fatalf("гейт краснеет на ЗАКОННОМ близнеце (иная полоса того же продукта):\n%s",
			strings.Join(findings, "\n"))
	}
}
