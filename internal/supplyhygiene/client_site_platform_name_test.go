// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// client_site_platform_name_test.go — ГЕЙТ оси «клиентский сайт»: сайт
// документации называет продукт своим именем, а каждое оставшееся имя
// платформы названо поимённо (kacho#2076).
//
// Предмет, критерий «самоназвание против ссылки на соседа» и почему запись
// ведётся по токену — в шапке `client_site_platform_name.go`; здесь не
// пересказываются.
//
// Способность упасть и смолчать доказана инъекцией —
// client_site_platform_name_injection_test.go.
package supplyhygiene

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/treecorpus"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// clientSiteSurface — из чего сайт состоит: страницы, компоненты, которыми они
// рендерятся, и оболочка (заголовок, навигация, подвал). Каталог страниц — тот
// же, что у соседнего гейта страниц (`clientPagesDir`), а не вторая его запись.
var clientSiteSurface = []string{
	clientPagesDir,
	"docs/src",
	"docs/docusaurus.config.ts",
	"docs/sidebars.ts",
}

// clientSitePagesFloor — страниц сайта, ниже которого обход беспредметен.
const clientSitePagesFloor = 20

// Причины записей ведомости. Каждая называет ВЛАДЕЛЬЦА предмета, у которого есть
// своё имя вне продукта, — критерий из шапки судьи, а не признак формы.
const (
	whyFoundationSeries = "ряд общего измерителя фундамента (corelib `grpcsrv`): имя ряда " +
		"производит не служба, и страница называет его так, как оператор видит его в выдаче"
	whyFoundationSecretLabel = "метка строки секрета, которую чеканит фундамент (corelib " +
		"`credsecret`): на неё ключуются сканеры утёкших удостоверений, и она наследуется как " +
		"код, а не как имя (kacho#2076, «ФОРМУЛИРОВКА НОРМЫ»)"
	whyFoundationKnob = "ручка фундамента (corelib `dropguard.ApprovalEnv`, читается " +
		"`migratorrun`, а не кодом службы: `git grep dropguard -- cmd/migrator` → 0): имя одно на " +
		"все продукты фундамента, своего у службы нет намеренно — второе имя одной ручки было бы " +
		"двумя именами; страница называет её так, как её набирает оператор, и говорит, почему " +
		"приставка чужая (kaname#212)"
	whyImageRevisionPath = "путь файла ревизии внутри образа: его пишет Dockerfile службы, и " +
		"страница называет его верно. Это остаток оси образа, а не прозы: правится в образе, " +
		"и страница — тем же изменением"
	whyTrackerAddress      = "адрес задачи трекера: за ним живой репозиторий учёта, а не имя продукта"
	whyNeighborServiceDocs = "ссылка на документацию СОСЕДНЕГО сервиса платформы — владельца вида " +
		"ресурса, чьи потолки читаются у него"
	whyNeighborService = "имя соседнего сервиса платформы, вызывающего службу: у объекта свой " +
		"владелец вне продукта"
	whyNeighborEdgeKnob     = "ручка края платформы — соседа, который держит кэш решений, а не службы"
	whyNeighborStandAddress = "адрес реестра платформы на стенде — соседнего сервиса, принимающего " +
		"удостоверение службы"
	whyLegacySchema = "прежнее имя схемы: по нему страж старта отказывает в пуске, и оператор " +
		"обязан найти его в своей базе (kacho#2088)"
	whyNeighborModuleRepo = "модуль инфраструктуры живёт в репозитории платформы: адрес чужого " +
		"репозитория, по которому модуль и берут"
	whyPlatformProvider = "провайдер инфраструктуры — продукт платформы: его адрес в реестре, его " +
		"ручки, адрес API в примере и прежние имена типов, по которым оператор переносит состояние"
	whySiteHistory = "историческое свидетельство в комментарии оболочки сайта: адрес, " +
		"переименованный #57, и производитель отказа, закрытый kaname#48"
	whyNeighborConsoleStyle = "консоль платформы — источник палитры и шрифтового стека, у которого " +
		"оформление сайта взято; называется в комментариях стилей и оболочки"
)

// clientSiteStay — ведомость: имя платформы, которое сайт вправе нести.
//
// Ведётся ПОИМЁННО, по странице и токену, с точным числом. Запись, которой
// нечего прощать, — находка: послабление истекает вместе со своим предметом.
// Адъюдикация каждой строки — критерием «самоназвание против ссылки на соседа»
// (kacho#2076); самоназвания на этих страницах сняты тем же изменением, что
// завело ведомость.
var clientSiteStay = []ClientSiteStay{
	{Page: "docs/content/advanced/observability.mdx", Token: "/etc/kacho/image-revision", Count: 1, Why: whyImageRevisionPath},
	{Page: "docs/content/advanced/observability.mdx", Token: "kacho_", Count: 1, Why: whyFoundationSeries},
	{Page: "docs/content/advanced/observability.mdx", Token: "kacho_grpc_server_handled_total", Count: 7, Why: whyFoundationSeries},
	{Page: "docs/content/advanced/observability.mdx", Token: "kacho_grpc_server_handling_seconds", Count: 1, Why: whyFoundationSeries},
	{Page: "docs/content/advanced/observability.mdx", Token: "kacho_grpc_server_stream_seconds", Count: 1, Why: whyFoundationSeries},
	{Page: "docs/content/api/project.mdx", Token: "https://github.com/PRO-Robotech/kacho/issues/1231", Count: 1, Why: whyTrackerAddress},
	{Page: "docs/content/api/quotas.mdx", Token: "Kachō", Count: 1, Why: whyNeighborServiceDocs},
	{Page: "docs/content/api/tokens.mdx", Token: "kacho_", Count: 2, Why: whyFoundationSecretLabel},
	{Page: "docs/content/api/tokens.mdx", Token: "kacho_soc0vwg9nr0bhspkj43s_", Count: 1, Why: whyFoundationSecretLabel},
	{Page: "docs/content/api/tokens.mdx", Token: "kacho_uoc4k2m8p0q1r5s9t3v7_", Count: 1, Why: whyFoundationSecretLabel},
	{Page: "docs/content/api/tokens.mdx", Token: "registry.kacho.local", Count: 1, Why: whyNeighborStandAddress},
	{Page: "docs/content/architecture/overview.mdx", Token: "kacho-compute", Count: 1, Why: whyNeighborService},
	{Page: "docs/content/architecture/overview.mdx", Token: "kacho-geo", Count: 2, Why: whyNeighborService},
	{Page: "docs/content/architecture/overview.mdx", Token: "kacho-nlb", Count: 1, Why: whyNeighborService},
	{Page: "docs/content/architecture/overview.mdx", Token: "kacho-vpc", Count: 1, Why: whyNeighborService},
	{Page: "docs/content/first-credential.mdx", Token: "kacho_", Count: 2, Why: whyFoundationSecretLabel},
	{Page: "docs/content/first-credential.mdx", Token: "kacho_uoc4k2m8p0q1r5s9t3v7_", Count: 1, Why: whyFoundationSecretLabel},
	{Page: "docs/content/getting-started.mdx", Token: "kacho_", Count: 1, Why: whyFoundationSecretLabel},
	{Page: "docs/content/getting-started.mdx", Token: "KACHO_API_GATEWAY_AUTHZ_CACHE_TTL_SECONDS", Count: 1, Why: whyNeighborEdgeKnob},
	// Прежнее имя схемы берётся у ЕДИНСТВЕННОГО его объявления — гейта имени
	// схемы (`retiredSchema`), а не пишется здесь второй раз: литерал был бы и
	// вторым местом об одном предмете, и находкой того гейта.
	{Page: "docs/content/install/deploy.mdx", Token: retiredSchema, Count: 4, Why: whyLegacySchema},
	{Page: "docs/content/install/deploy.mdx", Token: "KACHO_MIGRATOR_DROP_APPROVED", Count: 1, Why: whyFoundationKnob},
	{Page: "docs/content/intro.mdx", Token: "kacho-compute", Count: 1, Why: whyNeighborService},
	{Page: "docs/content/intro.mdx", Token: "kacho-geo", Count: 1, Why: whyNeighborService},
	{Page: "docs/content/intro.mdx", Token: "kacho-nlb", Count: 1, Why: whyNeighborService},
	{Page: "docs/content/intro.mdx", Token: "kacho-vpc", Count: 1, Why: whyNeighborService},
	{Page: "docs/content/terraform/module-iam-access.mdx", Token: "github.com/PRO-Robotech/kacho//terraform/modules/iam-access", Count: 1, Why: whyNeighborModuleRepo},
	{Page: "docs/content/terraform/module-iam-machine-identity.mdx", Token: "github.com/PRO-Robotech/kacho//terraform/modules/iam-machine-identity", Count: 1, Why: whyNeighborModuleRepo},
	{Page: "docs/content/terraform/module-iam-project.mdx", Token: "github.com/PRO-Robotech/kacho//terraform/modules/iam-project", Count: 1, Why: whyNeighborModuleRepo},
	{Page: "docs/content/terraform/provider.mdx", Token: "https://api.kacho.example", Count: 1, Why: whyPlatformProvider},
	{Page: "docs/content/terraform/provider.mdx", Token: "kacho", Count: 2, Why: whyPlatformProvider},
	{Page: "docs/content/terraform/provider.mdx", Token: "KACHO_ENDPOINT", Count: 1, Why: whyPlatformProvider},
	{Page: "docs/content/terraform/provider.mdx", Token: "kacho_iam_", Count: 2, Why: whyPlatformProvider},
	{Page: "docs/content/terraform/provider.mdx", Token: "kacho_iam_project.prod", Count: 1, Why: whyPlatformProvider},
	{Page: "docs/content/terraform/provider.mdx", Token: "KACHO_TOKEN", Count: 1, Why: whyPlatformProvider},
	{Page: "docs/content/terraform/provider.mdx", Token: "kacho_vpc_", Count: 1, Why: whyPlatformProvider},
	{Page: "docs/content/terraform/provider.mdx", Token: "PRO-Robotech/kacho", Count: 1, Why: whyPlatformProvider},
	{Page: "docs/content/terraform/provider.mdx", Token: "var.kacho_token", Count: 1, Why: whyPlatformProvider},
	{Page: "docs/docusaurus.config.ts", Token: "https://iam.kacho.cloud", Count: 1, Why: whySiteHistory},
	{Page: "docs/docusaurus.config.ts", Token: "iam.kacho.cloud", Count: 1, Why: whySiteHistory},
	{Page: "docs/docusaurus.config.ts", Token: "kacho-ui", Count: 1, Why: whyNeighborConsoleStyle},
	{Page: "docs/src/css/custom.css", Token: "kacho-ui", Count: 6, Why: whyNeighborConsoleStyle},
}

func TestClientSiteNamesTheProductByItsOwnName(t *testing.T) {
	tree, err := treecorpus.NewTree(serviceRoot)
	require.NoError(t, err, "состав дерева не прочитан — «ноль находок» здесь означало бы "+
		"«ноль прочитанного»")

	corpus, err := check.CorpusFrom(tree, func(rel string) bool {
		return InClientSite(rel, clientSiteSurface)
	})
	require.NoError(t, err, "обход сайта")

	census, findings := JudgeClientSitePlatformName(map[string]string(corpus), clientSiteStay,
		clientSiteSurface)

	t.Logf("перепись сайта: файлов прочитано %d, несут имя платформы %d; вхождений %d, из них "+
		"диакритической формой %d, названо ведомостью поимённо %d (записей %d)",
		census.Pages, census.PagesWithName, census.Hits, census.HitsDiacritic, census.Stayed,
		len(clientSiteStay))

	// Предпосылка — объём, а не находки: пустой сайт без имени платформы и есть
	// цель, и на ней гейт обязан проходить. Беспредметен он только тогда, когда
	// страниц не прочитано.
	require.GreaterOrEqual(t, census.Pages, clientSitePagesFloor, "прочитано %d файлов сайта "+
		"при пороге %d — обход сузился, и молчание гейта сказано о части сайта",
		census.Pages, clientSitePagesFloor)

	for _, f := range findings {
		t.Errorf("%s", f)
	}
}
