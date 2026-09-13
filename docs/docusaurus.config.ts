import { themes as prismThemes } from 'prism-react-renderer'
import type { Config } from '@docusaurus/types'
import type * as Preset from '@docusaurus/preset-classic'

const config: Config = {
  title: 'Kaname',
  tagline: 'Identity & Access Management — Account, Project, User, ServiceAccount, Group, Role, AccessBinding',

  // АДРЕС САЙТА НАЗЫВАЕТСЯ СУФФИКСОМ ЭТОГО ПРОДУКТА, А НЕ ПЛАТФОРМЫ.
  //
  // Здесь стояло `https://iam.kacho.cloud` — координата, пережившая переезд:
  // служба вынесена самостоятельным продуктом, имя и репозиторий сменились, а
  // адрес остался платформенным. Поле не косметическое: из него Docusaurus
  // строит канонические ссылки страниц, `sitemap.xml` и абсолютные адреса в
  // разметке, то есть сайт продукта Kaname объявлял читателю и поисковым
  // роботам, что живёт на домене чужого продукта (#57).
  //
  // ЗНАЧЕНИЕ ВЗЯТО У ОБЪЯВЛЕНИЯ ПРОДУКТА, А НЕ ПРИДУМАНО. Суффикс объявлен в
  // дереве ровно однажды — `internal/refusaldomain`, `ProductSuffix`, решение
  // приёмки WIRE-1 (W3), — и полоса `iam` оттуда же (`ServiceIAM`). Это тот же
  // класс и то же лекарство, что у домена отказа: его производитель отвечал
  // `iam.kacho.cloud` по той же причине и был закрыт `kaname#48` тем же ходом —
  // брать у объявления, а не у литерала. Согласие держит гейт
  // `internal/supplyhygiene/docs_site_address_test.go`.
  //
  // ИЗМЕНЁН РОВНО ОДИН ФАКТ — суффикс продукта. Полоса `iam` оставлена такой,
  // какой была: жить ли сайту на собственной полосе (`docs.`) — решение
  // развёртывания, и в этом дереве оно НЕ УСТАНОВЛЕНО. Замер на `4c3ad523`:
  // сайт не собирается ни одним заданием конвейера и не публикуется ничем, то
  // есть адреса, «по которому он обслуживается», сегодня не существует вовсе.
  // Предикат пересмотра ВНЕШНИЙ: появится задание, публикующее сайт, — адрес
  // берётся у него, а эта запись снимается вместе со своим предметом.
  url: 'https://iam.kaname.cloud',
  baseUrl: '/',
  onBrokenLinks: 'throw',
  // Якорь, который никуда не ведёт, — такая же битая ссылка, как несуществующий
  // путь: читатель приходит на страницу и не находит раздела. По умолчанию
  // Docusaurus лишь предупреждает, из-за чего переименование заголовка проезжает
  // сборку молча — гейт обязан на этом падать.
  onBrokenAnchors: 'throw',

  organizationName: 'PRO-Robotech',
  projectName: 'kaname',

  i18n: {
    defaultLocale: 'ru',
    locales: ['ru'],
  },

  markdown: {
    mermaid: true,
    hooks: {
      onBrokenMarkdownLinks: 'throw',
    },
  },

  // Продуктовый шрифтовой стек kacho-ui: Inter (текст) + JetBrains Mono (код/значения).
  // Подключаются с Google Fonts; preconnect ускоряет первый запрос.
  stylesheets: [
    {
      href: 'https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap',
      type: 'text/css',
    },
  ],
  headTags: [
    {
      tagName: 'link',
      attributes: { rel: 'preconnect', href: 'https://fonts.googleapis.com' },
    },
    {
      tagName: 'link',
      attributes: { rel: 'preconnect', href: 'https://fonts.gstatic.com', crossorigin: 'anonymous' },
    },
  ],

  presets: [
    [
      'classic',
      {
        docs: {
          // Страницы сайта лежат в `content/`, а не в умолчательном `docs/`: каталог
          // документации компонента сам называется `docs`, и вложенный `docs/docs`
          // читался бы как опечатка — по нему ошибались бы в каждой ссылке.
          // Рядом, в `engineering/`, лежат инженерные записки: они адресованы
          // разработчику сервиса, а не арендатору, и в сборку сайта не входят.
          path: 'content',
          sidebarPath: './sidebars.ts',
          routeBasePath: '/',
        },
        blog: false,
        theme: {
          customCss: './src/css/custom.css',
        },
      } satisfies Preset.Options,
    ],
  ],

  themes: ['@docusaurus/theme-mermaid'],

  themeConfig: {
    // Правая in-page оглавление (TOC) — только первый уровень (h2);
    // вложенные подзаголовки в навигации не показываются.
    tableOfContents: {
      minHeadingLevel: 2,
      maxHeadingLevel: 2,
    },
    navbar: {
      title: 'Kaname',
      items: [
        {
          type: 'docSidebar',
          sidebarId: 'iamSidebar',
          label: 'Документация',
          position: 'left',
        },
        {
          href: 'https://github.com/PRO-Robotech/kacho/tree/main/services/iam',
          label: 'GitHub',
          position: 'right',
        },
      ],
    },
    colorMode: {
      defaultMode: 'dark',
      disableSwitch: false,
      respectPrefersColorScheme: true,
    },
    footer: {
      style: 'dark',
      copyright: `Copyright © ${new Date().getFullYear()} ООО «ПРТ» · Kachō Cloud Platform.`,
      links: [
        {
          title: 'Документация',
          items: [
            { label: 'Введение', to: '/' },
            { label: 'Архитектура', to: '/architecture/overview' },
            { label: 'API', to: '/api/overview' },
          ],
        },
        {
          title: 'Исходный код',
          items: [
            { label: 'Монорепозиторий kacho', href: 'https://github.com/PRO-Robotech/kacho' },
            { label: 'services/iam/', href: 'https://github.com/PRO-Robotech/kacho/tree/main/services/iam' },
            { label: 'proto/', href: 'https://github.com/PRO-Robotech/kacho/tree/main/proto' },
            { label: 'pkg/', href: 'https://github.com/PRO-Robotech/kacho/tree/main/pkg' },
          ],
        },
      ],
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
      additionalLanguages: ['bash', 'json', 'protobuf', 'yaml', 'sql', 'docker'],
    },
  } satisfies Preset.ThemeConfig,
}

export default config
