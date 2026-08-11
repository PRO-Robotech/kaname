import type { SidebarsConfig } from '@docusaurus/plugin-content-docs'

const sidebars: SidebarsConfig = {
  iamSidebar: [
    'intro',
    'getting-started',
    {
      type: 'category',
      label: 'Архитектура',
      collapsed: false,
      items: [
        'architecture/overview',
        'architecture/authz',
        'architecture/identity',
        'architecture/data-model',
      ],
    },
    {
      type: 'category',
      label: 'Установка',
      collapsed: true,
      items: ['install/deploy', 'install/configuration'],
    },
    {
      type: 'category',
      label: 'API',
      collapsed: false,
      items: [
        'api/overview',
        'api/account',
        'api/project',
        'api/user',
        'api/service-account',
        'api/group',
        'api/role',
        'api/access-binding',
        'api/tokens',
        'api/authorize',
        'api/operations',
      ],
    },
    {
      type: 'category',
      label: 'Дополнительно',
      collapsed: true,
      items: ['advanced/design-decisions', 'advanced/observability'],
    },
  ],
}

export default sidebars
