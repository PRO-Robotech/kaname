import type { SidebarsConfig } from '@docusaurus/plugin-content-docs'

const sidebars: SidebarsConfig = {
  iamSidebar: [
    'intro',
    'getting-started',
    'first-credential',
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
        'api/membership',
        'api/service-account',
        'api/group',
        'api/role',
        'api/access-binding',
        'api/limit',
        'api/tokens',
        'api/authorize',
        'api/operations',
        'api/quotas',
        'api/rest-surface',
      ],
    },
    {
      type: 'category',
      label: 'Дополнительно',
      collapsed: true,
      items: ['advanced/design-decisions', 'advanced/observability'],
    },
    {
      type: 'category',
      label: 'Terraform',
      collapsed: false,
      items: [
        'terraform/provider',
        'terraform/module-iam-project',
        'terraform/module-iam-access',
        'terraform/module-iam-machine-identity',
      ],
    },
  ],
}

export default sidebars
