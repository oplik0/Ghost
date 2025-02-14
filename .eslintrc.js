const path = require('path');

module.exports = {
    env: {
        node: true,
        es2020: true
    },
    plugins: ['ghost'],
    extends: [
        'plugin:ghost/node'
    ],
    rules: {
        // @TODO: remove this rule once it's turned into "error" in the base plugin
        'no-shadow': 'error',
        'no-var': 'error',
        'one-var': ['error', 'never']
    },
    parserOptions: {
        ecmaVersion: 2020
    },
    overrides: [
        {
            files: 'core/server/api/canary/*',
            rules: {
                'ghost/ghost-custom/max-api-complexity': 'warn'
            }
        },
        {
            files: 'core/shared/**',
            rules: {
                'ghost/node/no-restricted-require': ['error', [
                    {
                        name: path.resolve(__dirname, 'core/server/**'),
                        message: 'Invalid require of core/server from core/shared.'
                    },
                    {
                        name: path.resolve(__dirname, 'core/frontend/**'),
                        message: 'Invalid require of core/frontend from core/shared.'
                    }
                ]]
            }
        },
        /**
         * @TODO: enable these soon
         */
        {
            files: 'core/frontend/**',
            rules: {
                'ghost/node/no-restricted-require': ['off', [
                    // These are critical refactoring issues that we need to tackle ASAP
                    {
                        name: path.resolve(__dirname, 'core/server/**'),
                        message: 'Invalid require of core/server from core/frontend.'
                    },
                    // If we make the frontend entirely independent, these have to be solved too
                    {
                        name: path.resolve(__dirname, 'core/shared/**'),
                        message: 'Invalid require of core/shared from core/frontend.'
                    }
                ]]
            }
        },
        {
            files: 'core/server/**',
            rules: {
                'ghost/node/no-restricted-require': ['off', [
                    {
                        name: path.resolve(__dirname, 'core/frontend/**'),
                        message: 'Invalid require of core/frontend from core/server.'
                    }
                ]]
            }
        }
    ]
};
