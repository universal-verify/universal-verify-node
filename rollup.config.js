import terser from '@rollup/plugin-terser';

export default {
    input: 'scripts/UniversalVerify.js',
    output: [{
            file: 'build/universal-verify.js',
            format: 'es',
        }, {
            file: 'build/universal-verify.min.js',
            format: 'es',
            name: 'version',
            plugins: [
                terser({mangle: { keep_classnames: true, keep_fnames: true }}),
            ],
        },
    ],
    external: ['crypto', 'jwks-rsa', 'jsonwebtoken'],
};
