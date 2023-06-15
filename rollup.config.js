import fs from 'fs';
import nodeResolve from "@rollup/plugin-node-resolve";
import typescript from "@rollup/plugin-typescript";
import terser from "@rollup/plugin-terser";
import filesize from "rollup-plugin-filesize";
import dts from 'rollup-plugin-dts';

const meta = JSON.parse(fs.readFileSync('./package.json', { encoding: 'utf-8' }));
const packageName = meta.name;

const extensions = ['.ts', '.js'];

const commonPlugins = [
    nodeResolve({ extensions }),
];

function createConfing_es({ input, output }) {
    return {
        input,
        output: { file: output, name: "WebSdk", format: "es", },
        plugins: [
            ...commonPlugins,
            filesize({ showBeforeSizes: true, showGzippedSize: true }),
        ],
    };
}

function createConfing_es_ts({ input, output }) {
    return {
        input,
        output: { file: output, format: "es", },
        plugins: [
            ...commonPlugins,
            typescript({ emitDeclarationOnly: true, declaration: true, outDir: './types' }),
            //typescript({}),
            filesize({ showBeforeSizes: true, showGzippedSize: true }),
        ],
    };
}

function createConfing_ts_defs({ input, output }) {
    return {
        input,
        output: { file: output, name: "WebSdk", format: "es", },
        plugins: [
            ...commonPlugins,
            typescript({ emitDeclarationOnly: true, declaration: true, })
        ],
    };
}

function createConfing_dts({ input, output }) {
    return {
        input,
        output: [{ file: output, format: "es" }],
        plugins: [
            dts(),
        ],
    };
}

function createConfing_udm_min({ input, output }) {
    return {
        input,
        output: {
            file: output, name: "WebSdk", format: "umd",
            indent: true,
            extend: true,
            banner: `//maxzz ${meta.homepage} v${meta.version}\n`
        },
        plugins: [
            ...commonPlugins,
            terser(),
        ],
    };
}

export default [
    createConfing_es_ts({ input: "./src/index.ts", output: `dist/index.js` }),
    createConfing_dts({ input: "./dist/types/index.d.ts", output: `dist/index.d.ts` }),
];

console.log('NODE_ENV2', process.env.NODE_ENV2); // = 'production1'
