//import fs from 'fs';
import nodeResolve from "@rollup/plugin-node-resolve";
import typescript from "@rollup/plugin-typescript";
//import terser from "@rollup/plugin-terser";
import filesize from "rollup-plugin-filesize";
import dts from 'rollup-plugin-dts';

// const meta = JSON.parse(fs.readFileSync('./package.json', { encoding: 'utf-8' }));
// const packageName = meta.name;

const extensions = ['.ts', '.js'];

const commonPlugins = [
    nodeResolve({ extensions }),
];

/*
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
*/

function confing_es_ts({ input, output }) {
    return {
        input,
        output: {
            file: output,
            format: "es",
            // globals: {
            //     "ts-sjcl": "sjcl",
            // },
        },
        // external: [
        //     "ts-sjcl",
        // ],
        plugins: [
            ...commonPlugins,
            typescript({ emitDeclarationOnly: true, declaration: true, outDir: './types' }),
            filesize({ showBeforeSizes: true, showGzippedSize: true }),
        ],
    };
}

function confing_dts({ input, output }) {
    return {
        input,
        output: [{
            file: output,
            format: "es",
            // globals: {
            //     "ts-sjcl": "sjcl",
            // },
        }],
        // external: [
        //     "ts-sjcl",
        // ],
        plugins: [
            dts(),
        ],
    };
}

export default [
    confing_es_ts({ input: "src/index.ts", output: `dist/index.js` }),
    confing_dts({ input: "dist/types/index.d.ts", output: `dist/index.d.ts` }),
];
