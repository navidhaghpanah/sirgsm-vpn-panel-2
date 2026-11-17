import * as esbuild from 'esbuild';
import {readFile, writeFile, mkdir} from 'node:fs/promises';

const dev = process.argv.includes('--dev');
const options = {
  entryPoints: ['src/main.jsx'], outdir: 'dist', bundle: true,
  format: 'esm', jsx: 'automatic', minify: !dev, metafile: true,
  entryNames: dev ? 'assets/app' : 'assets/app-[hash]',
  assetNames: 'assets/[name]-[hash]', target: ['es2022'],
  loader: {'.woff': 'file', '.woff2': 'file'},
  define: {'process.env.NODE_ENV': JSON.stringify(dev ? 'development' : 'production')},
  logLevel: 'info',
};
const result = await esbuild.build(options);
const [entry, info] = Object.entries(result.metafile.outputs).find(([,v])=>v.entryPoint==='src/main.jsx');
const publicPath = value => '/'+value.replaceAll('\\','/').replace(/^dist\//,'');
let html = (await readFile('index.html','utf8')).replace('/src/main.jsx',publicPath(entry));
if(info.cssBundle) html=html.replace('</head>',`<link rel="stylesheet" href="${publicPath(info.cssBundle)}"/></head>`);
await mkdir('dist',{recursive:true});
await writeFile('dist/index.html',html);
if(dev){
  const context=await esbuild.context(options);
  await context.watch();
  await context.serve({host:'127.0.0.1',port:5173,servedir:'dist'});
  console.log('Local preview: http://127.0.0.1:5173 (reload after edits)');
}
