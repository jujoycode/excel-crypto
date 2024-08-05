import * as esbuild from "esbuild";

await esbuild
  .build({
    entryPoints: ["src/index.ts"],
    outfile: "dist/index.js",
    logLevel: "debug",
    bundle: true,
    minify: true,
    treeShaking: true,
    format: "cjs",
    platform: "node",
    target: "node18",
  })
  .then(() => {
    console.log("");
  })
  .catch(() => process.exit(1));
