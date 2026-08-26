// Time snarkjs Groth16 proving for every input file in a directory.
//   NODE_PATH=packages/contracts/node_modules node bench/prove.js <inputsDir> <processZkey> <processWasm> <tallyZkey> <tallyWasm> <repeat> <label> <csvOut>
// Each proof is timed as: witness (wtns.calculate) + prove (groth16.prove), plus a full
// groth16.fullProve for the end-to-end number (what MACI's generateProofSnarkjs does).
const fs = require("fs");
const os = require("os");
const path = require("path");
const { performance } = require("perf_hooks");
const snarkjs = require("snarkjs");

const [inputsDir, pZkey, pWasm, tZkey, tWasm, repeatStr, label, csvOut] = process.argv.slice(2);
const repeat = parseInt(repeatStr || "1", 10);
const mode = process.env.PROVE_MODE || "full"; // full | split | both

async function timeOne(input, wasm, zkey, tag) {
  const row = { tag };
  if (mode === "split" || mode === "both") {
    const wtnsFile = path.join(os.tmpdir(), `maci_bench_${process.pid}.wtns`);
    let t0 = performance.now();
    await snarkjs.wtns.calculate(input, wasm, wtnsFile);
    row.witness_s = (performance.now() - t0) / 1000;
    t0 = performance.now();
    await snarkjs.groth16.prove(zkey, wtnsFile);
    row.prove_s = (performance.now() - t0) / 1000;
    fs.rmSync(wtnsFile, { force: true });
  }
  if (mode === "full" || mode === "both") {
    const t0 = performance.now();
    await snarkjs.groth16.fullProve(input, wasm, zkey);
    row.full_s = (performance.now() - t0) / 1000;
  }
  return row;
}

(async () => {
  const files = fs.readdirSync(inputsDir).filter((f) => f.endsWith(".json")).sort();
  if (!fs.existsSync(csvOut)) {
    fs.writeFileSync(csvOut, "label,repeat,batch,witness_s,prove_s,full_s,nproc\n");
  }
  for (const f of files) {
    const input = JSON.parse(fs.readFileSync(path.join(inputsDir, f), "utf8"));
    const isProcess = f.startsWith("process_");
    const wasm = isProcess ? pWasm : tWasm;
    const zkey = isProcess ? pZkey : tZkey;
    for (let r = 1; r <= repeat; r += 1) {
      const row = await timeOne(input, wasm, zkey, f.replace(".json", ""));
      const line = `${label},${r},${row.tag},${row.witness_s ?? ""},${row.prove_s ?? ""},${row.full_s ?? ""},${os.cpus().length}\n`;
      fs.appendFileSync(csvOut, line);
      process.stdout.write(line);
    }
  }
  if (globalThis.curve_bn128) await globalThis.curve_bn128.terminate();
  process.exit(0);
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
