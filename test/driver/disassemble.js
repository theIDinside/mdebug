const { DAClient, MDB_PATH, checkResponse, testException, getLineOf, readFile, buildDirFile, repoDirFile } = require("./client")
const { spawnSync } = require("child_process");

const da_client = new DAClient(MDB_PATH, []);

const expectedStackTraces = [
  [{ line: 39, name: "foo" }, { line: 46, name: "main" }, { line: 0, name: "unknown" }],
  [{ line: 33, name: "bar" }, { line: 40, name: "foo" }, { line: 46, name: "main" }, { line: 0, name: "unknown" }],
  [{ line: 14, name: "baz" }, { line: 34, name: "bar" }, { line: 40, name: "foo" }, { line: 46, name: "main" }, { line: 0, name: "unknown" }],
  [{ line: 7, name: "quux" }, { line: 16, name: "baz" }, { line: 34, name: "bar" }, { line: 40, name: "foo" }, { line: 46, name: "main" }, { line: 0, name: "unknown" }]
]
const regex = /[0-9a-f]+:/
function getTextSection(objdumpOutput) {
  const lines = objdumpOutput.split("\n");
  const res = [];
  let start = 0;
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].includes("Disassembly of section .text")) {
      start = i + 3;
      i = start;
    } else if (lines[i].includes("Disassembly") && start != 0) {
      return res;
    }
    if (start > 0) {
      if (regex.test(lines[i]))
        res.push(lines[i].trimStart().trimEnd());
    }
  }
}

function processObjdumpLines(insts) {
  const res = [];
  for (const line of insts) {
    const pos = line.indexOf(":");
    const rep = line.indexOf("\t", pos + 2);
    if (rep != -1) {
      const decomposition = { addr: `0x${line.substring(0, pos)}`, opcode: line.substring(pos + 2, rep).trimEnd(), rep: line.substring(rep + 1) };
      res.push(decomposition);
    } else {
      // zydis appends padding to last instruction, apparently, making our tests fail. This way, we make objdump behave like Zydis
      res[res.length - 1].opcode = `${res[res.length - 1].opcode} ${line.substring(pos + 2).trimEnd()}`
    }
  }
  return res;
}

function compareDisassembly(pc, objdump, mdbResult) {

  if (mdbResult.length != objdump.length) {
    throw new Error(`(${pc}): Expected ${objdump.length} disassembled instructions but instead got ${mdbResult.length}. Serial data: ${JSON.stringify(mdbResult, null, 2)}. Expected data ${JSON.stringify(objdump, null, 2)}`);
  }
  console.log(`MDB Instruction Output: ${mdbResult.length} == objdump Instruction Output: ${objdump.length}`);
  for (let i = 0; i < objdump.length; ++i) {
    if (mdbResult[i].address != objdump[i].addr) {
      throw new Error(`(${pc}): Expected disassembled instruction #${i} at address ${objdump[i].addr} but got ${mdbResult[i].address}. Serial data: ${JSON.stringify(mdbResult, null, 2)}. Expected data ${JSON.stringify(objdump, null, 2)}`);
    }
    if (mdbResult[i].instructionBytes != objdump.opcode
      && mdbResult[i].instructionBytes.split(" ").join("") != objdump[i].opcode.split(" ").join("")) {
      throw new Error(`(${pc}): Expected disassembled instruction to have opcode ${objdump[i].opcode} but got ${mdbResult[i].instructionBytes}. Serial data: ${JSON.stringify(mdbResult, null, 2)}. Expected data ${JSON.stringify(objdump, null, 2)}`)
    }
  }

}

async function disasm_verify(objdump, client, pc, insOffset, insCount) {
  const insIndex = objdump.findIndex(({ addr, opcode, rep }) => addr == pc);
  const offset = insIndex + insOffset
  const objdumpSpan = objdump.slice(offset, offset + insCount);
  const disassembly = await client.sendReqGetResponse("disassemble", { memoryReference: pc, offset: 0, instructionOffset: insOffset, instructionCount: insCount, resolveSymbols: false });
  compareDisassembly(pc, objdumpSpan, disassembly.body.instructions);
  console.log(`[offset: ${insOffset}, pc: ${pc}, count: ${insCount}]\n\t - MDB output == objdump output!`);
}

async function test() {
  const objdumped = spawnSync("objdump", ["-d", buildDirFile("stackframes")]).stdout.toString();
  const insts_of_interest = getTextSection(objdumped);
  const objdump = processObjdumpLines(insts_of_interest);
  await da_client.launchToMain(buildDirFile("stackframes"));
  const threads = await da_client.threads();
  const frames = await da_client.stackTrace(threads[0].id);
  const pc = frames.body.stackFrames[0].instructionPointerReference;
  await disasm_verify(objdump, da_client, pc, 0, 10);
  await disasm_verify(objdump, da_client, pc, 5, 10);
  await disasm_verify(objdump, da_client, pc, -5, 10)
  await disasm_verify(objdump, da_client, pc, -30, 10);
  await disasm_verify(objdump, da_client, pc, -50, 10);
  await disasm_verify(objdump, da_client, pc, -100, 200);
  await disasm_verify(objdump, da_client, pc, 10, 2000);
}

test().then(() => {
  console.log(`Test ${__filename} succeeded`);
  process.exit(0);
}).catch(testException);