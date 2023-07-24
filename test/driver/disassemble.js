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
      const decomposition = { addr: `0x${line.substring(0, pos)}`, opcode: line.substring(pos + 2).trimEnd(), rep: "padding" };
      res.push(decomposition);
    }
  }
  return res;
}

function compareDisassembly(objdump, mdbResult) {
  if (mdbResult.length != objdump.length) {
    throw new Error(`Expected ${objdump.length} disassembled instructions but instead got ${mdbResult.length}. Serial data: ${JSON.stringify(mdbResult, null, 2)}`);
  }
  for (let i = 0; i < objdump.length; ++i) {
    if (mdbResult[i].address != objdump[i].addr) {
      throw new Error(`Expected disassembled instruction #${i} at address ${objdump[i].addr} but got ${mdbResult[i].address}. Serial data: ${JSON.stringify(mdbResult, null, 2)}`);
    }
    if (mdbResult[i].instructionBytes != objdump.opcode
      && mdbResult[i].instructionBytes.split(" ").join("") != objdump[i].opcode.split(" ").join("")) {
      throw new Error(`Expected disassembled instruction to have opcode ${objdump[i].opcode} but got ${mdbResult[i].instructionBytes}. Serial data: ${JSON.stringify(mdbResult, null, 2)}`)
    }
  }
}

async function test() {
  const objdumped = spawnSync("objdump", ["-d", buildDirFile("stackframes")]).stdout.toString();
  const insts_of_interest = getTextSection(objdumped);
  const insts = processObjdumpLines(insts_of_interest);
  await da_client.launchToMain(buildDirFile("stackframes"));
  const threads = await da_client.threads();
  const frames = await da_client.stackTrace(threads[0].id);
  const pc = frames.body.stackFrames[0].instructionPointerReference;

  const insIndex = insts.findIndex(({ addr, opcode, rep }) => addr == pc);
  const objdumpSpan = insts.slice(insIndex - 5, insIndex + 5);
  console.log(`${JSON.stringify(objdumpSpan, null, 2)}`);
  const disassembly = await da_client.sendReqGetResponse("disassemble", { memoryReference: pc, offset: 0, instructionOffset: -5, instructionCount: 10, resolveSymbols: false });
  if (disassembly.body.instructions.length != 10) {
    throw new Error(`Expected 10 disassembled instructions but instead got ${disassembly.body.instructions.length}. Serial data: ${JSON.stringify(disassembly.body.instructions, null, 2)}`);
  }
  const mdbResult = disassembly.body.instructions;
  compareDisassembly(objdumpSpan, mdbResult);
}

test().then(() => {
  console.log(`Test ${__filename} succeeded`);
  process.exit(0);
}).catch(testException);