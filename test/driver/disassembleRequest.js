const { spawnSync } = require('child_process')
const { assert, prettyJson } = require('./utils')

const regex = /[0-9a-f]+:/
function getTextSection(objdumpOutput) {
  const lines = objdumpOutput.split('\n')
  const res = []
  let start = 0
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].includes('Disassembly of section .text') || lines[i].includes('Disassemblering av sektion .text')) {
      start = i + 3
      i = start
    } else if ((lines[i].includes('Disassembly') || lines[i].includes('Disassemblering')) && start != 0) {
      return res
    }
    if (start > 0) {
      if (regex.test(lines[i])) res.push(lines[i].trimStart().trimEnd())
    }
  }
  return res
}

function processObjdumpLines(insts) {
  const res = []
  for (const line of insts) {
    const pos = line.indexOf(':')
    const rep = line.indexOf('\t', pos + 2)
    if (rep != -1) {
      const decomposition = {
        addr: `0x${line.substring(0, pos)}`,
        opcode: line.substring(pos + 2, rep).trimEnd(),
        rep: line.substring(rep + 1),
      }
      res.push(decomposition)
    } else {
      // zydis appends padding to last instruction, apparently, making our tests fail. This way, we make objdump behave like Zydis
      res[res.length - 1].opcode = `${res[res.length - 1].opcode} ${line.substring(pos + 2).trimEnd()}`
    }
  }
  return res
}

function adjustPCBackToUnrelocated(programCounter) {
  // if addr is low, this system most likely creates PIE's for most things.
  // add the most common base-addr (0x555555554000) to the address to test this feature here.
  let num = Number.parseInt(programCounter, 16)
  if (num > 0x555555554000) {
    return `0x${(num - 0x555555554000).toString(16)}`
  }
  return programCounter
}

function compareDisassembly(pc, objdump, mdbResult) {
  if (mdbResult.length != objdump.length) {
    throw new Error(
      `(${pc}): Expected ${objdump.length} disassembled instructions but instead got ${
        mdbResult.length
      }. Serial data: ${JSON.stringify(mdbResult, null, 2)}. Expected data ${JSON.stringify(objdump, null, 2)}`
    )
  }
  for (let i = 0; i < objdump.length; ++i) {
    const resAddr = adjustPCBackToUnrelocated(mdbResult[i].address)
    const dumpAddr = objdump[i].addr
    assert(
      resAddr == dumpAddr,
      () =>
        `(${pc}): Expected disassembled instruction #${i} at address ${dumpAddr} but got ${resAddr}. Serial data: ${prettyJson(
          mdbResult
        )}. Expected data ${prettyJson(objdump)}`
    )

    if (
      mdbResult[i].instructionBytes != objdump.opcode &&
      mdbResult[i].instructionBytes.split(' ').join('') != objdump[i].opcode.split(' ').join('')
    ) {
      throw new Error(
        `(${pc}): Expected disassembled instruction to have opcode ${objdump[i].opcode} but got ${
          mdbResult[i].instructionBytes
        }. Serial data: ${JSON.stringify(mdbResult, null, 2)}. Expected data ${JSON.stringify(objdump, null, 2)}`
      )
    }
  }
}

async function disasm_verify(objdump, client, pc, insOffset, insCount) {
  const objdumpPc = adjustPCBackToUnrelocated(pc)
  const insIndex = objdump.findIndex(({ addr, opcode, rep }) => addr == objdumpPc)
  const offset = insIndex + insOffset
  const objdumpSpan = objdump.slice(offset, offset + insCount)
  const disassembly = await client.sendReqGetResponse('disassemble', {
    memoryReference: pc,
    offset: 0,
    instructionOffset: insOffset,
    instructionCount: insCount,
    resolveSymbols: false,
  })
  compareDisassembly(pc, objdumpSpan, disassembly.body.instructions)
}

/** @param { import("./client").DebugAdapterClient } debugAdapter */
async function backAndForward(debugAdapter) {
  const objdumped = spawnSync('objdump', ['-d', debugAdapter.buildDirFile('stackframes')]).stdout.toString()
  const insts_of_interest = getTextSection(objdumped)
  const objdump = processObjdumpLines(insts_of_interest)
  await debugAdapter.startRunToMain(debugAdapter.buildDirFile('stackframes'))
  const threads = await debugAdapter.threads()
  const frames = await threads[0].stacktrace()
  await disasm_verify(objdump, debugAdapter, frames[0].pc, 0, 10)
  await disasm_verify(objdump, debugAdapter, frames[0].pc, 5, 10)
  await disasm_verify(objdump, debugAdapter, frames[0].pc, -5, 10)
  await disasm_verify(objdump, debugAdapter, frames[0].pc, -30, 10)
  await disasm_verify(objdump, debugAdapter, frames[0].pc, -50, 10)
  await disasm_verify(objdump, debugAdapter, frames[0].pc, -100, 200)
  await disasm_verify(objdump, debugAdapter, frames[0].pc, 10, 2000)
}

const tests = {
  backAndForward: () => backAndForward,
}

module.exports = {
  tests: tests,
}
