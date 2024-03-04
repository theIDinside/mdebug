const { spawnSync } = require('child_process')

function prettyJson(obj) {
  return JSON.stringify(obj, null, 2)
}

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

function objdump(file) {
  return spawnSync('objdump', ['-d', file]).stdout.toString()
}

function hexStrAddressesEquals(a, b) {
  let addr_a = Number.parseInt(a, 16)
  let addr_b = Number.parseInt(b, 16)

  if (Number.isNaN(addr_a) || Number.isNaN(addr_b)) {
    throw new Error(`Could not parse hex strings ${a} or ${b} to numbers`)
  }
  return addr_a == addr_b
}

function assert(boolCondition, errMsg) {
  if (!boolCondition) {
    if (typeof errMsg === 'function') {
      const errMessage = errMsg()
      if (typeof errMessage !== 'string')
        throw new Error('Expected return type from errMessage function to be of string')
      throw new Error(errMessage)
    } else if (typeof errMsg === 'string') {
      throw new Error(errMsg)
    } else {
      throw new Error('errMsg parameter expected to be a string or a function returning a string.')
    }
  }
}

/**
 * @param {any} a
 * @param {any} b
 * @param {string | () => string } errMsg
 */
function assert_eq(a, b, errMsg) {
  assert(a == b, errMsg)
}

function todo(fnName) {
  const err = new Error()
  err.message = `The ${fnName} test is not implemented`
  return async (da) => {
    throw err
  }
}

// Compares all values in a and makes sure they exist and are equal in B. Note that this does not necessarily mean that B == A, only that A is a subset of B.
function assertEqAInB(expectedValue, b) {
  if (expectedValue == undefined) throw new Error(`expectedValue was undefined`)
  if (b == undefined) throw new Error(`b was undefined`)
  for (let prop in expectedValue) {
    if (typeof expectedValue[prop] === 'function') {
      if (!expectedValue[prop](b[prop])) {
        throw new Error(`Comparison function failed: ${expectedValue[prop]}\nInput value:\n${prettyJson(b)}`)
      }
    } else if (expectedValue[prop] !== b[prop]) {
      throw new Error(
        `expectedValue["${prop}"] != b["${prop}"]. expectedValue = ${prettyJson(expectedValue)}\nb = ${prettyJson(b)}`
      )
    }
  }
}

function isHexadecimalString(input) {
  if (input.split(' ').length > 1) throw new Error(`String should not contain white spaces: ${input}`)
  return !isNaN(input)
}

function getPrintfPlt(DA, executable) {
  const objdumped = objdump(DA.buildDirFile(executable)).split('\n')
  for (const line of objdumped) {
    let i = line.indexOf('<printf@plt>:')
    if (i != -1) {
      const addr = line.substring(0, i).trim()
      return `0x${addr}`
    }
  }
  throw new Error('Could not find prologue and epilogue of bar')
}

module.exports = {
  objdump,
  getTextSection,
  processObjdumpLines,
  hexStrAddressesEquals,
  todo,
  assert,
  assert_eq,
  assertEqAInB,
  isHexadecimalString,
  prettyJson,
  getPrintfPlt,
}
