const path = require('path')
const fs = require('fs')
const { spawnSync } = require('child_process')

function prettyJson(obj) {
  return JSON.stringify(obj, null, 2)
}

const RecognizedArgsConfig = [
  { short: 's', long: 'session', values: ['remote', 'native'] },
  { short: 'b', long: 'build-dir', values: null },
  { short: 't', long: 'test-suite', values: null },
  { short: 'u', long: 'test', values: null },
]

class TestArgs {
  /**
   * @param {ConfigParseResult} cfg
   */
  constructor(cfg) {
    const { map, config } = cfg
    for (const arg of RecognizedArgsConfig) {
      let maparg = map.get(arg.short)
      if (maparg == null) {
        maparg = map.get(arg.long)
        map.set(arg.short, maparg)
      } else {
        map.set(arg.long, maparg)
      }

      if (maparg == null) {
        throw new Error(`Required argument in short (-${arg.short}=<value>) or long form (--${arg.long}=<value>)`)
      }

      if (arg.values !== null) {
        if (!arg.values.some((e) => e == maparg)) {
          throw new Error(`Expected variant ${arg.values.join('|')} but got ${maparg}`)
        }
      }
    }
    this.map = map
    this.cfg = config
  }

  getBinary(exe_name) {
    return path.join(this.binaryDir, exe_name)
  }

  get binaryDir() {
    const build = this.buildDir
    if (build == null) {
      throw new Error(`No build directory was passed as an argument`)
    }
    const bin_path = path.join(build, 'bin')
    if (!fs.existsSync(bin_path)) {
      throw new Error(`Binary path did not exist: ${bin_path}`)
    }
    return bin_path
  }

  getServerBinary() {
    return this.cfg.server
  }

  getArg(arg) {
    const item = this.map.get(arg)
    if (item == null) {
      for (const recArg of RecognizedArgsConfig) {
        if (arg != recArg.short && arg == recArg.long) {
          return this.map.get(recArg.short)
        }
        if (arg != recArg.long && arg == recArg.short) {
          return this.map.get(recArg.long)
        }
      }
    }
    return item
  }

  get buildDir() {
    return this.map.get('b')
  }

  get testSuite() {
    return this.map.get('t')
  }

  get test() {
    return this.map.get('u')
  }

  get sessionKind() {
    return this.map.get('s')
  }
}

/**
 * @typedef {{ server: string }} HarnessConfiguration
 */

/**
 * @type {HarnessConfiguration}
 */
const defaultConfiguration = {
  server: 'gdbserver',
}

/**
 *
 * @param {string} cfgPath
 * @returns {HarnessConfiguration}
 */
function loadConfiguration(cfgPath) {
  if (fs.existsSync(cfgPath)) {
    const contents = fs.readFileSync(cfgPath)
    try {
      const result = JSON.parse(contents)
      return result
    } catch (ex) {
      console.log(`Failed to load test harness configuration from ${cfgPath}. Loading default`)
      return defaultConfiguration
    }
  } else {
    fs.writeFileSync(cfgPath, JSON.stringify(defaultConfiguration))
    return defaultConfiguration
  }
}

/**
 * @typedef {{ map: Map<string, string>, config: HarnessConfiguration }} ConfigParseResult
 */

/**
 * @param {string[]} argv
 * @returns {{ map: Map<string, string>, config: HarnessConfiguration }}
 */
function parseTestConfiguration(argv) {
  const map = new Map()

  argv.forEach((arg) => {
    if (arg.startsWith('--')) {
      if (arg.includes('=')) {
        const [key, value] = arg.slice(2).split('=')
        map.set(key, value)
      } else {
        const key = arg.slice(2)
        map.set(key, true)
      }
    } else if (arg.startsWith('-')) {
      if (arg.includes('=')) {
        const [key, value] = arg.slice(1).split('=')
        map.set(key, value)
      } else {
        const key = arg.slice(1)
        map.set(key, true)
      }
    }
  })

  const configPath = path.join(process.cwd(), 'testharness.config')
  const cfg = loadConfiguration(configPath)

  return { map: map, config: cfg }
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

function buildMaybeLazyMessage(msg) {
  if (typeof msg === 'function') {
    let res = msg()
    if (typeof res !== 'string') {
      throw new Error('Returned data from a (optionally) lazy message builder must be a string')
    }
    return res
  } else if (typeof msg === 'string') {
    return msg
  } else {
    throw new Error(`Type of (optionally) lazy message builder can not be of type ${typeof msg}`)
  }
}

function assertLog(boolCondition, AssertLogMessage, AssertErrorMessage = null) {
  if (AssertLogMessage == null) {
    throw new Error(
      'Assertion log message must not be null, it can be a string or a function that returns a string (for lazy construction of err messages)'
    )
  }
  const logMsg = buildMaybeLazyMessage(AssertLogMessage)
  if (!boolCondition) {
    if (AssertErrorMessage !== null) {
      const errMsg = buildMaybeLazyMessage(AssertErrorMessage)
      throw new Error(`${logMsg}: ${errMsg}`)
    } else {
      throw new Error(logMsg)
    }
  } else {
    console.log(`[ASSERTION]: ${logMsg}: PASSED`)
  }
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

function subject(fn) {
  return fn
}

function todo(fn) {
  if (typeof fn !== 'function') {
    throw new Error(`todo initializer must receive a function as a parameter`)
  }
  const err = new Error()
  err.message = `The ${fn.name} test is not implemented`
  err.testName = fn.name
  throw err
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

function allUniqueVariableReferences(variables) {
  // yes I know this is slower. 2 iterations. 2 created arrays. bla bla.
  const idsOnly = []
  for (const v of variables) {
    if (v.variablesReference != 0) idsOnly.push(v.variablesReference)
  }
  return new Set(idsOnly).size == idsOnly.length
}

/**
 * Verify that all objects in `varRefs` have unique variablesReference value.
 */
function assertAllVariableReferencesUnique(varRefs) {
  assert(
    allUniqueVariableReferences(varRefs),
    `Duplicate variablesReferences found (that were non-zero).\nResponse:\n${prettyJson(varRefs)}`
  )
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
  assertLog,
  assert_eq,
  assertEqAInB,
  isHexadecimalString,
  prettyJson,
  getPrintfPlt,
  allUniqueVariableReferences,
  assertAllVariableReferencesUnique,
  parseTestConfiguration,
  TestArgs,
}
