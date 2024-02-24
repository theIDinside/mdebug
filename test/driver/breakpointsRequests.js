const { checkResponse, getLineOf, readFile, repoDirFile } = require('./client')
const { assert, assert_eq, prettyJson } = require('./utils')

async function initLaunchToMain(DA, exe, { file, bps } = {}) {
  await DA.launchToMain(DA.buildDirFile(exe))
  if (file) {
    const fileContent = readFile(repoDirFile(file))
    const bp_lines = bps
      .map((ident) => getLineOf(fileContent, ident))
      .filter((item) => item != null)
      .map((l) => ({ line: l }))
    assert(
      bp_lines.length == bps.length,
      `Could not parse contents of  ${repoDirFile('test/next.cpp')} to find all string identifiers`
    )

    const breakpoint_response = await DA.sendReqGetResponse('setBreakpoints', {
      source: {
        name: repoDirFile(file),
        path: repoDirFile(file),
      },
      breakpoints: bp_lines,
    })
    assert(
      breakpoint_response.body.breakpoints.length == bps.length,
      `Expected to have set ${bps.length} breakpoints but only successfully set ${
        breakpoint_response.body.breakpoints.length
      }:\n${prettyJson(breakpoint_response)}`
    )
  }
}

async function setup(DA, executableFile) {
  const init = await DA.sendReqGetResponse('initialize', {})
  checkResponse(init, 'initialize', true)
  const launch = await DA.sendReqGetResponse('launch', {
    program: DA.buildDirFile(executableFile),
    stopAtEntry: true,
  })
  checkResponse(launch, 'launch', true)
}

async function setInstructionBreakpoint(debuggerAdapter) {
  // we don't care for initialize, that's tested elsewhere
  await setup(debuggerAdapter, 'stackframes')

  await debuggerAdapter
    .sendReqGetResponse('setInstructionBreakpoints', {
      breakpoints: [{ instructionReference: '0x40127e' }],
    })
    .then((res) => {
      checkResponse(res, 'setInstructionBreakpoints', true)
      assert(res.body.breakpoints.length == 1, `Expected bkpts 1 but got ${res.body.breakpoints.length}`)

      const { id, verified, instructionReference } = res.body.breakpoints[0]
      assert(verified, 'Expected breakpoint to be verified and exist!')
      assert_eq(
        instructionReference,
        '0x40127e',
        `Attempted to set ins breakpoint at 0x40127e but it was set at ${instructionReference}`
      )
    })
}

async function set4InSameCompUnit(debuggerAdapter) {
  await setup(debuggerAdapter, 'stackframes')
  const bpRequest = 'setBreakpoints'
  const file = readFile(repoDirFile('test/stackframes.cpp'))
  const bp_lines = ['BP1', 'BP2', 'BP3', 'BP4']
    .map((ident) => getLineOf(file, ident))
    .filter((item) => item != null)
    .map((l) => ({ line: l }))
  const res = await debuggerAdapter.sendReqGetResponse(bpRequest, {
    source: {
      name: repoDirFile('test/stackframes.cpp'),
      path: repoDirFile('test/stackframes.cpp'),
    },
    breakpoints: bp_lines,
  })

  checkResponse(res, bpRequest, true)
  assert_eq(res.body.breakpoints.length, 4, `Expected bkpts 3 but got ${res.body.breakpoints.length}`)
  const found_all = [false, false, false]
  for (let i = 0; i < bp_lines.length; i++) {
    for (let bp of res.body.breakpoints) {
      if (bp.line == bp_lines[i].line) found_all[i] = true
    }
  }
  assert(
    !found_all.some((v) => v == false),
    `Expected to get breakpoints for lines ${JSON.stringify(bp_lines)} but got ${prettyJson(res.body.breakpoints)}`
  )
  console.log(`Test ${__filename} succeeded`)
  process.exit(0)
}

async function set2InDifferentCompUnit(debuggerAdapter) {
  await setup(debuggerAdapter, 'stackframes')
  const files = ['test/stackframes.cpp', 'test/templated_code/template.h']
  const bpIdentifier = 'BP3'

  let bps = files.map((file) => {
    const fullFilePath = repoDirFile(file)
    console.log(`Full file path: ${fullFilePath}`)
    return { file: fullFilePath, line: getLineOf(readFile(fullFilePath), bpIdentifier) }
  })

  for (const { file, line } of bps) {
    const res = await debuggerAdapter.sendReqGetResponse('setBreakpoints', {
      source: {
        name: file,
        path: file,
      },
      breakpoints: [{ line: line }],
    })
  }
}

async function setFunctionBreakpoint(DA) {
  await initLaunchToMain(DA, 'functionBreakpoints')
  const functions = ['Person', 'sayHello'].map((n) => ({ name: n }))

  const fnBreakpointResponse = await DA.sendReqGetResponse('setFunctionBreakpoints', {
    breakpoints: functions,
  })
  assert(
    fnBreakpointResponse.body.breakpoints.length == 5,
    () =>
      `Expected 5 breakpoints from breakpoint requests: [${functions.map((v) => v.name)}] but only got ${
        fnBreakpointResponse.body.breakpoints.length
      }`
  )
  console.log(prettyJson(fnBreakpointResponse))
}

const tests = {
  set4InSameCompUnit: set4InSameCompUnit,
  set2InDifferentCompUnit: set2InDifferentCompUnit,
  setInstructionBreakpoint: setInstructionBreakpoint,
  setFunctionBreakpoint: setFunctionBreakpoint,
}

module.exports = {
  tests: tests,
}
