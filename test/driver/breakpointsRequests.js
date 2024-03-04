const { checkResponse, getLineOf, readFile, repoDirFile } = require('./client')
const { assert, assert_eq, prettyJson, getPrintfPlt } = require('./utils')

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
  const instructionAddress = '0x40088c'
  await debuggerAdapter
    .sendReqGetResponse('setInstructionBreakpoints', {
      breakpoints: [{ instructionReference: instructionAddress }],
    })
    .then((res) => {
      checkResponse(res, 'setInstructionBreakpoints', true)
      assert(res.body.breakpoints.length == 1, `Expected bkpts 1 but got ${res.body.breakpoints.length}`)

      const { id, verified, instructionReference } = res.body.breakpoints[0]
      assert(verified, 'Expected breakpoint to be verified and exist!')
      assert_eq(
        instructionReference,
        instructionAddress,
        `Attempted to set ins breakpoint at ${instructionAddress} but it was set at ${instructionReference}`
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
    return { file: fullFilePath, breakpoints: [{ line: getLineOf(readFile(fullFilePath), bpIdentifier) }] }
  })

  for (const { file, breakpoints } of bps) {
    const res = await debuggerAdapter.sendReqGetResponse('setBreakpoints', {
      source: {
        name: file,
        path: file,
      },
      breakpoints: breakpoints,
    })
    assert(
      res.body.breakpoints.length == breakpoints.length,
      () => `Expected to see ${breakpoints.length} but saw ${res.body.breakpoints.length}.\n${prettyJson(res)}`
    )
    console.log(prettyJson(res))
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

async function setBreakpointsThatArePending(debuggerAdapter) {
  // we don't care for initialize, that's tested elsewhere
  let stopped_promise = debuggerAdapter.prepareWaitForEventN('stopped', 1, 1000, setBreakpointsThatArePending)
  await setup(debuggerAdapter, 'stackframes')
  const printf_plt_addr = getPrintfPlt(debuggerAdapter, 'stackframes')
  const invalidAddressess = ['0x300000', '0x200000', '0x9800000', printf_plt_addr].map((v) => ({
    instructionReference: v,
  }))
  await debuggerAdapter
    .sendReqGetResponse('setInstructionBreakpoints', {
      breakpoints: invalidAddressess,
    })
    .then((res) => {
      console.log(prettyJson(res))
      checkResponse(res, 'setInstructionBreakpoints', true)
      assert(
        res.body.breakpoints.length == invalidAddressess.length,
        `Expected bkpts 1 but got ${res.body.breakpoints.length}`
      )

      let expected = [{ verified: false }, { verified: false }, { verified: false }, { verified: true }]

      for (let i = 0; i < 4; ++i) {
        assert(
          res.body.breakpoints[i].verified == expected[i].verified,
          `Expected verified for ${i} to be ${expected[i].verified}`
        )
      }
    })

  const cfg = await debuggerAdapter.sendReqGetResponse('configurationDone', {})
  assert(cfg.success)
  await stopped_promise
}

const tests = {
  set4InSameCompUnit: set4InSameCompUnit,
  set2InDifferentCompUnit: set2InDifferentCompUnit,
  setInstructionBreakpoint: setInstructionBreakpoint,
  setFunctionBreakpoint: setFunctionBreakpoint,
  setBreakpointsThatArePending: setBreakpointsThatArePending,
}

module.exports = {
  tests: tests,
}
