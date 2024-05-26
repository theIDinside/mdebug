const { checkResponse, getLineOf, readFileContents, repoDirFile, launchToGetFramesAndScopes } = require('./client')
const { assert, assertLog, assert_eq, prettyJson, getPrintfPlt } = require('./utils')

const bpRequest = 'setBreakpoints'

/**
 * @param {import("./client").DAClient } DA
 * @param {string} exe
 */
async function initLaunchToMain(DA, exe, { file, bps } = {}) {
  await DA.startRunToMain(DA.buildDirFile(exe), [], 1000)
  if (file) {
    const fileContent = readFileContents(repoDirFile(file))
    const bp_lines = bps
      .map((ident) => getLineOf(fileContent, ident))
      .filter((item) => item != null)
      .map((l) => ({ line: l }))
    assertLog(
      bp_lines.length == bps.length,
      `Expected ${bps.length} identifiers`,
      `Could not parse contents of  ${repoDirFile('test/next.cpp')} to find all string identifiers`
    )

    const breakpoint_response = await DA.sendReqGetResponse('setBreakpoints', {
      source: {
        name: repoDirFile(file),
        path: repoDirFile(file),
      },
      breakpoints: bp_lines,
    })
    assertLog(
      breakpoint_response.body.breakpoints.length == bps.length,
      `Expected to have set ${bps.length} breakpoints`,
      ` but only successfully set ${breakpoint_response.body.breakpoints.length}:\n${prettyJson(breakpoint_response)}`
    )
  }
}

/** @param {import("./client").DAClient } DA */
async function setup(DA, executableFile) {
  const init = await DA.sendReqGetResponse('initialize', {})
  checkResponse(init, 'initialize', true)
  const launch = await DA.sendReqGetResponse('launch', {
    program: DA.buildDirFile(executableFile),
    stopAtEntry: true,
  })
  checkResponse(launch, 'launch', true)
}

/** @param {import("./client").DAClient } debuggerAdapter */
async function setInstructionBreakpoint(debuggerAdapter) {
  // we don't care for initialize, that's tested elsewhere
  await debuggerAdapter.startRunToMain(debuggerAdapter.buildDirFile('stackframes'), [], 1000)
  const instructionAddress = '0x40088c'
  await debuggerAdapter
    .sendReqGetResponse('setInstructionBreakpoints', {
      breakpoints: [{ instructionReference: instructionAddress }],
    })
    .then((res) => {
      checkResponse(res, 'setInstructionBreakpoints', true)
      assertLog(res.body.breakpoints.length == 1, `Expected bkpts 1`, ` but got ${res.body.breakpoints.length}`)

      const { id, verified, instructionReference } = res.body.breakpoints[0]
      assertLog(verified, 'Expected breakpoint to be verified', ' but failed')
      assert_eq(
        instructionReference,
        instructionAddress,
        `Attempted to set ins breakpoint at ${instructionAddress} but it was set at ${instructionReference}`
      )
    })
}

/** @param {import("./client").DAClient } debuggerAdapter */
async function set4InSameCompUnit(debuggerAdapter) {
  await setup(debuggerAdapter, 'stackframes')
  const file = readFileContents(repoDirFile('test/stackframes.cpp'))
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
  assertLog(
    !found_all.some((v) => v == false),
    `Expected to get breakpoints for lines ${JSON.stringify(bp_lines)}`,
    ` but got ${prettyJson(res.body.breakpoints)}`
  )
}

/** @param {import("./client").DAClient } debuggerAdapter */
async function set2InDifferentCompUnit(debuggerAdapter) {
  await setup(debuggerAdapter, 'stackframes')
  const files = ['test/stackframes.cpp', 'test/templated_code/template.h']
  const bpIdentifier = 'BP3'

  let bps = files.map((file) => {
    const fullFilePath = repoDirFile(file)
    console.log(`Full file path: ${fullFilePath}`)
    return { file: fullFilePath, breakpoints: [{ line: getLineOf(readFileContents(fullFilePath), bpIdentifier) }] }
  })

  for (const { file, breakpoints } of bps) {
    const res = await debuggerAdapter.sendReqGetResponse('setBreakpoints', {
      source: {
        name: file,
        path: file,
      },
      breakpoints: breakpoints,
    })
    assertLog(
      res.body.breakpoints.length == breakpoints.length,
      `Expected to see ${breakpoints.length} breakpoints`,
      ` but saw ${res.body.breakpoints.length}.\n${prettyJson(res)}`
    )
    console.log(prettyJson(res))
  }
}

/** @param {import("./client").DAClient } DA */
async function setFunctionBreakpoint(DA) {
  await initLaunchToMain(DA, 'functionBreakpoints')
  const functions = ['Person', 'sayHello'].map((n) => ({ name: n }))

  const fnBreakpointResponse = await DA.sendReqGetResponse('setFunctionBreakpoints', {
    breakpoints: functions,
  })
  assertLog(
    fnBreakpointResponse.body.breakpoints.length == 5,
    `Expected 5 breakpoints from breakpoint requests: [${functions.map((v) => v.name)}]`,
    ` but got ${fnBreakpointResponse.body.breakpoints.length}: ${prettyJson(fnBreakpointResponse)}`
  )
  console.log(prettyJson(fnBreakpointResponse))
}

/** @param {import("./client").DAClient } debugAdapter */
async function setFunctionBreakpointUsingRegex(debugAdapter) {
  let { threads, frames, scopes } = await launchToGetFramesAndScopes(
    debugAdapter,
    'test/dynamicLoading.cpp',
    ['BP_PRE_OPEN', 'BP_PRE_DLSYM', 'BP_PRE_CALL', 'BP_PRE_CLOSE'],
    'perform_dynamic',
    'dynamicLoading'
  )

  const requestArgs = { breakpoints: [{ name: `less_than<\\w+>`, regex: true }] }
  const response = await debugAdapter.sendReqGetResponse('setFunctionBreakpoints', requestArgs)
  assertLog(
    response.body.breakpoints.length == 3,
    'Expected 3 breakpoints',
    ` but saw ${response.body.breakpoints.length}`
  )
  let breakpoint_events = debugAdapter.prepareWaitForEventN('breakpoint', 1, 5000)
  await debugAdapter.contNextStop(threads[0].id)
  const res = await breakpoint_events
  console.log(prettyJson(res))
}

/** @param {import("./client").DAClient } debugAdapter */
async function setBreakpointsThatArePending(debugAdapter) {
  // we don't care for initialize, that's tested elsewhere
  let stopped_promise = debugAdapter.prepareWaitForEventN('stopped', 1, 1000, setBreakpointsThatArePending)
  await setup(debugAdapter, 'stackframes')
  const printf_plt_addr = getPrintfPlt(debugAdapter, 'stackframes')
  const invalidAddressess = ['0x300000', '0x200000', '0x9800000', printf_plt_addr].map((v) => ({
    instructionReference: v,
  }))
  await debugAdapter
    .sendReqGetResponse('setInstructionBreakpoints', {
      breakpoints: invalidAddressess,
    })
    .then((res) => {
      console.log(prettyJson(res))
      checkResponse(res, 'setInstructionBreakpoints', true)
      assertLog(
        res.body.breakpoints.length == invalidAddressess.length,
        `Expected bkpts 1`,
        ` but got ${res.body.breakpoints.length}`
      )

      let expected = [{ verified: false }, { verified: false }, { verified: false }, { verified: true }]

      for (let i = 0; i < 4; ++i) {
        assertLog(
          res.body.breakpoints[i].verified == expected[i].verified,
          `Expected verified for ${i} to be ${expected[i].verified}`,
          ` but was ${res.body.breakpoints[i].verified}`
        )
      }
    })

  const cfg = await debugAdapter.sendReqGetResponse('configurationDone', {})
  assertLog(cfg.success, `configDone success`)
  await stopped_promise
}

/** @param {import("./client").DAClient } debugAdapter */
async function setNonExistingSourceBp(debugAdapter) {
  let { threads, frames, scopes } = await launchToGetFramesAndScopes(
    debugAdapter,
    'test/dynamicLoading.cpp',
    ['BP_PRE_OPEN', 'BP_PRE_DLSYM', 'BP_PRE_CALL', 'BP_PRE_CLOSE'],
    'perform_dynamic',
    'dynamicLoading'
  )

  const bp_lines = [{ line: 1 }, { line: 2 }, { line: 3 }]

  const res = await debugAdapter.sendReqGetResponse(bpRequest, {
    source: {
      name: repoDirFile('test/doesNotExist.cpp'),
      path: repoDirFile('test/doesNotExist.cpp'),
    },
    breakpoints: bp_lines,
  })

  console.log(prettyJson(res))
  assertLog(
    res.body.breakpoints.length == bp_lines.length,
    `Expected to see ${bp_lines.length} breakpoints`,
    ` but saw ${res.body.breakpoints.length}: \n${prettyJson(res)}`
  )
}

/** @param {import("./client").DAClient } debugAdapter */
async function set4ThenSet2(debugAdapter) {
  await debugAdapter.startRunToMain(debugAdapter.buildDirFile('stackframes'), [], 2000)
  const file = readFileContents(repoDirFile('test/stackframes.cpp'))
  {
    const bp_lines = ['BP1', 'BP2', 'BP3', 'BP4']
      .map((ident) => getLineOf(file, ident))
      .filter((item) => item != null)
      .map((l) => ({ line: l }))
    const res = await debugAdapter.sendReqGetResponse(bpRequest, {
      source: {
        name: repoDirFile('test/stackframes.cpp'),
        path: repoDirFile('test/stackframes.cpp'),
      },
      breakpoints: bp_lines,
    })

    checkResponse(res, bpRequest, true)
    assertLog(res.body.breakpoints.length == 4, `Expected 4 bkpts`, ` but got ${res.body.breakpoints.length}`)
    const found_all = [false, false, false]
    for (let i = 0; i < bp_lines.length; i++) {
      for (let bp of res.body.breakpoints) {
        if (bp.line == bp_lines[i].line) found_all[i] = true
      }
    }
    assertLog(
      !found_all.some((v) => v == false),
      `Expected to get breakpoints for lines ${JSON.stringify(bp_lines)}`,
      ` but got ${prettyJson(res.body.breakpoints)}`
    )
  }
  // Now, sending the same request, but only with BP1, BP2, we should get 2 breakpoints back, and the other two shall have been removed.
  {
    const bp_lines = ['BP3', 'BP4']
      .map((ident) => getLineOf(file, ident))
      .filter((item) => item != null)
      .map((l) => ({ line: l }))
    const res = await debugAdapter.sendReqGetResponse(bpRequest, {
      source: {
        name: repoDirFile('test/stackframes.cpp'),
        path: repoDirFile('test/stackframes.cpp'),
      },
      breakpoints: bp_lines,
    })

    checkResponse(res, bpRequest, true)
    assertLog(res.body.breakpoints.length == 2, `Expected 2 bkpts`, ` but got ${res.body.breakpoints.length}`)
    const found_all = [false, false]
    for (let i = 0; i < bp_lines.length; i++) {
      for (let bp of res.body.breakpoints) {
        if (bp.line == bp_lines[i].line) found_all[i] = true
      }
    }
    assertLog(
      !found_all.some((v) => v == false),
      `Expected to get breakpoints for lines ${JSON.stringify(bp_lines)}`,
      ` but got ${prettyJson(res.body.breakpoints)}`
    )
  }

  // continue to make sure we don't hit breakpoints at BP1 and BP2
  let threads = await debugAdapter.threads()
  await debugAdapter.contNextStop(threads[0].id)
  const frames = await debugAdapter.stackTrace()
  assertLog(
    frames.body.stackFrames[0].name == 'baz',
    `Expected to be in function 'baz'`,
    ` but was in '${frames.body.stackFrames[0].name}'`
  )
}

const tests = {
  setNonExistingSourceBp: () => setNonExistingSourceBp,
  set4InSameCompUnit: () => set4InSameCompUnit,
  set2InDifferentCompUnit: () => set2InDifferentCompUnit,
  setInstructionBreakpoint: () => setInstructionBreakpoint,
  setFunctionBreakpoint: () => setFunctionBreakpoint,
  setBreakpointsThatArePending: () => setBreakpointsThatArePending,
  setUsingRegexFunctionBreakpoint: () => setFunctionBreakpointUsingRegex,
  set4ThenSet2: () => set4ThenSet2,
}

module.exports = {
  tests: tests,
}
