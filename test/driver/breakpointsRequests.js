const {
  checkResponse,
  getLineOf,
  readFileContents,
  repoDirFile,
  launchToGetFramesAndScopes,
  PrepareBreakpointArguments,
} = require('./client')
const { findDisasmFunction, prettyJson, getPrintfPlt } = require('./utils')

const bpRequest = 'setBreakpoints'

/**
 * @param {import("./client").DebugAdapterClient } debugAdapter
 * @param {string} exe
 */
async function initLaunchToMain(debugAdapter, exe, { file, bps } = {}) {
  await debugAdapter.startRunToMain(debugAdapter.buildDirFile(exe), 1000)
  if (file) {
    const fileContent = readFileContents(repoDirFile(file))
    const bp_lines = bps
      .map((ident) => getLineOf(fileContent, ident))
      .filter((item) => item != null)
      .map((l) => ({ line: l }))
    await debugAdapter.assert(
      bp_lines.length == bps.length,
      `Expected ${bps.length} identifiers`,
      `Could not parse contents of  ${repoDirFile('test/next.cpp')} to find all string identifiers`
    )

    const breakpoint_response = await debugAdapter.sendReqGetResponse('setBreakpoints', {
      source: {
        name: repoDirFile(file),
        path: repoDirFile(file),
      },
      breakpoints: bp_lines,
    })
    await debugAdapter.assert(
      breakpoint_response.body.breakpoints.length == bps.length,
      `Expected to have set ${bps.length} breakpoints`,
      ` but only successfully set ${breakpoint_response.body.breakpoints.length}:\n${prettyJson(breakpoint_response)}`
    )
  }
}

/** @param {import("./client").DebugAdapterClient } debugAdapter */
async function setInstructionBreakpoint(debugAdapter) {
  // we don't care for initialize, that's tested elsewhere
  await debugAdapter.startRunToMain(debugAdapter.buildDirFile('stackframes'), 1000)
  const mainFnAddresses = findDisasmFunction('main', debugAdapter.buildDirFile('stackframes'))
  const instructionAddress = mainFnAddresses[1]
  await debugAdapter
    .sendReqGetResponse('setInstructionBreakpoints', {
      breakpoints: [{ instructionReference: instructionAddress }],
    })
    .then(async (res) => {
      checkResponse(res, 'setInstructionBreakpoints', true)
      await debugAdapter.assert(
        res.body.breakpoints.length == 1,
        `Expected bkpts 1`,
        ` but got ${res.body.breakpoints.length}`
      )

      const bpres = res.body.breakpoints[0]
      const { id, verified, instructionReference } = res.body.breakpoints[0]
      await debugAdapter.assert(verified, 'Expected breakpoint to be verified', `. Failed: ${JSON.stringify(bpres)}`)
      await debugAdapter.assert(
        instructionReference == instructionAddress,
        `Expected breakpoint at ${instructionAddress}`,
        `Was set at ${instructionReference}`
      )
    })
}

/** @param {import("./client").DebugAdapterClient } debugAdapter */
async function set4InSameCompUnit(debugAdapter) {
  await debugAdapter.startRunToMain(debugAdapter.buildDirFile('stackframes'), 1000)
  const file = readFileContents(repoDirFile('test/stackframes.cpp'))
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
  await debugAdapter.assert(
    res.body.breakpoints.length == 4,
    `Expected 4 breakpoints`,
    `Got ${res.body.breakpoints.length}`
  )
  const found_all = [false, false, false]
  for (let i = 0; i < bp_lines.length; i++) {
    for (let bp of res.body.breakpoints) {
      if (bp.line == bp_lines[i].line) found_all[i] = true
    }
  }
  await debugAdapter.assert(
    !found_all.some((v) => v == false),
    `Expected to get breakpoints for lines ${JSON.stringify(bp_lines)}`,
    ` but got ${prettyJson(res.body.breakpoints)}`
  )
}

/** @param {import("./client").DebugAdapterClient } debugAdapter */
async function set2InDifferentCompUnit(debugAdapter) {
  await debugAdapter.startRunToMain(debugAdapter.buildDirFile('stackframes'), 1000)
  const files = ['test/stackframes.cpp', 'test/templated_code/template.h']
  const bpIdentifier = 'BP3'

  let bps = files.map((file) => {
    const fullFilePath = repoDirFile(file)
    console.log(`Full file path: ${fullFilePath}`)
    return { file: fullFilePath, breakpoints: [{ line: getLineOf(readFileContents(fullFilePath), bpIdentifier) }] }
  })

  for (const { file, breakpoints } of bps) {
    const res = await debugAdapter.sendReqGetResponse('setBreakpoints', {
      source: {
        name: file,
        path: file,
      },
      breakpoints: breakpoints,
    })
    await debugAdapter.assert(
      res.body.breakpoints.length == breakpoints.length,
      `Expected to see ${breakpoints.length} breakpoints`,
      ` but saw ${res.body.breakpoints.length}.\n${prettyJson(res)}`
    )
    console.log(prettyJson(res))
  }
}

/** @param {import("./client").DebugAdapterClient } debugAdapter */
async function setFunctionBreakpoint(debugAdapter) {
  await initLaunchToMain(debugAdapter, 'functionBreakpoints')
  const functions = ['Person', 'sayHello'].map((n) => ({ name: n }))

  const fnBreakpointResponse = await debugAdapter.sendReqGetResponse('setFunctionBreakpoints', {
    breakpoints: functions,
  })
  await debugAdapter.assert(
    fnBreakpointResponse.body.breakpoints.length == 5,
    `Expected 5 breakpoints from breakpoint requests: [${functions.map((v) => v.name)}]`,
    ` but got ${fnBreakpointResponse.body.breakpoints.length}: ${prettyJson(fnBreakpointResponse)}`
  )
  console.log(prettyJson(fnBreakpointResponse))
}

/** @param {import("./client").DebugAdapterClient } debugAdapter */
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
  await debugAdapter.assert(
    response.body.breakpoints.length == 3,
    'Expected 3 breakpoints',
    ` but saw ${response.body.breakpoints.length}`
  )
  console.log(`now wait for 1 breakpoint event`)
  let breakpoint_events = debugAdapter.prepareWaitForEventN('breakpoint', 1, 1000)
  await debugAdapter.contNextStop(threads[0].id)
  await debugAdapter.contNextStop(threads[0].id)
  const res = await breakpoint_events
  console.log(prettyJson(res))
}

/** @param {import("./client").DebugAdapterClient } debugAdapter */
async function setBreakpointsThatArePending(debugAdapter) {
  // we don't care for initialize, that's tested elsewhere
  await debugAdapter.startRunToMain(debugAdapter.buildDirFile('stackframes'), 1000)
  const printf_plt_addr = getPrintfPlt(debugAdapter, 'stackframes')
  const invalidAddressess = ['0x300000', '0x100000', '0x9800000', printf_plt_addr].map((v) => ({
    instructionReference: v,
  }))
  await debugAdapter
    .sendReqGetResponse('setInstructionBreakpoints', {
      breakpoints: invalidAddressess,
    })
    .then(async (res) => {
      console.log(prettyJson(res))
      checkResponse(res, 'setInstructionBreakpoints', true)
      await debugAdapter.assert(
        res.body.breakpoints.length == invalidAddressess.length,
        `Expected bkpts 1`,
        ` but got ${res.body.breakpoints.length}`
      )

      let expected = [{ verified: false }, { verified: false }, { verified: false }, { verified: true }]

      for (let i = 0; i < 4; ++i) {
        await debugAdapter.assert(
          res.body.breakpoints[i].verified == expected[i].verified,
          `Expected verified for ${i} to be ${expected[i].verified}`,
          ` but was ${res.body.breakpoints[i].verified}`
        )
      }
    })
}

/** @param {import("./client").DebugAdapterClient } debugAdapter */
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

  await debugAdapter.assert(
    res.body.breakpoints.length == bp_lines.length,
    `Expected to see ${bp_lines.length} breakpoints`,
    ` but saw ${res.body.breakpoints.length}: \n${prettyJson(res)}`
  )
}

/** @param {import("./client").DebugAdapterClient } debugAdapter */
async function set4ThenSet2(debugAdapter) {
  await debugAdapter.startRunToMain(debugAdapter.buildDirFile('stackframes'), 1000)
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
    await debugAdapter.assert(
      res.body.breakpoints.length == 4,
      `Expected 4 bkpts`,
      ` but got ${res.body.breakpoints.length}`
    )
    const found_all = [false, false, false]
    for (let i = 0; i < bp_lines.length; i++) {
      for (let bp of res.body.breakpoints) {
        if (bp.line == bp_lines[i].line) found_all[i] = true
      }
    }
    await debugAdapter.assert(
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
    await debugAdapter.assert(
      res.body.breakpoints.length == 2,
      `Expected 2 bkpts`,
      ` but got ${res.body.breakpoints.length}`
    )
    const found_all = [false, false]
    for (let i = 0; i < bp_lines.length; i++) {
      for (let bp of res.body.breakpoints) {
        if (bp.line == bp_lines[i].line) found_all[i] = true
      }
    }
    await debugAdapter.assert(
      !found_all.some((v) => v == false),
      `Expected to get breakpoints for lines ${JSON.stringify(bp_lines)}`,
      ` but got ${prettyJson(res.body.breakpoints)}`
    )
  }

  // continue to make sure we don't hit breakpoints at BP1 and BP2
  let threads = await debugAdapter.threads()
  await debugAdapter.contNextStop(threads[0].id)
  const frames = await threads[0].stacktrace()
  await debugAdapter.assert(
    frames[0].name == 'baz',
    `Expected to be in function 'baz'`,
    ` but was in '${frames[0].name}'`
  )
}

/** @param {import("./client").DebugAdapterClient } debugAdapter */
async function testConditionShouldStopOn5(debugAdapter) {
  let { threads, frames, scopes } = await launchToGetFramesAndScopes(
    debugAdapter,
    'test/variables.cpp',
    ['FOR_LOOP_START_BREAKPOINT'],
    'forloop',
    'variables'
  )

  const args = await PrepareBreakpointArguments('test/variables.cpp', ['COND_BREAKPOINT'])

  let conditionLines = [
    'let frame = task.frame();', //1
    'let variable = frame.locals().find(v => v.name() == "i");',
    "if(variable.name() == 'i') {", //9
    '  if(variable == 5) {', //10
    '    bpstat.stop();', //11
    '    return;', //12
    '  } else {', //13
    "    mdb.log('variable is: ' + variable);", //14
    '  }', //15
    '}', //16
  ]

  args.breakpoints[0].condition = conditionLines.join('\n')

  let res = await debugAdapter.setBreakpointsRequest(args)
  checkResponse(res, 'setBreakpoints', true)
  await debugAdapter.contNextStop()
  {
    const stackTrace = await debugAdapter.stackTraceRequest({ threadId: threads[0].id })
    const scopes = await debugAdapter.scopesRequest({ frameId: stackTrace.body.stackFrames[0].id })
    const variables = await debugAdapter.variablesRequest({
      variablesReference: scopes.body.scopes[1].variablesReference,
    })
    await debugAdapter.assert(
      variables.body.variables[0].value == 5,
      `Breakpoint stopped succesfully with condition`,
      () => `Expected value of variable to be 5, was ${variables.body.variables[0].value}`
    )
  }
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
  testCondtionThatShouldNeverStop: () => testConditionShouldStopOn5,
}

module.exports = {
  tests: tests,
}
