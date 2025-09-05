const { checkResponse, getLineOf, readFileContents, repoDirFile, seconds } = require('./client')
const { objdump, hexStrAddressesEquals, assert, assertLog, prettyJson, getPrintfPlt } = require('./utils')

/**
 * @param { import("./client").DebugAdapterClient } client
 * @param {string} source - relative path to source file from source root of project.
 * @param {string[]} bps - identifiers to search for in the search file, to get a line in the file
 * @returns - returns the Debug Adapter Protocol response object
 */
async function setBreakpoints(client, source, bps) {
  const file = readFileContents(repoDirFile(source))
  const lineNumbers = bps
    .map((ident) => getLineOf(file, ident))
    .filter((item) => item != null)
    .map((l) => ({ line: l }))
  return client.sendReqGetResponse('setBreakpoints', {
    source: {
      name: repoDirFile(source),
      path: repoDirFile(source),
    },
    breakpoints: lineNumbers,
  })
}

/** @param { import("./client").DebugAdapterClient } client */
async function unwindFromSharedObject(client) {
  const sharedObjectsCount = 6

  async function setFnBp(fn) {
    const bps = fn.map((name) => ({ name: name }))
    return client.sendReqGetResponse('setFunctionBreakpoints', {
      breakpoints: bps,
    })
  }

  let modules_event_promise = client.prepareWaitForEventN('module', 6, seconds(1))
  await client.startRunToMain(client.buildDirFile('stupid_shared'), seconds(1))
  const res = await modules_event_promise

  const bp_res = await setFnBp(['convert_kilometers_to_miles'])
  console.log(`bpres ${JSON.stringify(bp_res)}`)

  assertLog(
    res.length >= sharedObjectsCount,
    `Expected to see >= 6 module events for shared objects, saw ${res.length}`
  )

  const threads = await client.threads()
  const bps = await client.setBreakpointsRequest({}, { source: 'test/todo.cpp', identifiers: ['BP1'] })

  assertLog(bps.body.breakpoints.length == 1, 'Expected 1 breakpoint')
  const bps2 = await client.setBreakpointsRequest({}, { source: 'test/dynamic_lib.cpp', identifiers: ['BPKM'] })

  assertLog(bps2.body.breakpoints.length == 1, 'Expected 1 breakpoint')
  // hit breakpoint in todo.cpp
  // await DA.sendReqWaitEvent('continue', { threadId: threads[0].id }, 'stopped', seconds(1))
  await client.contNextStop()
  await client.contNextStop()
  const frames = await client.stackTrace(threads[0].id, seconds(1)).then((res) => {
    checkResponse(res, 'stackTrace', true)
    const { stackFrames } = res.body
    return stackFrames
  })
  const name = 'convert_kilometers_to_miles'
  assertLog(
    frames[0].name == name,
    `Expected frame ${name}`,
    `Got ${frames[0].name}. Stacktrace:\n${prettyJson(frames)}`
  )
}

/** @param { import("./client").DebugAdapterClient } client */
function parse_prologue_and_epilogue(client) {
  const objdumped = objdump(client.buildDirFile('stackframes')).split('\n')
  let lineNumber = 0
  let found = false
  let res = { prologue: null, epilogue: null }
  for (const line of objdumped) {
    if (!found) {
      let i = line.indexOf('<_ZL3barii>:')
      if (i != -1) {
        const addr = line.substring(0, i).trim()
        res.prologue = `0x${addr}`
        found = true
      }
    } else {
      let i = line.indexOf('ret')
      if (i != -1) {
        const addr = line.substring(0, i).trim().split(':')[0].trim()
        res.epilogue = `0x${addr}`
        console.log(`bar frame: ${JSON.stringify(res)}`)
        return res
      }
    }
    lineNumber += 1
  }
  assert(false, 'Could not find prologue and epilogue of bar')
}

function verifyFrameIs(frame, name) {
  assertLog(frame.name == name, `Expected frame ${name} but got ${frame.name}`)
}

/** @param { import("./client").DebugAdapterClient } client */
async function insidePrologueTest(client) {
  const { prologue, epilogue } = parse_prologue_and_epilogue(client)
  await client.startRunToMain(client.buildDirFile('stackframes'), seconds(1))
  await client.setInsBreakpoint(prologue)
  await client.contNextStop()
  const frames = await client.stackTrace().then(({ response_seq, command, type, success, body: { stackFrames } }) => {
    checkResponse({ type, success, command }, 'stackTrace', true)
    let application_frames = 0
    for (const f of stackFrames) {
      application_frames++
      if (f.name == 'main') {
        break
      }
    }
    assert(
      application_frames == 3,
      `We're exactly at the start of the first instruction of main - expecting only 3 frame but got ${
        stackFrames.length
      }: ${JSON.stringify(stackFrames)}`
    )
    return stackFrames
  })
  console.log(`${JSON.stringify(frames, null, 2)}`)
  verifyFrameIs(frames[0], 'bar')
  verifyFrameIs(frames[1], 'foo')
  verifyFrameIs(frames[2], 'main')
}

/** @param { import("./client").DebugAdapterClient } client */
async function insideEpilogueTest(client) {
  const { prologue, epilogue } = parse_prologue_and_epilogue(client)
  await client.startRunToMain(client.buildDirFile('stackframes'), seconds(1))
  await client.setInsBreakpoint(epilogue)
  await client.contNextStop()
  const frames = await client.stackTrace().then(({ response_seq, command, type, success, body: { stackFrames } }) => {
    checkResponse({ type, success, command }, 'stackTrace', true)
    let application_frames = 0
    for (const f of stackFrames) {
      application_frames++
      if (f.name == 'main') {
        break
      }
    }
    assert(
      application_frames == 3,
      () =>
        `We're exactly at the start of the first instruction of main - expecting only 3 frame but got ${
          stackFrames.length
        }: ${JSON.stringify(stackFrames)}`
    )
    return stackFrames
  })
  verifyFrameIs(frames[0], 'bar')
  verifyFrameIs(frames[1], 'foo')
  verifyFrameIs(frames[2], 'main')
}

function createExpectedStacktraces() {
  const sourceFileContents = readFileContents(repoDirFile('test/stackframes.cpp'))

  const callstack = (idents) =>
    idents
      .map((ident) => getLineOf(sourceFileContents, ident))
      .filter((item) => item != null)
      .map((l) => ({ line: l }))
  const checks = ['A', 'B', 'C', 'D']
  const [callstackA, callstackB, callstackC, callstackD] = [2, 3, 4, 5]
    .map((num, checkIndex) => new Array(num).fill(0).map((_, index) => `${checks[checkIndex]}${index + 1}`))
    .map((stack) => callstack(stack))
  const names = ['quux', 'baz', 'bar', 'foo', 'main']

  // the C/ELF/posix runtime usually have 3 frames above the main function, the first one being _start.
  const libcStack = [
    { line: 0, name: '*' },
    { line: 0, name: '*' },
    { line: 0, name: '_start' },
  ]

  const cs = [callstackA, callstackB, callstackC, callstackD].map((stack) =>
    stack
      .map((item, index) => ({ line: item.line, name: names.slice(names.length - stack.length)[index] }))
      .concat(libcStack)
  )
  console.log(`expected: ${JSON.stringify(cs, null, 2)}`)
  return cs
}

/** @param { import("./client").DebugAdapterClient } client */
async function normalTest(client) {
  const expectedStackTraces = createExpectedStacktraces(client)

  await client.startRunToMain(client.buildDirFile('stackframes'), seconds(1))
  const file = readFileContents(repoDirFile('test/stackframes.cpp'))
  const bp_lines = ['BP1', 'BP2', 'BP3', 'BP4']
    .map((ident) => getLineOf(file, ident))
    .filter((item) => item != null)
    .map((l) => ({ line: l }))
  if (bp_lines.length != 4) throw new Error(`Expected to find 4 breakpoint locations but found ${bp_lines.length}`)
  const bpResponse = await client.sendReqGetResponse('setBreakpoints', {
    source: {
      name: repoDirFile('test/stackframes.cpp'),
      path: repoDirFile('test/stackframes.cpp'),
    },
    breakpoints: bp_lines,
  })
  const threads = await client.threads()
  {
    const frames = await client
      .stackTrace(threads[0].id)
      .then(({ response_seq, command, type, success, body: { stackFrames } }) => {
        checkResponse({ type, success, command }, 'stackTrace', true)
        return stackFrames
      })
    assert(
      frames.length == 4,
      () =>
        `We're exactly at the start of the first instruction of main - expecting only 1 frame but got ${
          stackFrames.length
        }: ${prettyJson(stackFrames)}`
    )

    const scopes = []
    for (const frame of frames) {
      scopes.push(await client.sendReqGetResponse('scopes', { frameId: frame.id }))
    }
    if (scopes.length != frames.length) throw new Error(`Expected ${frames.length} scopes but got ${scopes.length}`)
  }
  const total = 5
  for (let i = total; i < 9; i++) {
    await client.sendReqWaitEvent('continue', { threadId: threads[0].id }, 'stopped', seconds(1))
    await client.stackTrace(threads[0].id).then((res) => {
      checkResponse(res, 'stackTrace', true)
      const { stackFrames } = res.body
      if (stackFrames.length != i) {
        throw new Error(
          `Expected ${i} stackframes but got ${stackFrames.length}: ${JSON.stringify(stackFrames, null, 2)}`
        )
      }

      for (const idx in stackFrames) {
        assert(
          stackFrames[idx].line == expectedStackTraces[i - total][idx].line,
          () =>
            `Expected line to be at ${expectedStackTraces[i - total][idx].line} but was ${
              stackFrames[idx].line
            }: ${prettyJson(stackFrames)}`
        )
        if (
          stackFrames[idx].name != expectedStackTraces[i - total][idx].name &&
          expectedStackTraces[i - total][idx].name != '*'
        ) {
          assert(
            false,
            `Expected name to be ${expectedStackTraces[i - total][idx].name} but was ${
              stackFrames[idx].name
            }: ${prettyJson(stackFrames)}`
          )
        }
      }
    })
  }
}

function* walk_expected_frames(frames) {
  for (let i = 1; i < frames.length; i++) yield frames[i]
}

/** @param { import("./client").DebugAdapterClient } client */
async function unwindWithDwarfExpression(client) {
  const printf_plt_addr = getPrintfPlt(client, 'next')
  console.log(`printf@plt address: ${printf_plt_addr}`)
  await client.startRunToMain(client.buildDirFile('next'), seconds(1))
  await client
    .sendReqGetResponse('setInstructionBreakpoints', {
      breakpoints: [{ instructionReference: printf_plt_addr }],
    })
    .then((res) => {
      console.log(prettyJson(res))
      checkResponse(res, 'setInstructionBreakpoints', true)
      assert(
        res.body.breakpoints.length == 1,
        `Expected bkpts 1 but got ${res.body.breakpoints.length}: ${prettyJson(res)}`
      )

      const { id, verified, instructionReference } = res.body.breakpoints[0]
      assert(verified, 'Expected breakpoint to be verified and exist!')
      assert(
        hexStrAddressesEquals(instructionReference, printf_plt_addr),
        `Attempted to set ins breakpoint at ${printf_plt_addr} but it was set at ${instructionReference}`
      )
    })
  const threads = await client.threads()
  await client.contNextStop(threads[0].id)

  const verify_correct_stacktrace = (frames, expected) => {
    let idx = 0
    for (const f of walk_expected_frames(frames)) {
      assert(f.name == expected[idx].name, `Expected frame to be '${expected[idx].name}' but was '${f.name}'`)
      idx++
      if (idx >= expected.length) return
    }
  }

  {
    const {
      body: { stackFrames },
    } = await client.stackTrace(threads[0].id)
    verify_correct_stacktrace(stackFrames, [{ name: 'print' }, { name: 'main' }])
  }
  await client.contNextStop(threads[0].id)
  {
    const {
      body: { stackFrames },
    } = await client.stackTrace(threads[0].id)
    verify_correct_stacktrace(stackFrames, [{ name: 'print' }, { name: 'bar' }, { name: 'foo' }, { name: 'main' }])
  }
}

const tests = {
  insidePrologue: () => insidePrologueTest,
  insideEpilogue: () => insideEpilogueTest,
  normal: () => normalTest,
  unwindFromSharedObject: () => unwindFromSharedObject,
  unwindWithDwarfExpression: () => unwindWithDwarfExpression,
}

module.exports = {
  tests: tests,
}
