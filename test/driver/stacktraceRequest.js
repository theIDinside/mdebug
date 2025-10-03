const { checkResponse, getLineOf, readFileContents, repoDirFile, seconds } = require('./client')
const { objdump, hexStrAddressesEquals, prettyJson, getPrintfPlt } = require('./utils')

/** @param { import("./client").DebugAdapterClient } debugAdapter */
async function unwindFromSharedObject(debugAdapter) {
  const sharedObjectsCount = 6

  async function setFnBp(fn) {
    const bps = fn.map((name) => ({ name: name }))
    return debugAdapter.sendReqGetResponse('setFunctionBreakpoints', {
      breakpoints: bps,
    })
  }

  let modules_event_promise = debugAdapter.prepareWaitForEventN('module', 6, seconds(1))
  await debugAdapter.startRunToMain(debugAdapter.buildDirFile('stupid_shared'), seconds(1))
  const res = await modules_event_promise

  const bp_res = await setFnBp(['convert_kilometers_to_miles'])
  console.log(`bpres ${JSON.stringify(bp_res)}`)

  await debugAdapter.assert(
    res.length >= sharedObjectsCount,
    `Expected to see >= 6 module events for shared objects.`,
    `Saw ${res.length}`
  )

  const threads = await debugAdapter.threads()
  const bps = await debugAdapter.setBreakpointsRequest({}, { source: 'test/todo.cpp', identifiers: ['BP1'] })

  await debugAdapter.assert(
    bps.body.breakpoints.length == 1,
    'Expected 1 breakpoint',
    `Saw ${bps.body.breakpoints.length}`
  )
  const bps2 = await debugAdapter.setBreakpointsRequest({}, { source: 'test/dynamic_lib.cpp', identifiers: ['BPKM'] })

  await debugAdapter.assert(bps2.body.breakpoints.length == 1, 'Expected 1 breakpoint')
  // hit breakpoint in todo.cpp
  // await DA.sendReqWaitEvent('continue', { threadId: threads[0].id }, 'stopped', seconds(1))
  await debugAdapter.contNextStop()
  await debugAdapter.contNextStop()
  const frames = await debugAdapter.stackTrace(threads[0].id, seconds(1)).then((res) => {
    checkResponse(res, 'stackTrace', true)
    const { stackFrames } = res.body
    return stackFrames
  })
  const name = 'convert_kilometers_to_miles'
  await debugAdapter.assert(
    frames[0].name == name,
    `Expected frame ${name}`,
    `Got ${frames[0].name}. Stacktrace:\n${prettyJson(frames)}`
  )
}

/** @param { import("./client").DebugAdapterClient } debugAdapter */
async function parsePrologueAndEpilogue(debugAdapter) {
  const objdumped = objdump(debugAdapter.buildDirFile('stackframes')).split('\n')
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
  await debugAdapter.assert(false, 'Could not find prologue and epilogue of bar')
}

async function verifyFrameIs(debugAdapter, frame, name) {
  await debugAdapter.assert(frame.name == name, `Expected frame ${name} but got ${frame.name}`)
}

/** @param { import("./client").DebugAdapterClient } debugAdapter */
async function insidePrologueTest(debugAdapter) {
  const { prologue, epilogue } = await parsePrologueAndEpilogue(debugAdapter)
  await debugAdapter.startRunToMain(debugAdapter.buildDirFile('stackframes'), seconds(1))
  await debugAdapter.setInsBreakpoint(prologue)
  await debugAdapter.contNextStop()
  const frames = await debugAdapter
    .stackTrace()
    .then(async ({ response_seq, command, type, success, body: { stackFrames } }) => {
      checkResponse({ type, success, command }, 'stackTrace', true)
      let application_frames = 0
      for (const f of stackFrames) {
        application_frames++
        if (f.name == 'main') {
          break
        }
      }
      await debugAdapter.assert(
        application_frames == 3,
        `We're exactly at the start of the first instruction of main - expecting only 3 frame but got ${
          stackFrames.length
        }: ${JSON.stringify(stackFrames)}`
      )
      return stackFrames
    })
  console.log(`${JSON.stringify(frames, null, 2)}`)
  await verifyFrameIs(debugAdapter, frames[0], 'bar')
  await verifyFrameIs(debugAdapter, frames[1], 'foo')
  await verifyFrameIs(debugAdapter, frames[2], 'main')
}

/** @param { import("./client").DebugAdapterClient } debugAdapter */
async function insideEpilogueTest(debugAdapter) {
  const { prologue, epilogue } = await parsePrologueAndEpilogue(debugAdapter)
  await debugAdapter.startRunToMain(debugAdapter.buildDirFile('stackframes'), seconds(1))
  await debugAdapter.setInsBreakpoint(epilogue)
  await debugAdapter.contNextStop()
  const frames = await debugAdapter
    .stackTrace()
    .then(async ({ response_seq, command, type, success, body: { stackFrames } }) => {
      checkResponse({ type, success, command }, 'stackTrace', true)
      let application_frames = 0
      for (const f of stackFrames) {
        application_frames++
        if (f.name == 'main') {
          break
        }
      }
      await debugAdapter.assert(
        application_frames == 3,
        () =>
          `We're exactly at the start of the first instruction of main - expecting only 3 frame but got ${
            stackFrames.length
          }: ${JSON.stringify(stackFrames)}`
      )
      return stackFrames
    })
  await verifyFrameIs(debugAdapter, frames[0], 'bar')
  await verifyFrameIs(debugAdapter, frames[1], 'foo')
  await verifyFrameIs(debugAdapter, frames[2], 'main')
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

/** @param { import("./client").DebugAdapterClient } debugAdapter */
async function normalTest(debugAdapter) {
  const expectedStackTraces = createExpectedStacktraces(debugAdapter)

  await debugAdapter.startRunToMain(debugAdapter.buildDirFile('stackframes'), seconds(1))
  const file = readFileContents(repoDirFile('test/stackframes.cpp'))
  const bp_lines = ['BP1', 'BP2', 'BP3', 'BP4']
    .map((ident) => getLineOf(file, ident))
    .filter((item) => item != null)
    .map((l) => ({ line: l }))
  if (bp_lines.length != 4) throw new Error(`Expected to find 4 breakpoint locations but found ${bp_lines.length}`)
  const bpResponse = await debugAdapter.sendReqGetResponse('setBreakpoints', {
    source: {
      name: repoDirFile('test/stackframes.cpp'),
      path: repoDirFile('test/stackframes.cpp'),
    },
    breakpoints: bp_lines,
  })
  const threads = await debugAdapter.threads()
  {
    const frames = await debugAdapter
      .stackTrace(threads[0].id)
      .then(({ response_seq, command, type, success, body: { stackFrames } }) => {
        checkResponse({ type, success, command }, 'stackTrace', true)
        return stackFrames
      })
    await debugAdapter.assert(
      frames.length == 4,
      () =>
        `We're exactly at the start of the first instruction of main - expecting only 1 frame but got ${
          frames.length
        }: ${prettyJson(frames)}`
    )

    const scopes = []
    for (const frame of frames) {
      scopes.push(await debugAdapter.sendReqGetResponse('scopes', { frameId: frame.id }))
    }
    if (scopes.length != frames.length) throw new Error(`Expected ${frames.length} scopes but got ${scopes.length}`)
  }
  const total = 5
  for (let i = total; i < 9; i++) {
    await debugAdapter.sendReqWaitEvent('continue', { threadId: threads[0].id }, 'stopped', seconds(1))
    await debugAdapter.stackTrace(threads[0].id).then(async (res) => {
      checkResponse(res, 'stackTrace', true)
      const { stackFrames } = res.body
      if (stackFrames.length != i) {
        throw new Error(
          `Expected ${i} stackframes but got ${stackFrames.length}: ${JSON.stringify(stackFrames, null, 2)}`
        )
      }

      for (const idx in stackFrames) {
        await debugAdapter.assert(
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
          await debugAdapter.assert(
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

/** @param { import("./client").DebugAdapterClient } debugAdapter */
async function unwindWithDwarfExpression(debugAdapter) {
  const printf_plt_addr = getPrintfPlt(debugAdapter, 'next')
  console.log(`printf@plt address: ${printf_plt_addr}`)
  await debugAdapter.startRunToMain(debugAdapter.buildDirFile('next'), seconds(1))
  await debugAdapter
    .sendReqGetResponse('setInstructionBreakpoints', {
      breakpoints: [{ instructionReference: printf_plt_addr }],
    })
    .then(async (res) => {
      console.log(prettyJson(res))
      checkResponse(res, 'setInstructionBreakpoints', true)
      await debugAdapter.assert(
        res.body.breakpoints.length == 1,
        `Expected bkpts 1`,
        `Got ${res.body.breakpoints.length}: ${prettyJson(res)}`
      )

      const { id, verified, instructionReference } = res.body.breakpoints[0]
      await debugAdapter.assert(verified, 'Expected breakpoint to be verified and exist!')
      await debugAdapter.assert(
        hexStrAddressesEquals(instructionReference, printf_plt_addr),
        `Attempted to set ins breakpoint at ${printf_plt_addr}`,
        `Was set at ${instructionReference}`
      )
    })
  const threads = await debugAdapter.threads()
  await debugAdapter.contNextStop(threads[0].id)

  const verifyCorrectStacktrace = async (frames, expected) => {
    let idx = 0
    for (const f of walk_expected_frames(frames)) {
      await debugAdapter.assert(
        f.name == expected[idx].name,
        `Expected frame to be '${expected[idx].name}' but was '${f.name}'`
      )
      idx++
      if (idx >= expected.length) return
    }
  }

  {
    const {
      body: { stackFrames },
    } = await debugAdapter.stackTrace(threads[0].id)
    await verifyCorrectStacktrace(stackFrames, [{ name: 'print' }, { name: 'main' }])
  }
  await debugAdapter.contNextStop(threads[0].id)
  {
    const {
      body: { stackFrames },
    } = await debugAdapter.stackTrace(threads[0].id)
    await verifyCorrectStacktrace(stackFrames, [{ name: 'print' }, { name: 'bar' }, { name: 'foo' }, { name: 'main' }])
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
