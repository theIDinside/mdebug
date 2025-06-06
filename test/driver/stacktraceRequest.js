const { checkResponse, getLineOf, readFileContents, repoDirFile, seconds } = require('./client')
const { objdump, hexStrAddressesEquals, assert, assertLog, prettyJson, getPrintfPlt } = require('./utils')

async function unwindFromSharedObject(DA) {
  const sharedObjectsCount = 6

  async function set_bp(source, bps) {
    const file = readFileContents(repoDirFile(source))
    const bp_lines = bps
      .map((ident) => getLineOf(file, ident))
      .filter((item) => item != null)
      .map((l) => ({ line: l }))
    return DA.sendReqGetResponse('setBreakpoints', {
      source: {
        name: repoDirFile(source),
        path: repoDirFile(source),
      },
      breakpoints: bp_lines,
    })
  }

  async function setFnBp(fn) {
    const bps = fn.map((name) => ({ name: name }))
    return DA.sendReqGetResponse('setFunctionBreakpoints', {
      breakpoints: bps,
    })
  }

  let modules_event_promise = DA.prepareWaitForEventN('module', 6, seconds(1))
  await DA.startRunToMain(DA.buildDirFile('stupid_shared'), [], seconds(1))
  const res = await modules_event_promise

  const bp_res = await setFnBp(['convert_kilometers_to_miles'])
  console.log(`bpres ${JSON.stringify(bp_res)}`)

  assertLog(
    res.length >= sharedObjectsCount,
    `Expected to see >= 6 module events for shared objects, saw ${res.length}`
  )

  const threads = await DA.threads()
  const bps = await set_bp('test/todo.cpp', ['BP1'])
  assertLog(bps.body.breakpoints.length == 1, 'Expected 1 breakpoint')
  const bps2 = await set_bp('test/dynamic_lib.cpp', ['BPKM'])
  assertLog(bps2.body.breakpoints.length == 1, 'Expected 1 breakpoint')
  // hit breakpoint in todo.cpp
  // await DA.sendReqWaitEvent('continue', { threadId: threads[0].id }, 'stopped', seconds(1))
  await DA.contNextStop()
  await DA.contNextStop()
  const frames = await DA.stackTrace(threads[0].id, seconds(1)).then((res) => {
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

function parse_prologue_and_epilogue(DA) {
  const objdumped = objdump(DA.buildDirFile('stackframes')).split('\n')
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

async function insidePrologueTest(DA) {
  const { prologue, epilogue } = parse_prologue_and_epilogue(DA)
  await DA.startRunToMain(DA.buildDirFile('stackframes'), [], seconds(1))
  await DA.setInsBreakpoint(prologue)
  await DA.contNextStop()
  const frames = await DA.stackTrace().then(({ response_seq, command, type, success, body: { stackFrames } }) => {
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

async function insideEpilogueTest(DA) {
  const { prologue, epilogue } = parse_prologue_and_epilogue(DA)
  await DA.startRunToMain(DA.buildDirFile('stackframes'), [], seconds(1))
  await DA.setInsBreakpoint(epilogue)
  await DA.contNextStop()
  const frames = await DA.stackTrace().then(({ response_seq, command, type, success, body: { stackFrames } }) => {
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

function createExpectedStacktraces(debugAdapter) {
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

async function normalTest(DA) {
  const expectedStackTraces = createExpectedStacktraces(DA)

  await DA.startRunToMain(DA.buildDirFile('stackframes'), [], seconds(1))
  const file = readFileContents(repoDirFile('test/stackframes.cpp'))
  const bp_lines = ['BP1', 'BP2', 'BP3', 'BP4']
    .map((ident) => getLineOf(file, ident))
    .filter((item) => item != null)
    .map((l) => ({ line: l }))
  if (bp_lines.length != 4) throw new Error(`Expected to find 4 breakpoint locations but found ${bp_lines.length}`)
  const bpResponse = await DA.sendReqGetResponse('setBreakpoints', {
    source: {
      name: repoDirFile('test/stackframes.cpp'),
      path: repoDirFile('test/stackframes.cpp'),
    },
    breakpoints: bp_lines,
  })
  const threads = await DA.threads()
  {
    const frames = await DA.stackTrace(threads[0].id).then(
      ({ response_seq, command, type, success, body: { stackFrames } }) => {
        checkResponse({ type, success, command }, 'stackTrace', true)
        return stackFrames
      }
    )
    assert(
      frames.length == 4,
      () =>
        `We're exactly at the start of the first instruction of main - expecting only 1 frame but got ${
          stackFrames.length
        }: ${prettyJson(stackFrames)}`
    )

    const scopes = []
    for (const frame of frames) {
      scopes.push(await DA.sendReqGetResponse('scopes', { frameId: frame.id }))
    }
    if (scopes.length != frames.length) throw new Error(`Expected ${frames.length} scopes but got ${scopes.length}`)
  }
  const total = 5
  for (let i = total; i < 9; i++) {
    await DA.sendReqWaitEvent('continue', { threadId: threads[0].id }, 'stopped', seconds(1))
    await DA.stackTrace(threads[0].id).then((res) => {
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

async function unwindWithDwarfExpression(DA) {
  const printf_plt_addr = getPrintfPlt(DA, 'next')
  console.log(`printf@plt address: ${printf_plt_addr}`)
  await DA.startRunToMain(DA.buildDirFile('next'), [], seconds(1))
  await DA.sendReqGetResponse('setInstructionBreakpoints', {
    breakpoints: [{ instructionReference: printf_plt_addr }],
  }).then((res) => {
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
  const threads = await DA.threads()
  await DA.contNextStop(threads[0].id)

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
    } = await DA.stackTrace(threads[0].id)
    verify_correct_stacktrace(stackFrames, [{ name: 'print' }, { name: 'main' }])
  }
  await DA.contNextStop(threads[0].id)
  {
    const {
      body: { stackFrames },
    } = await DA.stackTrace(threads[0].id)
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
