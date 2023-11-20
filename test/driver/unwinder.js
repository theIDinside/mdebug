const {
  DAClient,
  MDB_PATH,
  prettyJson,
  buildDirFile,
  checkResponse,
  getLineOf,
  readFile,
  repoDirFile,
  seconds,
  runTestSuite,
} = require('./client')(__filename)

async function unwindFromSharedObject() {
  const da_client = new DAClient(MDB_PATH, [])

  const sharedObjectsCount = 6

  const so_addr = '0x7ffff7fbc189'
  async function set_bp(source, bps) {
    const file = readFile(repoDirFile(source))
    const bp_lines = bps
      .map((ident) => getLineOf(file, ident))
      .filter((item) => item != null)
      .map((l) => ({ line: l }))
    return da_client.sendReqGetResponse('setBreakpoints', {
      source: {
        name: repoDirFile(source),
        path: repoDirFile(source),
      },
      breakpoints: bp_lines,
    })
  }

  async function setFnBp(fn) {
    const bps = fn.map((name) => ({ name: name }))
    return da_client.sendReqGetResponse('setFunctionBreakpoints', {
      breakpoints: bps,
    })
  }

  let modules_event_promise = da_client.prepareWaitForEventN('module', 6, seconds(1))
  await da_client.launchToMain(buildDirFile('stupid_shared'), seconds(1))
  const res = await modules_event_promise

  const bp_res = await setFnBp(['convert_kilometers_to_miles'])
  console.log(`bpres ${JSON.stringify(bp_res)}`)

  if (res.length < sharedObjectsCount) {
    throw new Error(`Expected to see 6 module events for shared objects but saw ${res.length}`)
  }
  const threads = await da_client.threads()
  const bps = await set_bp('test/todo.cpp', ['BP1'])
  const bps2 = await set_bp('test/dynamic_lib.cpp', ['BPKM'])
  console.log(`bps: ${JSON.stringify(bps)}`)
  console.log(`bps2: ${JSON.stringify(bps2)}`)
  // hit breakpoint in todo.cpp
  await da_client.sendReqWaitEvent('continue', { threadId: threads[0].id }, 'stopped', seconds(1))
  console.log('foo')
  await da_client.setInsBreakpoint(so_addr)
  await da_client.contNextStop()
  const frames = await da_client.stackTrace(threads[0].id, seconds(1)).then((res) => {
    checkResponse(res, 'stackTrace', true)
    const { stackFrames } = res.body
    console.log(`${JSON.stringify(stackFrames, null, 2)}`)
    return stackFrames
  })
  verifyFrameIs(frames[0], 'convert_kilometers_to_miles')
  const response = await da_client.disconnect('terminate')
  if (!response.success) throw new Error(`Failed to disconnect. ${JSON.stringify(response)}`)
}

const INSIDE_BAR_PROLOGUE = '0x00000000004008a0'
const INSIDE_BAR_EPILOGUE = '0x00000000004008c3'

function verifyFrameIs(frame, name) {
  if (frame.name != name) {
    throw new Error(`Expected frame ${name} but got ${frame.name}`)
  }
}

async function insidePrologueTest() {
  const da_client = new DAClient(MDB_PATH, [])
  await da_client.launchToMain(buildDirFile('stackframes'))
  await da_client.setInsBreakpoint(INSIDE_BAR_PROLOGUE)
  await da_client.contNextStop()
  const frames = await da_client
    .stackTrace()
    .then(({ response_seq, command, type, success, body: { stackFrames } }) => {
      checkResponse({ type, success, command }, 'stackTrace', true)
      let application_frames = 0
      for (const f of stackFrames) {
        application_frames++
        if (f.name == 'main') {
          break
        }
      }
      if (application_frames != 3)
        throw new Error(
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

async function insideEpilogueTest() {
  const da_client = new DAClient(MDB_PATH, [])
  await da_client.launchToMain(buildDirFile('stackframes'))
  await da_client.setInsBreakpoint(INSIDE_BAR_EPILOGUE)
  await da_client.contNextStop()
  const frames = await da_client
    .stackTrace()
    .then(({ response_seq, command, type, success, body: { stackFrames } }) => {
      checkResponse({ type, success, command }, 'stackTrace', true)
      let application_frames = 0
      for (const f of stackFrames) {
        application_frames++
        if (f.name == 'main') {
          break
        }
      }
      if (application_frames != 3)
        throw new Error(
          `We're exactly at the start of the first instruction of main - expecting only 3 frame but got ${
            stackFrames.length
          }: ${JSON.stringify(stackFrames)}`
        )
      else return stackFrames
    })
  verifyFrameIs(frames[0], 'bar')
  verifyFrameIs(frames[1], 'foo')
  verifyFrameIs(frames[2], 'main')
}

async function normalTest() {
  const expectedStackTraces = [
    [
      { line: 39, name: 'foo' },
      { line: 46, name: 'main' },
      { line: 0, name: 'unknown' },
      { line: 0, name: 'unknown' },
      { line: 0, name: 'unknown' },
    ],
    [
      { line: 33, name: 'bar' },
      { line: 40, name: 'foo' },
      { line: 46, name: 'main' },
      { line: 0, name: 'unknown' },
      { line: 0, name: 'unknown' },
      { line: 0, name: 'unknown' },
    ],
    [
      { line: 14, name: 'baz' },
      { line: 34, name: 'bar' },
      { line: 40, name: 'foo' },
      { line: 46, name: 'main' },
      { line: 0, name: 'unknown' },
      { line: 0, name: 'unknown' },
      { line: 0, name: 'unknown' },
    ],
    [
      { line: 7, name: 'quux' },
      { line: 16, name: 'baz' },
      { line: 34, name: 'bar' },
      { line: 40, name: 'foo' },
      { line: 46, name: 'main' },
      { line: 0, name: 'unknown' },
      { line: 0, name: 'unknown' },
      { line: 0, name: 'unknown' },
    ],
  ]

  const da_client = new DAClient(MDB_PATH, [])
  await da_client.launchToMain(buildDirFile('stackframes'))
  const disassembly = await da_client.sendReqGetResponse('disassemble', {
    memoryReference: '0x401210',
    offset: 0,
    instructionOffset: 0,
    instructionCount: 9,
    resolveSymbols: false,
  })
  if (disassembly.body.instructions.length != 9) {
    throw new Error(
      `Expected 4 disassembled instructions but instead got ${
        disassembly.body.instructions.length
      }. Serial data: ${JSON.stringify(disassembly.body.instructions)}`
    )
  }
  const file = readFile(repoDirFile('test/stackframes.cpp'))
  const bp_lines = ['BP1', 'BP2', 'BP3', 'BP4']
    .map((ident) => getLineOf(file, ident))
    .filter((item) => item != null)
    .map((l) => ({ line: l }))
  if (bp_lines.length != 4) throw new Error(`Expected to find 4 breakpoint locations but found ${bp_lines.length}`)
  await da_client.sendReqGetResponse('setBreakpoints', {
    source: {
      name: repoDirFile('test/stackframes.cpp'),
      path: repoDirFile('test/stackframes.cpp'),
    },
    breakpoints: bp_lines,
  })
  const threads = await da_client.threads()
  {
    const frames = await da_client
      .stackTrace(threads[0].id)
      .then(({ response_seq, command, type, success, body: { stackFrames } }) => {
        checkResponse({ type, success, command }, 'stackTrace', true)
        return stackFrames
      })
    if (frames.length != 4)
      throw new Error(
        `We're exactly at the start of the first instruction of main - expecting only 1 frame but got ${
          stackFrames.length
        }: ${JSON.stringify(stackFrames)}`
      )
    const scopes = []
    for (const frame of frames) {
      scopes.push(await da_client.sendReqGetResponse('scopes', { frameId: frame.id }))
    }
    console.log(prettyJson(scopes))
    if (scopes.length != frames.length) throw new Error(`Expected ${frames.length} scopes but got ${scopes.length}`)
  }
  const total = 5
  for (let i = total; i < 9; i++) {
    await da_client.sendReqWaitEvent('continue', { threadId: threads[0].id }, 'stopped', seconds(1))
    await da_client.stackTrace(threads[0].id).then((res) => {
      checkResponse(res, 'stackTrace', true)
      const { stackFrames } = res.body
      if (stackFrames.length != i) {
        throw new Error(
          `Expected ${i} stackframes but got ${stackFrames.length}: ${JSON.stringify(stackFrames, null, 2)}`
        )
      }

      for (const idx in stackFrames) {
        if (stackFrames[idx].line != expectedStackTraces[i - total][idx].line) {
          throw new Error(
            `Expected line to be at ${expectedStackTraces[i - total][idx].line} but was ${
              stackFrames[idx].line
            }: ${JSON.stringify(stackFrames, null, 2)}`
          )
        }
        if (stackFrames[idx].name != expectedStackTraces[i - total][idx].name) {
          throw new Error(
            `Expected name to be ${expectedStackTraces[i - total][idx].name} but was ${
              stackFrames[idx].name
            }: ${JSON.stringify(stackFrames, null, 2)}`
          )
        }
      }
    })
  }
}

const tests = {
  insidePrologue: insidePrologueTest,
  insideEpilogue: insideEpilogueTest,
  normal: normalTest,
  unwindFromSharedObject: unwindFromSharedObject,
}

runTestSuite(tests)
