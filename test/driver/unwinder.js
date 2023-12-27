const { DAClient, MDB_PATH, buildDirFile, checkResponse, getLineOf, readFile, repoDirFile, seconds, runTestSuite } =
  require('./client')(__filename)

const { objdump, hexStrAddressesEquals } = require('./utils')

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

function parse_prologue_and_epilogue() {
  const objdumped = objdump(buildDirFile('stackframes')).split('\n')
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
        const addr = line.substring(0, i).trim()
        res.epilogue = `0x${addr}`
        console.log(`bar frame: ${JSON.stringify(res)}`)
        return res
      }
    }
    lineNumber += 1
  }
  throw new Error('Could not find prologue and epilogue of bar')
}

function verifyFrameIs(frame, name) {
  if (frame.name != name) {
    throw new Error(`Expected frame ${name} but got ${frame.name}`)
  }
}

async function insidePrologueTest() {
  const { prologue, epilogue } = parse_prologue_and_epilogue()
  const da_client = new DAClient(MDB_PATH, [])
  await da_client.launchToMain(buildDirFile('stackframes'))
  await da_client.setInsBreakpoint(prologue)
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
  const { prologue, epilogue } = parse_prologue_and_epilogue()
  const da_client = new DAClient(MDB_PATH, [])
  await da_client.launchToMain(buildDirFile('stackframes'))
  await da_client.setInsBreakpoint(epilogue)
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
      { line: 48, name: 'foo' },
      { line: 55, name: 'main' },
      { line: 0, name: '*' },
      { line: 0, name: '*' },
      { line: 0, name: '_start' },
    ],
    [
      { line: 42, name: 'bar' },
      { line: 49, name: 'foo' },
      { line: 55, name: 'main' },
      { line: 0, name: '*' },
      { line: 0, name: '*' },
      { line: 0, name: '_start' },
    ],
    [
      { line: 23, name: 'baz' },
      { line: 43, name: 'bar' },
      { line: 49, name: 'foo' },
      { line: 55, name: 'main' },
      { line: 0, name: '*' },
      { line: 0, name: '*' },
      { line: 0, name: '_start' },
    ],
    [
      { line: 16, name: 'quux' },
      { line: 25, name: 'baz' },
      { line: 43, name: 'bar' },
      { line: 49, name: 'foo' },
      { line: 55, name: 'main' },
      { line: 0, name: '*' },
      { line: 0, name: '*' },
      { line: 0, name: '_start' },
    ],
  ]

  const da_client = new DAClient(MDB_PATH, [])
  await da_client.launchToMain(buildDirFile('stackframes'))
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
        if (
          stackFrames[idx].name != expectedStackTraces[i - total][idx].name &&
          expectedStackTraces[i - total][idx].name != '*'
        ) {
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

function* walk_expected_frames(frames) {
  for (let i = 1; i < frames.length; i++) yield frames[i]
}

function getPrintfPlt() {
  const objdumped = objdump(buildDirFile('next')).split('\n')
  for (const line of objdumped) {
    let i = line.indexOf('<printf@plt>:')
    if (i != -1) {
      const addr = line.substring(0, i).trim()
      return `0x${addr}`
    }
  }
  throw new Error('Could not find prologue and epilogue of bar')
}

async function unwindWithDwarfExpression() {
  const printf_plt_addr = getPrintfPlt()
  console.log(`printf@plt address: ${printf_plt_addr}`)
  const da_client = new DAClient(MDB_PATH, [])
  await da_client.launchToMain(buildDirFile('next'))
  await da_client
    .sendReqGetResponse('setInstructionBreakpoints', {
      breakpoints: [{ instructionReference: printf_plt_addr }],
    })
    .then((res) => {
      checkResponse(res, 'setInstructionBreakpoints', true)
      if (res.body.breakpoints.length != 1) {
        throw new Error(`Expected bkpts 1 but got ${res.body.breakpoints.length}`)
      }
      const { id, verified, instructionReference } = res.body.breakpoints[0]
      if (!verified) throw new Error('Expected breakpoint to be verified and exist!')
      if (!hexStrAddressesEquals(instructionReference, printf_plt_addr))
        throw new Error(
          `Attempted to set ins breakpoint at ${printf_plt_addr} but it was set at ${instructionReference}`
        )
    })
  const threads = await da_client.threads()
  await da_client.contNextStop(threads[0].id)

  const verify_correct_stacktrace = (frames, expected) => {
    let idx = 0
    for (const f of walk_expected_frames(frames)) {
      if (f.name != expected[idx].name)
        throw new Error(`Expected frame to be '${expected[idx].name}' but was '${f.name}'`)
      idx++
      if (idx >= expected.length) return
    }
  }

  {
    const {
      body: { stackFrames },
    } = await da_client.stackTrace(threads[0].id)
    verify_correct_stacktrace(stackFrames, [{ name: 'print' }, { name: 'main' }])
  }
  await da_client.contNextStop(threads[0].id)
  {
    const {
      body: { stackFrames },
    } = await da_client.stackTrace(threads[0].id)
    verify_correct_stacktrace(stackFrames, [{ name: 'print' }, { name: 'bar' }, { name: 'foo' }, { name: 'main' }])
  }
}

const tests = {
  insidePrologue: insidePrologueTest,
  insideEpilogue: insideEpilogueTest,
  normal: normalTest,
  unwindFromSharedObject: unwindFromSharedObject,
  unwindWithDwarfExpression: unwindWithDwarfExpression,
}

runTestSuite(tests)
