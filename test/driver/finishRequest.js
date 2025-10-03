const { readFileContents, repoDirFile, getLineOf } = require('./client')
const { prettyJson } = require('./utils')

/**
 * @param { import("./client").DebugAdapterClient } debugAdapter
 */
async function finishSuccess(debugAdapter) {
  await debugAdapter.startRunToMain(debugAdapter.buildDirFile('stackframes'))
  const file = readFileContents(repoDirFile('test/stackframes.cpp'))
  const bp_lines = ['BP3']
    .map((ident) => getLineOf(file, ident))
    .filter((item) => item != null)
    .map((l) => ({ line: l }))
  const res = await debugAdapter.sendReqGetResponse('setBreakpoints', {
    source: {
      name: repoDirFile('test/stackframes.cpp'),
      path: repoDirFile('test/stackframes.cpp'),
    },
    breakpoints: bp_lines,
  })
  const threads = await debugAdapter.threads()
  await debugAdapter.contNextStop(threads[0].id)
  console.log(`request stack trace`)

  let frames = await debugAdapter.stackTrace(threads[0].id)
  const next_up_frame = frames.body.stackFrames[1]
  const { event_body, response } = await debugAdapter.sendReqWaitEvent(
    'stepOut',
    {
      threadId: threads[0].id,
      singleThread: true,
      granularity: 'instruction',
    },
    'stopped',
    1000
  )

  console.log(
    `We're at ${JSON.stringify(frames.body.stackFrames[0], null, 2)}\n\n Expected to stop at ${JSON.stringify(
      next_up_frame,
      null,
      2
    )}`
  )

  await debugAdapter.assert(response.success, `Expected success-response`, `Response: ${JSON.stringify(response)}`)

  await debugAdapter.assert(
    event_body.reason == 'step',
    `Expected to see 'stopped' event with 'step' as reason`,
    `Got event: ${prettyJson(event_body)}`
  )

  frames = await debugAdapter.stackTrace(threads[0].id)
  console.log(`Stopped at ${JSON.stringify(frames.body.stackFrames[0], null, 2)}`)
  await debugAdapter.assert(
    frames.body.stackFrames[0].line == next_up_frame.line,
    `Expected to be at line ${next_up_frame.line}`,
    `But was at ${frames.body.stackFrames[0].line}`
  )
}

/**
 * @param { import("./client").DebugAdapterClient } debugAdapter
 */
async function abortedDueToBkpt(debugAdapter) {
  await debugAdapter.startRunToMain(debugAdapter.buildDirFile('stackframes'))
  const file = readFileContents(repoDirFile('test/stackframes.cpp'))
  const bp_lines = ['BPLine1', 'BP3']
    .map((ident) => getLineOf(file, ident))
    .filter((item) => item != null)
    .map((l) => ({ line: l }))
  const res = await debugAdapter.sendReqGetResponse('setBreakpoints', {
    source: {
      name: repoDirFile('test/stackframes.cpp'),
      path: repoDirFile('test/stackframes.cpp'),
    },
    breakpoints: bp_lines,
  })
  const threads = await debugAdapter.threads()
  await debugAdapter.contNextStop(threads[0].id)

  let frames = await debugAdapter.stackTrace(threads[0].id)
  const next_up_frame = frames.body.stackFrames[1]

  const { event_body, response } = await debugAdapter.sendReqWaitEvent(
    'stepOut',
    {
      threadId: threads[0].id,
      singleThread: true,
      granularity: 'instruction',
    },
    'stopped',
    1000
  )

  await debugAdapter.assert(response.success, `Expected success response`, `Got: ${JSON.stringify(response)}`)
  await debugAdapter.assert(
    event_body.reason == 'breakpoint',
    `Expected to see a 'stopped' event with 'step' as reason.`,
    `Got event ${prettyJson(event_body)}`
  )

  frames = await debugAdapter.stackTrace(threads[0].id)

  await debugAdapter.assert(
    frames.body.stackFrames[0].line == bp_lines[1].line,
    `Expected to have hit breakpoint before finishing function!`,
    `Stack frame ${prettyJson(frames.body.stackFrames[0])} when we should have been at line ${bp_lines[1].line}`
  )
}

const tests = {
  finishSuccess: () => finishSuccess,
  abortedDueToBkpt: () => abortedDueToBkpt,
}

module.exports = {
  tests: tests,
}
