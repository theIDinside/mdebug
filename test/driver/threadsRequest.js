const { getLineOf, readFileContents, repoDirFile, seconds } = require('./client')
const { assert, prettyJson, assertLog } = require('./utils')

/**
 * @param {import("./client").DebugAdapterClient } debugAdapter
 */
async function threads(debugAdapter) {
  await debugAdapter.startRunToMain(debugAdapter.buildDirFile('threads_shared'), [], seconds(1))
  let threads = await debugAdapter.threads()
  const file = readFileContents(repoDirFile('test/threads_shared.cpp'))
  const bp_lines = ['BP1']
    .map((ident) => getLineOf(file, ident))
    .filter((item) => item != null)
    .map((l) => ({ line: l }))
  const breakpointsResponse = await debugAdapter.sendReqGetResponse('setBreakpoints', {
    source: {
      name: repoDirFile('test/threads_shared.cpp'),
      path: repoDirFile('test/threads_shared.cpp'),
    },
    breakpoints: bp_lines,
  })

  assertLog(breakpointsResponse[0].verified, 'Expected breakpoint to be ok', 'Breakpoint could not be verified')

  await debugAdapter.contNextStop(threads[0].id)
  threads = await debugAdapter.threads()
  let frames = await debugAdapter.stackTrace(threads[1].id, 1000)
  console.log(`next line for ${threads[1].id}: (${JSON.stringify(threads[1], null, 2)})`)
  const { event_body, response } = await debugAdapter.sendReqWaitEvent(
    'next',
    {
      threadId: threads[1].id,
      singleThread: true,
      granularity: 'line',
    },
    'stopped',
    500
  )

  assert(response.success, `Expected 'next' command to succeed; got ${JSON.stringify(response)}`)

  frames = await debugAdapter.stackTrace(threads[1].id)
  console.log(`Stack frames for ${threads[1].id}: ${JSON.stringify(frames, null, 2)}`)
  const end_line = frames.body.stackFrames[0].line
  assert(
    end_line == bp_lines[0].line + 1,
    `Expected to be at line ${bp_lines[0].line + 1} but we're at line ${end_line}: ${prettyJson(
      frames.body.stackFrames
    )}`
  )
}
const tests = {
  threads: () => threads,
}

module.exports = {
  tests: tests,
}
