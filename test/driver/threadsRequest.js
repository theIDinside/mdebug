const { getLineOf, readFileContents, repoDirFile, seconds } = require('./client')
const { assert, prettyJson, assertLog } = require('./utils')

/**
 * @param {import("./client").DebugAdapterClient } debugAdapter
 */
async function threads(debugAdapter) {
  await debugAdapter.startRunToMain(debugAdapter.buildDirFile('threads_shared'), seconds(1))
  let threads = await debugAdapter.threads()
  const file = readFileContents(repoDirFile('test/threads_shared.cpp'))
  const breakpointLines = ['BP1']
    .map((ident) => getLineOf(file, ident))
    .filter((item) => item != null)
    .map((l) => ({ line: l }))

  const res = await debugAdapter.setBreakpointsRequest({
    source: {
      name: repoDirFile('test/threads_shared.cpp'),
      path: repoDirFile('test/threads_shared.cpp'),
    },
    breakpoints: breakpointLines,
  })

  assertLog(res.body.breakpoints[0].verified, `Expected breakpoint to be ok`, 'Breakpoint could not be verified')

  let waitForStop = debugAdapter.waitForEvent('stopped', 3000, (event) => {
    return (event.reason == 'breakpoint' && event.threadId == threads[0].id) || event.allThreadsStopped
  })
  await debugAdapter.continueRequest({ threadId: threads[0].id }).then(() => waitForStop)
  await waitForStop

  threads = await debugAdapter.threads()
  let frames = await threads[1].stacktrace(1000)

  let nextFinisihed = debugAdapter.waitForEvent('stopped', 3000, (event) => {
    return event.reason === 'step'
  })

  let response = await debugAdapter.nextRequest({ threadId: threads[1].id, granularity: 'line', singleThread: true })
  assertLog(response.success, `Expected 'next' command to succeed`, `Response was ${JSON.stringify(response)}`)
  await nextFinisihed

  frames = await debugAdapter.stackTrace(threads[1].id)

  const currentLine = frames.body.stackFrames[0].line
  assertLog(
    currentLine == breakpointLines[0].line + 1,
    `Expected to be at line ${breakpointLines[0].line + 1}`,
    `Was at line ${currentLine}. \n${prettyJson(frames.body.stackFrames)}`
  )
}
const tests = {
  threads: () => threads,
}

module.exports = {
  tests: tests,
}
