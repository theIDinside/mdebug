const { seconds } = require('./client')
const { assert, assertLog, prettyJson } = require('./utils')

/**
 * @param { import("./client").DebugAdapterClient } debugAdapter
 */
async function programExit(debugAdapter) {
  await debugAdapter.startRunToMain(debugAdapter.buildDirFile('stackframes'))
  const threads = await debugAdapter.threads()
  const { event_body } = await debugAdapter.sendReqWaitEvent(
    'continue',
    { threadId: threads[0].id },
    'thread',
    seconds(2)
  )

  await debugAdapter.assert(
    event_body.reason == 'exited',
    `Expected a 'thread exit' event`,
    `Got ${prettyJson(event_body)}`
  )

  await debugAdapter.assert(
    event_body.threadId == threads[0].id,
    `Expected to see ${threads[0].id} exit`,
    `Saw ${event_body.threadId}`
  )
}

/**
 * @param { import("./client").DebugAdapterClient } debugAdapter
 */
async function readExitCode(debugAdapter) {
  await debugAdapter.startRunToMain(debugAdapter.buildDirFile('stackframes'))
  const threads = await debugAdapter.getThreads()
  const { event_body } = await debugAdapter.sendReqWaitEvent(
    'continue',
    { threadId: threads[0].id },
    'exited',
    seconds(1)
  )
  const ExpectedExitCode = 241
  await debugAdapter.assert(
    event_body.exitCode == ExpectedExitCode,
    `Expected exitCode == ${ExpectedExitCode}`,
    ` Failed. Got ${prettyJson(event_body)}`
  )
}

const tests = {
  programExit: () => programExit,
  readExitCode: () => readExitCode,
}

module.exports = {
  tests: tests,
}
