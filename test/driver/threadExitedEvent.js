const { assert, assertLog, prettyJson } = require('./utils')
/**
 *
 * @param {import("./client").DAClient } DA
 */
async function see9ThreadExits(DA) {
  await DA.startRunToMain(DA.buildDirFile('threads_shared'))
  const threads = await DA.threads()
  const EXPECTED_THREAD_EVENTS = 17;
  let p = DA.prepareWaitForEventN('thread', EXPECTED_THREAD_EVENTS, 2500)
  let pexited = DA.prepareWaitForEventN('exited', 1, 1000)
  for (let i = 0; i < 3; i++) {
    const response = await DA.sendReqGetResponse('continue', { threadId: threads[0].id })
    if (i == 0) {
      assert(response.success, `Request continue failed. Message: ${response.message}`)
      break
    }
    // The reason why this should fail, is because, we hit the breakpoint at main, and then continue { threads[0] }, should step over the bp, and then continue
    // which means, that when the second continue requests comes in, target should be running (thus returning a "continue request failed response")
    if (i > 0 && response.success) {
      assert(!response.success, `Did not expect continue request to succeed!: Response ${JSON.stringify(response)}`)
    }
  }
  let r = await p
  assertLog(r.length == EXPECTED_THREAD_EVENTS, `Expected ${EXPECTED_THREAD_EVENTS} thread events`);
  let re = (await pexited)[0]

  let threads_started = 0
  let threads_exited = 0

  for (let evt of r) {
    if (evt.reason == 'exited') threads_exited++
    if (evt.reason == 'started') threads_started++
  }
  assertLog(
    threads_started == threads_exited - 1,
    `Expected to see 8 new threads start and 9 threads exit. `,
    `Started: ${threads_started}. Exited: ${threads_exited}`
  )
  assertLog(re.exitCode == 42, `Expected to see exit code 42. `, `Saw ${re.exitCode}`)
}

const tests = {
  see9ThreadExits: () => see9ThreadExits,
}

module.exports = {
  tests: tests,
}
