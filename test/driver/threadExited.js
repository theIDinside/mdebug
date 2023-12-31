const { DAClient, MDB_PATH, buildDirFile, runTestSuite } = require('./client')(__filename)

async function test() {
  const da_client = new DAClient(MDB_PATH, [])
  await da_client.launchToMain(buildDirFile('threads_shared'))
  const threads = await da_client.threads()
  let p = da_client.prepareWaitForEventN('thread', 17, 2000)
  for (let i = 0; i < 3; i++) {
    const response = await da_client.sendReqGetResponse('continue', { threadId: threads[0].id })
    if (i == 0 && !response.success) {
      throw new Error(`Request continue failed. Message: ${response.message}`)
    }
    // The reason why this should fail, is because, we hit the breakpoint at main, and then continue { threads[0] }, should step over the bp, and then continue
    // which means, that when the second continue requests comes in, target should be running (thus returning a "continue request failed response")
    if (i > 0 && response.success) {
      throw new Error(`Did not expect continue request to succeed!: Response ${JSON.stringify(response)}`)
    }
  }
  let r = await p
  let threads_started = 0
  let threads_exited = 0

  for (let evt of r) {
    if (evt.reason == 'exited') threads_exited++
    if (evt.reason == 'started') threads_started++
  }
  if (threads_started != threads_exited - 1) {
    throw new Error(
      `Expected to see 8 new threads start and 9 threads exit. Started: ${threads_started}. Exited: ${threads_exited}`
    )
  }
}

const tests = {
  see9ThreadExits: test,
}

runTestSuite(tests).then(() => console.log('Done.'))
