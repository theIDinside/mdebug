const { DAClient, MDB_PATH, buildDirFile, getStackFramePc, runTestSuite, seconds, readFile, repoDirFile, getLineOf } =
  require('./client')(__filename)

async function finish() {
  const da_client = new DAClient(MDB_PATH, [])
  await da_client.launchToMain(buildDirFile('stackframes'))
  const file = readFile(repoDirFile('test/stackframes.cpp'))
  const bp_lines = ['BP3']
    .map((ident) => getLineOf(file, ident))
    .filter((item) => item != null)
    .map((l) => ({ line: l }))
  const res = await da_client.sendReqGetResponse('setBreakpoints', {
    source: {
      name: repoDirFile('test/stackframes.cpp'),
      path: repoDirFile('test/stackframes.cpp'),
    },
    breakpoints: bp_lines,
  })
  const threads = await da_client.threads()
  await da_client.contNextStop(threads[0].id)

  let frames = await da_client.stackTrace(threads[0].id)
  const next_up_frame = frames.body.stackFrames[1]
  // await da_client.setInsBreakpoint("0x40121f");
  const allThreadsStop = true
  // await da_client.contNextStop(threads[0].id);
  const { event_body, response } = await da_client.sendReqWaitEvent(
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

  if (!response.success) throw new Error(`Request was unsuccessful: ${JSON.stringify(response)}`)
  console.log(`stopped event: ${JSON.stringify(event_body, null, 2)}`)

  if (event_body.reason != 'step') {
    throw new Error(`Expected to see a 'stopped' event with 'step' as reason. Got event ${JSON.stringify(event_body)}`)
  }

  frames = await da_client.stackTrace(threads[0].id)
  console.log(`Stopped at ${JSON.stringify(frames.body.stackFrames[0], null, 2)}`)
  if (frames.body.stackFrames[0].line != next_up_frame.line) {
    throw new Error(`Expected to be at line ${next_up_frame.line} but was at ${frames.body.stackFrames[0].line}`)
  }
}

const tests = {
  finish: finish,
}

runTestSuite(tests).then(() => {
  console.log(`done with test`)
})
