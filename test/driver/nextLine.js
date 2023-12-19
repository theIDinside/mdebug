const { DAClient, MDB_PATH, buildDirFile, readFile, runTestSuite, repoDirFile, getLineOf } =
  require('./client')(__filename)

function getLinesOf(names) {
  const file = readFile(repoDirFile('test/next.cpp'))
  return names
    .map((ident) => getLineOf(file, ident))
    .filter((item) => item != null)
    .map((l) => ({ line: l }))
}

async function clientSpawn(bps) {
  const da_client = new DAClient(MDB_PATH, [])
  await da_client.launchToMain(buildDirFile('next'))
  const file = readFile(repoDirFile('test/next.cpp'))
  const bp_lines = bps
    .map((ident) => getLineOf(file, ident))
    .filter((item) => item != null)
    .map((l) => ({ line: l }))

  await da_client.sendReqGetResponse('setBreakpoints', {
    source: {
      name: repoDirFile('test/next.cpp'),
      path: repoDirFile('test/next.cpp'),
    },
    breakpoints: bp_lines,
  })
  return da_client
}

async function nextLineOverFunction() {
  const bp_lines = getLinesOf(['BP1', 'BP2'])
  const da_client = await clientSpawn(['BP1'])
  const threads = await da_client.threads()
  let stopped = await da_client.contNextStop(threads[0].id)
  let frames = await da_client.stackTrace(threads[0].id)
  const start_line = frames.body.stackFrames[0].line
  if (start_line != bp_lines[0].line)
    throw new Error(`Expected to be on line ${bp_lines[0].line} for breakpoint but saw ${start_line}`)
  const allThreadsStop = true
  const { event_body, response } = await da_client.sendReqWaitEvent(
    'next',
    {
      threadId: threads[0].id,
      singleThread: !allThreadsStop,
      granularity: 'line',
    },
    'stopped',
    1000
  )

  if (event_body.reason != 'step') {
    throw new Error(`Expected to see a 'stopped' event with 'step' as reason. Got event ${JSON.stringify(event_body)}`)
  }

  {
    frames = await da_client.stackTrace(threads[0].id)
    const end_line = frames.body.stackFrames[0].line
    if (end_line != bp_lines[1].line) {
      throw new Error(
        `Expected to be at line ${bp_lines[1].line} but we're at line ${end_line}: ${JSON.stringify(
          frames.body.stackFrames,
          null,
          2
        )}`
      )
    }
    console.log(`at correct line ${end_line}`)
  }
}

async function stopBecauseBpWhenNextLine() {
  const bp_lines = getLinesOf(['BP1', 'BP3'])
  const da_client = await clientSpawn(['BP1', 'BP3'])
  const threads = await da_client.threads()
  let stopped = await da_client.contNextStop(threads[0].id)
  let frames = await da_client.stackTrace(threads[0].id)
  const start_line = frames.body.stackFrames[0].line
  if (start_line != bp_lines[0].line)
    throw new Error(`Expected to be on line ${bp_lines[0].line} for breakpoint but saw ${start_line}`)
  const allThreadsStop = true
  const { event_body, response } = await da_client.sendReqWaitEvent(
    'next',
    {
      threadId: threads[0].id,
      singleThread: !allThreadsStop,
      granularity: 'line',
    },
    'stopped',
    1000
  )

  if (event_body.reason != 'breakpoint') {
    throw new Error(`Expected to see a 'stopped' event with 'step' as reason. Got event ${JSON.stringify(event_body)}`)
  }

  {
    frames = await da_client.stackTrace(threads[0].id)
    const end_line = frames.body.stackFrames[0].line
    if (end_line != bp_lines[1].line) {
      throw new Error(
        `Expected to be at line ${bp_lines[1].line} but we're at line ${end_line}: ${JSON.stringify(
          frames.body.stackFrames,
          null,
          2
        )}`
      )
    }
    console.log(`at correct line ${end_line}`)
  }
}

async function nextLineInTemplateCode() {}

const tests = {
  nextLineOverFunction: nextLineOverFunction,
  stopBecauseBpWhenNextLine: stopBecauseBpWhenNextLine,
  nextLineInTemplateCode: nextLineInTemplateCode,
}

runTestSuite(tests)
