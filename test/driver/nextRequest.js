const { readFileContents, repoDirFile, getLineOf } = require('./client')
const { todo, prettyJson } = require('./utils')

function getLinesOf(names) {
  const file = readFileContents(repoDirFile('test/next.cpp'))
  return names
    .map((ident) => getLineOf(file, ident))
    .filter((item) => item != null)
    .map((l) => ({ line: l }))
}

/**
 * @param { import("./client").DebugAdapterClient } debugAdapter
 * @param { string[] } bps
 */
async function setup(debugAdapter, bps) {
  await debugAdapter.startRunToMain(debugAdapter.buildDirFile('next'))
  const file = readFileContents(repoDirFile('test/next.cpp'))
  const bp_lines = bps
    .map((ident) => getLineOf(file, ident))
    .filter((item) => item != null)
    .map((l) => ({ line: l }))

  await debugAdapter.assert(
    bp_lines.length == bps.length,
    `Could not parse contents of ${repoDirFile('test/next.cpp')} to find all string identifiers`
  )

  const breakpoint_response = await debugAdapter.sendReqGetResponse('setBreakpoints', {
    source: {
      name: repoDirFile('test/next.cpp'),
      path: repoDirFile('test/next.cpp'),
    },
    breakpoints: bp_lines,
  })
  await debugAdapter.assert(
    breakpoint_response.body.breakpoints.length == bps.length,
    `Expected to have set ${bps.length} breakpoints`,
    `Set ${breakpoint_response.body.breakpoints.length} breakpoints`
  )
}

/**
 * @param { import("./client").DebugAdapterClient } debugAdapter
 */
async function nextLineOverFunction(debugAdapter) {
  const bp_lines = getLinesOf(['BP1', 'BP2'])
  await setup(debugAdapter, ['BP1'])
  const threads = await debugAdapter.threads()
  await debugAdapter.contNextStop(threads[0].id)
  let frames = await debugAdapter.stackTrace(threads[0].id)
  const start_line = frames.body.stackFrames[0].line
  await debugAdapter.assert(
    start_line == bp_lines[0].line,
    `Expeceted to be on line ${bp_lines[0].line}`,
    `But saw ${start_line}. Frames: ${prettyJson(frames)}`
  )

  const allThreadsStop = true
  const { event_body, response } = await debugAdapter.sendReqWaitEvent(
    'next',
    {
      threadId: threads[0].id,
      singleThread: !allThreadsStop,
      granularity: 'line',
    },
    'stopped',
    5000
  )

  await debugAdapter.assert(
    event_body.reason == 'step',
    `Expected to see a 'stopped' event with 'step' as reason.`,
    `Got event ${prettyJson(event_body)}`
  )

  {
    frames = await debugAdapter.stackTrace(threads[0].id)
    const end_line = frames.body.stackFrames[0].line
    await debugAdapter.assert(
      end_line == bp_lines[1].line,
      `Expected to be at line ${bp_lines[1].line}`,
      `At line ${end_line}: ${prettyJson(frames.body.stackFrames)}`
    )
  }
}

/**
 * @param { import("./client").DebugAdapterClient } debugAdapter
 */
async function stopBecauseBpWhenNextLine(debugAdapter) {
  const bp_lines = getLinesOf(['BP1', 'BP3'])
  await setup(debugAdapter, ['BP1', 'BP3'])
  const threads = await debugAdapter.threads()
  await debugAdapter.contNextStop(threads[0].id)
  let frames = await debugAdapter.stackTrace(threads[0].id)
  const start_line = frames.body.stackFrames[0].line
  await debugAdapter.assert(
    start_line == bp_lines[0].line,
    `Expected to be on line ${bp_lines[0].line}`,
    `At: ${start_line}`
  )
  const allThreadsStop = true
  const { event_body, response } = await debugAdapter.sendReqWaitEvent(
    'next',
    {
      threadId: threads[0].id,
      singleThread: !allThreadsStop,
      granularity: 'line',
    },
    'stopped',
    1000
  )
  await debugAdapter.assert(
    event_body.reason == 'breakpoint',
    `Expected to see a 'stopped' event with 'breakpoint' as reason.`,
    `Got event ${JSON.stringify(event_body)}`
  )

  {
    frames = await debugAdapter.stackTrace(threads[0].id)
    const end_line = frames.body.stackFrames[0].line
    await debugAdapter.assert(
      end_line == bp_lines[1].line,
      `Expected to be at line ${bp_lines[1].line}`,
      `At line ${end_line}: ${prettyJson(frames.body.stackFrames)}`
    )
    console.log(`at correct line ${end_line}`)
  }
}

async function nextLineInTemplateCode(da) {}

/** @param { import("./client").DebugAdapterClient } debugAdapter */
async function nextInstruction(debugAdapter) {
  await debugAdapter.startRunToMain(debugAdapter.buildDirFile('stackframes'))
  const threads = await debugAdapter.threads()
  let frames = await threads[0].stacktrace()
  // await da_client.setInsBreakpoint("0x40121f");
  const firstPc = frames[0].pc
  console.log(`STARTING PC THAT WE START DISASSEMBLING FROM: ${firstPc}`)
  const disassembly = await debugAdapter.sendReqGetResponse('disassemble', {
    memoryReference: firstPc,
    offset: 0,
    instructionOffset: 0,
    instructionCount: 10,
    resolveSymbols: false,
  })
  const allThreadsStop = true
  // await da_client.contNextStop(threads[0].id);
  const { event_body, response } = await debugAdapter.sendReqWaitEvent(
    'next',
    {
      threadId: threads[0].id,
      singleThread: !allThreadsStop,
      granularity: 'instruction',
    },
    'stopped',
    1000
  )
  await debugAdapter.assert(response.success, `Expected succesful response`)
  await debugAdapter.assert(
    event_body.reason == 'step',
    `Expected to see a 'stopped' event with 'step' as reason.`,
    `Got event ${prettyJson(event_body)}`
  )

  frames = await threads[0].stacktrace()
  const nextPc = frames[0].pc
  await debugAdapter.assert(
    nextPc == disassembly.body.instructions[1].address,
    `Expected to be at ${disassembly.body.instructions[1].address}`,
    `RIP=${nextPc} (previous pc: ${firstPc})`
  )
}

const tests = {
  nextLineOverFunction: () => nextLineOverFunction,
  stopBecauseBpWhenNextLine: () => stopBecauseBpWhenNextLine,
  nextLineInTemplateCode: () => todo(nextLineInTemplateCode),
  nextInstruction: () => nextInstruction,
}

module.exports = {
  tests: tests,
}
