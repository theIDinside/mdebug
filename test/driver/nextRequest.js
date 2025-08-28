const { readFileContents, repoDirFile, getLineOf, getStackFramePc } = require('./client')
const { todo, assert, prettyJson } = require('./utils')

function getLinesOf(names) {
  const file = readFileContents(repoDirFile('test/next.cpp'))
  return names
    .map((ident) => getLineOf(file, ident))
    .filter((item) => item != null)
    .map((l) => ({ line: l }))
}

async function setup(DA, bps) {
  await DA.startRunToMain(DA.buildDirFile('next'))
  const file = readFileContents(repoDirFile('test/next.cpp'))
  const bp_lines = bps
    .map((ident) => getLineOf(file, ident))
    .filter((item) => item != null)
    .map((l) => ({ line: l }))

  assert(
    bp_lines.length == bps.length,
    `Could not parse contents of ${repoDirFile('test/next.cpp')} to find all string identifiers`
  )

  const breakpoint_response = await DA.sendReqGetResponse('setBreakpoints', {
    source: {
      name: repoDirFile('test/next.cpp'),
      path: repoDirFile('test/next.cpp'),
    },
    breakpoints: bp_lines,
  })
  assert(
    breakpoint_response.body.breakpoints.length == bps.length,
    `Expected to have set ${bps.length} breakpoints but only successfully set ${
      breakpoint_response.body.breakpoints.length
    }:\n${prettyJson(breakpoint_response)}`
  )
}

async function nextLineOverFunction(DA) {
  const bp_lines = getLinesOf(['BP1', 'BP2'])
  await setup(DA, ['BP1'])
  const threads = await DA.threads()
  await DA.contNextStop(threads[0].id)
  let frames = await DA.stackTrace(threads[0].id)
  const start_line = frames.body.stackFrames[0].line
  assert(
    start_line == bp_lines[0].line,
    `Expected to be on line ${bp_lines[0].line} for breakpoint but saw ${start_line}. Frames: ${prettyJson(frames)}`
  )

  const allThreadsStop = true
  const { event_body, response } = await DA.sendReqWaitEvent(
    'next',
    {
      threadId: threads[0].id,
      singleThread: !allThreadsStop,
      granularity: 'line',
    },
    'stopped',
    5000
  )

  assert(
    event_body.reason == 'step',
    `Expected to see a 'stopped' event with 'step' as reason. Got event ${prettyJson(event_body)}`
  )

  {
    frames = await DA.stackTrace(threads[0].id)
    const end_line = frames.body.stackFrames[0].line
    assert(
      end_line == bp_lines[1].line,
      `Expected to be at line ${bp_lines[1].line} but we're at line ${end_line}: ${prettyJson(frames.body.stackFrames)}`
    )
    console.log(`at correct line ${end_line}`)
  }
}

async function stopBecauseBpWhenNextLine(DA) {
  const bp_lines = getLinesOf(['BP1', 'BP3'])
  await setup(DA, ['BP1', 'BP3'])
  const threads = await DA.threads()
  await DA.contNextStop(threads[0].id)
  let frames = await DA.stackTrace(threads[0].id)
  const start_line = frames.body.stackFrames[0].line
  assert(
    start_line == bp_lines[0].line,
    `Expected to be on line ${bp_lines[0].line} for breakpoint but saw ${start_line}`
  )
  const allThreadsStop = true
  const { event_body, response } = await DA.sendReqWaitEvent(
    'next',
    {
      threadId: threads[0].id,
      singleThread: !allThreadsStop,
      granularity: 'line',
    },
    'stopped',
    1000
  )
  assert(
    event_body.reason == 'breakpoint',
    `Expected to see a 'stopped' event with 'breakpoint' as reason. Got event ${JSON.stringify(event_body)}`
  )

  {
    frames = await DA.stackTrace(threads[0].id)
    const end_line = frames.body.stackFrames[0].line
    assert(
      end_line == bp_lines[1].line,
      `Expected to be at line ${bp_lines[1].line} but we're at line ${end_line}: ${prettyJson(frames.body.stackFrames)}`
    )
    console.log(`at correct line ${end_line}`)
  }
}

async function nextLineInTemplateCode(da) {}

async function nextInstruction(DA) {
  await DA.startRunToMain(DA.buildDirFile('stackframes'))
  const threads = await DA.threads()
  let frames = await DA.stackTrace(threads[0].id)
  // await da_client.setInsBreakpoint("0x40121f");
  const pc = getStackFramePc(frames, 0)
  console.log(`STARTING PC THAT WE START DISASSEMBLING FROM: ${pc}`)
  const disassembly = await DA.sendReqGetResponse('disassemble', {
    memoryReference: pc,
    offset: 0,
    instructionOffset: 0,
    instructionCount: 10,
    resolveSymbols: false,
  })
  const allThreadsStop = true
  // await da_client.contNextStop(threads[0].id);
  const { event_body, response } = await DA.sendReqWaitEvent(
    'next',
    {
      threadId: threads[0].id,
      singleThread: !allThreadsStop,
      granularity: 'instruction',
    },
    'stopped',
    1000
  )
  assert(response.success, `Request was unsuccessful: ${prettyJson(response)}`)
  assert(
    event_body.reason == 'step',
    `Expected to see a 'stopped' event with 'step' as reason. Got event ${prettyJson(event_body)}`
  )

  frames = await DA.stackTrace(threads[0].id)
  const next_pc = getStackFramePc(frames, 0)
  assert(
    next_pc == disassembly.body.instructions[1].address,
    `Expected to be at ${disassembly.body.instructions[1].address} but RIP=${next_pc} (previous pc: ${pc})`
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
