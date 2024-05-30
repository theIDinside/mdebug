const {
  checkResponse,
  getLineOf,
  readFileContents,
  repoDirFile,
  SetBreakpoints,
  RemoteService,
  createRemoteService,
} = require('./client')
const { assert, assertLog, assert_eq, prettyJson, getPrintfPlt } = require('./utils')

async function attachArgsGetErrResponseWhenInvalid(debugAdapter) {
  const attachArgs = {
    type: 'INVALID TYPE FOR SURE',
    host: 'localhost',
    port: 12345,
    allstop: false,
  }

  assertLog(server_spawn.ok, 'Spawn gdbserver for MDB to attach to', server_spawn.msg)

  let init_res = await debugAdapter.sendReqGetResponse('initialize', {}, 1000)
  checkResponse(init_res, 'initialize', true)

  let attach_res = await debugAdapter.sendReqGetResponse('attach', attachArgs, 1000)

  assertLog(
    attach_res.success == false,
    'Expected attach command to fail',
    `Succeeded when it should not, with ${JSON.stringify(attachArgs)}`
  )
}

/**
 * @param {import("./client").DAClient} debugAdapter
 */
async function attachInit(debugAdapter) {
  const attachArgs = {
    type: 'gdbremote',
    host: 'localhost',
    port: 12345,
    allstop: false,
  }

  const server_spawn = { ok: false, msg: '', server: null }
  try {
    server_spawn.server = await createRemoteService(
      'gdbserver',
      attachArgs.host,
      attachArgs.port,
      debugAdapter.buildDirFile('next')
    )
    server_spawn.ok = true
  } catch (ex) {
    server_spawn.ok = false
    server_spawn.msg = `${ex}`
    console.log(`ERROR: ${ex}`)
  }
  assertLog(server_spawn.ok, 'Spawn gdbserver for MDB to attach to', server_spawn.msg)

  await debugAdapter.remoteAttach(attachArgs, true, 1000)

  const functions = ['main'].map((n) => ({ name: n }))

  const fnBreakpointResponse = await debugAdapter.sendReqGetResponse('setFunctionBreakpoints', {
    breakpoints: functions,
  })
  assertLog(
    fnBreakpointResponse.success,
    'Function breakpoints request',
    `Response failed with contents: ${JSON.stringify(fnBreakpointResponse)}`
  )

  assertLog(
    fnBreakpointResponse.body.breakpoints.length == 1,
    'Expected 1 breakpoint returned',
    `But received ${JSON.stringify(fnBreakpointResponse.body.breakpoints)}`
  )
}

async function attachContinue(debugAdapter) {
  throw new Error('remoteAttachContinue not implemented')
}

async function ptraceAttach(debugAdapter) {
  throw new Error('ptraceAttach not implemented')
}

const tests = {
  attachContinue: () => todo(attachContinue),
  attachInit: () => attachInit,
  ptraceAttach: () => todo(ptraceAttach),
  attachArgsGetErrResponseWhenInvalid: () => attachArgsGetErrResponseWhenInvalid,
}

module.exports = {
  tests: tests,
}
