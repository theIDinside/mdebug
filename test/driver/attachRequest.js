const { checkResponse, createRemoteService } = require('./client')
const { findAvailablePort, assertLog, todo } = require('./utils')

async function attachArgsGetErrResponseWhenInvalid(debugAdapter) {
  const attachArgs = {
    type: 'INVALID TYPE FOR SURE',
    host: 'localhost',
    port: await findAvailablePort(),
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

  let init_res = await debugAdapter.sendReqGetResponse('initialize', { sessionId: 'aaca-1234123ad-aadd' }, 1000)
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
  await debugAdapter.startRunToMain(debugAdapter.buildDirFile('next'), [], 1000)
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
