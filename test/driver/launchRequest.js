const { checkResponse } = require('./client')
const { assert } = require('./utils')
const { randomUUID } = require('crypto')

/** @param { import("./client").DebugAdapterClient } debugAdapter */
async function launch(debugAdapter) {
  // we don't care for initialize, that's tested elsewhere
  let initEvent = debugAdapter.initializedEventPromise()
  await Promise.all([debugAdapter.initializeRequest().then((res) => checkResponse(res, 'initialize', true)), initEvent])
  console.log('Init complete.')
  await debugAdapter.configurationDoneRequest().then((res) => {
    checkResponse(res, 'configurationDone', true)
    console.log('Configuration done')
  })
  await debugAdapter
    .launchRequest({
      program: debugAdapter.buildDirFile('stackframes'),
      stopOnEntry: true,
    })
    .then((res) => {
      checkResponse(res, 'launch')
      console.log('Launched.')
    })
}

/** @param { import("./client").DebugAdapterClient } debugAdapter */
async function launchToMain(debugAdapter) {
  await debugAdapter.launchToMain(debugAdapter.buildDirFile('stackframes'))
}

/** @param { import("./client").DebugAdapterClient } debugAdapter */
async function launchThenDisconnect(DA) {
  await DA.launchToMain(DA.buildDirFile('stackframes'))
  const response = await DA.disconnect('terminate')
  assert(response.success, `Failed to disconnect. ${JSON.stringify(response)}`)
}

const tests = {
  launch: () => launch,
  main: () => launchToMain,
  disconnect: () => launchThenDisconnect,
}

module.exports = {
  tests: tests,
}
