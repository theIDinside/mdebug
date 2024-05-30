const { checkResponse } = require('./client')
const { assert } = require('./utils')

async function launch(DA) {
  // we don't care for initialize, that's tested elsewhere
  await DA.sendReqGetResponse('initialize', {}, 1000).then((res) => checkResponse(res, 'initialize', true))
  await DA.sendReqGetResponse('launch', {
    program: DA.buildDirFile('stackframes'),
    stopOnEntry: true,
  }).then((res) => checkResponse(res, 'launch', true))
}

async function launchToMain(DA) {
  await DA.launchToMain(DA.buildDirFile('stackframes'))
}

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
