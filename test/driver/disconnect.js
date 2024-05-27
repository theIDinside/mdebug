const { seconds } = require('./client')
const { assertLog, prettyJson } = require('./utils')

/**
 * @param { import("./client").DAClient } debugAdapter
 */
async function terminate(debugAdapter) {
  await debugAdapter.startRunToMain(debugAdapter.buildDirFile('stackframes'))
  const disc = await debugAdapter.disconnect('terminate', 1000)
  assertLog(disc.success, 'Disconnect attempted. ', `Failed: ${prettyJson(disc)}`)
}

const tests = {
  terminate: () => terminate,
}

module.exports = {
  tests: tests,
}
