const { getExecutorArgs, runTestSuite } = require('./client')

async function run() {
  const config = getExecutorArgs()
  const testSuiteFile = require(`./${config.args.testSuite}`)
  await runTestSuite(config, testSuiteFile.tests)
}

run()
