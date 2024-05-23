const { readFileContents, repoDirFile, getLineOf } = require('./client')
const { prettyJson, assert } = require('./utils')

async function evaluateBlockVariable(DA) {
  throw new Error('evaluateBlockVariable not implemented')
}

async function evalateAddressAsVariable(DA) {
  throw new Error('evaluateBlockVariable not implemented')
}

const tests = {
  evaluateBlockVariable: evaluateBlockVariable,
  evalateAddressAsVariable: evalateAddressAsVariable,
}

module.exports = {
  tests: tests,
}
