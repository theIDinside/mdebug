const { readFileContents, repoDirFile, getLineOf } = require('./client')
const { todo } = require('./utils')

async function evaluateBlockVariable(DA) {
  throw new Error('evaluateBlockVariable not implemented')
}

async function evalateAddressAsVariable(DA) {
  throw new Error('evaluateBlockVariable not implemented')
}

const tests = {
  evaluateBlockVariable: () => todo(evaluateBlockVariable),
  evalateAddressAsVariable: () => todo(evalateAddressAsVariable),
}

module.exports = {
  tests: tests,
}
