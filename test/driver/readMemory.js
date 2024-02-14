const { readFile, repoDirFile, getLineOf, prettyJson } = require('./client')
const { todo, assert } = require('./utils')

async function setup(DA, bps) {
  await DA.launchToMain(DA.buildDirFile('readMemory'))
  const file = readFile(repoDirFile('test/readMemory.cpp'))
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
      name: repoDirFile('test/readMemory.cpp'),
      path: repoDirFile('test/readMemory.cpp'),
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

const readAtMemoryMappedAddress = async function (DA) {
  const hardcodedMmapAddress = '0x1f21000'
  await setup(DA, ['BP1'])
  const threads = await DA.threads()
  await DA.contNextStop(threads[0].id)
  const readMemoryResponse = await DA.sendReqGetResponse('readMemory', {
    memoryReference: hardcodedMmapAddress,
    count: 255,
  })
  assert(readMemoryResponse.success, `readMemory request was unsuccessful: ${readMemoryResponse.message}`)
  const decodedString = Buffer.from(readMemoryResponse.body.data, 'base64').toString('hex')
  assert(
    decodedString.length == 255 * 2,
    `Expected decoded string to be 255 * 2 bytes (bytes represent as hex pair-values) but was ${decodedString.length}. Contents:\n${decodedString}`
  )

  const arr = []
  for (let i = 0; i < 255; ++i) {
    arr.push(i.toString(16).padStart(2, '0'))
  }

  assert(
    arr.join('') == decodedString,
    () => `Unexpected content of decoded string.\nExpected value: ${arr.join('')}\nSeen value: ${decodedString}`
  )
}
const readStackFrameStack = todo('readStackFrameStack')
const readShouldFail = todo('readShouldFail')
const readShouldFailFaultyArgs = todo('readShouldFailFaultyArgs')
const readAtMMapDetermineAddressByVariablesRequest = todo('readAtMMapDetermineAddressByVariablesRequest')

const tests = {
  readAtMemoryMappedAddress: readAtMemoryMappedAddress,
  readAtMMapDetermineAddressByVariablesRequest: readAtMMapDetermineAddressByVariablesRequest,
  readStackFrameStack: readStackFrameStack,
  readShouldFail: readShouldFail,
  readShouldFailFaultyArgs: readShouldFailFaultyArgs,
}

module.exports = {
  tests: tests,
}
