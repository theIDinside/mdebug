const { DAClient, MDB_PATH, checkResponse } = require('./client')

async function init(DA) {
  await DA.sendReqGetResponse('initialize', {}, 1000).then((res) => checkResponse(res, 'initialize', true))
}

const tests = {
  init: init,
}

module.exports = {
  tests: tests,
}
