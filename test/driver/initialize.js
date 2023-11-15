const { DAClient, MDB_PATH, checkResponse, runTest } = require('./client')(__filename)

async function test() {
  const da_client = new DAClient(MDB_PATH, [])
  await da_client.sendReqGetResponse('initialize', {}, 1000).then((res) => checkResponse(res, 'initialize', true))
}

runTest(test)
