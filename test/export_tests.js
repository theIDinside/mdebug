const fs = require('fs')
const process = require('process')
const path = require('path')

const fileDir = path.dirname(__filename)
const driverTestDir = `${fileDir}/driver`
const filePath = `${fileDir}/driver/DriverTests.cmake`

const ignoredJsFiles = ['client.js', 'run.js', 'utils.js']
function testFileFilter(file) {
  return path.extname(file) == '.js' && !ignoredJsFiles.some((f) => f == file)
}

function readFiles(directory) {
  return new Promise((resolve, reject) => {
    fs.readdir(driverTestDir, (err, files) => {
      if (err) {
        reject(err)
      }
      resolve(files)
    })
  })
}

function addTest(suite, test, is_todo = false) {
  if (is_todo) {
    return `add_test(NAME DriverTest.Native.${suite}.${test} COMMAND node \${CMAKE_CURRENT_SOURCE_DIR}/test/driver/run.js --build-dir=\${CMAKE_BINARY_DIR} --test-suite=${suite} --test=${test} --session=native)
add_test(NAME DriverTest.Remote.${suite}.${test} COMMAND node \${CMAKE_CURRENT_SOURCE_DIR}/test/driver/run.js --build-dir=\${CMAKE_BINARY_DIR} --test-suite=${suite} --test=${test} --session=remote)
set_tests_properties(DriverTest.Remote.${suite}.${test} PROPERTIES LABELS "Todo: Not Implemented" WILL_FAIL TRUE)
set_tests_properties(DriverTest.Native.${suite}.${test} PROPERTIES LABELS "Todo: Not Implemented" WILL_FAIL TRUE)`
  } else {
    return `add_test(NAME DriverTest.Native.${suite}.${test} COMMAND node \${CMAKE_CURRENT_SOURCE_DIR}/test/driver/run.js --build-dir=\${CMAKE_BINARY_DIR} --test-suite=${suite} --test=${test} --session=native)
add_test(NAME DriverTest.Remote.${suite}.${test} COMMAND node \${CMAKE_CURRENT_SOURCE_DIR}/test/driver/run.js --build-dir=\${CMAKE_BINARY_DIR} --test-suite=${suite} --test=${test} --session=remote)`
  }
}

// Test names should match file names (but without .js extension)
// As such each file should expose a `tests` object containing { "name": theTestFunction },
// See the other files for an example.
// Test function must accept 1 parameter, DA of type `DAClient` defined in client.js
// A test that manages to execute until the end without exiting the program with a non-zero value is a passed test.

// This file will create the necessary CMake file and setup to be able to say `ctest -R breakpoints` for instance.
async function main() {
  const testNames = await readFiles(driverTestDir)
    .then((res) => res.filter(testFileFilter))
    .then((res) => res.map((e) => path.basename(e, '.js')))

  let cmakeTestFileContents = []

  for (const test of testNames) {
    const filePath = `./driver/${test}.js`

    let subtest = []
    let todos = []

    let subtestNames = []
    let unimplementedTests = []

    const suite = require(filePath)
    for (let prop in suite.tests) {
      try {
        const fn = suite.tests[prop]()
        subtest.push(addTest(test, prop, false))
      } catch (ex) {
        console.log(`exception: ${ex}`)
        todos.push(addTest(test, prop, true))
      }
    }
    cmakeTestFileContents.push(subtest.join('\n'))
    cmakeTestFileContents.push(todos.join('\n\n'))
  }

  const cmakeContent = `# This is generated content. Do not alter.
${cmakeTestFileContents.join('\n\n')}`

  // Use fs.writeFile to create the file and write the content
  fs.writeFile(filePath, `${cmakeContent}`, (err) => {
    if (err) {
      throw new Error(`Couldn't create CMake file: ${err}.\nContents:\n${cmakeContent}`)
    } else {
      process.exit(0)
    }
  })
}

main().catch((ex) => {
  console.log(ex)
})
