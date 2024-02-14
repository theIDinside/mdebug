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

  let testSuite = []
  let testSuitesContainingTests = []
  for (const test of testNames) {
    const filePath = `./driver/${test}.js`
    let subtestNames = []
    for (let prop in require(filePath).tests) {
      subtestNames.push(`${prop}`)
    }
    if (subtestNames.length > 0) {
      testSuitesContainingTests.push(test)
      const cmakeOutput = `set(${test} ${subtestNames.join(' ')})`
      testSuite.push(cmakeOutput)
    }
  }

  const cmakeDriverTestSuitesContent = `# This is generated content. Do not alter. \n\nset(DRIVER_TEST_SUITES \n\t${testSuitesContainingTests.join(
    '\n\t'
  )}\n)`
  const cmakeContent = testSuite.join('\n')

  // Use fs.writeFile to create the file and write the content
  fs.writeFile(filePath, `${cmakeDriverTestSuitesContent}\n\n${cmakeContent}`, (err) => {
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
