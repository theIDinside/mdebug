const net = require('net')
const events = require('events')
const readline = require('node:readline')
const { stdin: input, stdout: output } = require('node:process')

function connect(host, port) {
  console.log(`host: ${host}\nport: ${port}`)
  return net.connect(port, host)
}

function printUsage() {
  console.log(`usage: node gdbserver_repl.js <host> <port>`)
}

if (process.argv.length < 4) {
  printUsage()
  process.exit(-1)
}

let socket = connect(process.argv[2], process.argv[3])

let evt = new events.EventEmitter()

let last_msg = null

evt.on('ack', (data) => {
  if (last_msg == null) {
    console.log(`received ack for unknown message`)
  } else {
    console.log(`last request: ${last_msg} acknowledged`)
  }

  last_msg = null
})
evt.on('payload', (data) => {})
evt.on('notification', (data) => {})

class Parser {
  swap = [Buffer.alloc(4096), Buffer.alloc(4096), Buffer.alloc(4096), Buffer.alloc(4096)]
  swap_size = [0, 0, 0, 0]
  swap_index = 0

  buf = Buffer.alloc(4 * 4096)
  buf_size = 0

  eventEmitter = null

  constructor(evt) {
    this.eventEmitter = evt
  }

  push_read(data) {
    this.buf.set(data, this.buf_size)
    this.buf_size += data.length
  }

  try_parse() {
    for (let i = 0; i < this.buf_size; ++i) {
      switch (this.buf.at(i).toString()) {
        case '+':
          evt.emit('ack')
          break
        case '-':
          break
        case '$':
          break
        case '%':
          break
      }
    }
  }
}

const parser = new Parser()

socket.on('data', (data) => {
  // if (data.toString() != '+') { socket.write('+') }

  console.log(`\nreceived: '${data.toString()}'`)
})

function format_packet(msg) {
  let checksum = 0
  let buf = Buffer.from(msg, 'ascii')
  console.log(`formatting '${msg}'`)
  for (let idx = 0; idx < buf.length; ++idx) {
    checksum += buf.at(idx)
  }
  checksum = checksum % 256
  console.log(`checksum in decimal: ${checksum}`)
  const packet_checksum = checksum.toString(16)
  return `\$${msg}#${packet_checksum}`
}

function write_packet(packet) {
  last_msg = packet
  socket.write(packet)
}

socket.on('connect', (err) => {
  write_packet(format_packet('QStartNoAckMode'))
  write_packet(format_packet('!'))
  write_packet(
    format_packet(
      'qSupported:multiprocess+;swbreak+;hwbreak+;qRelocInsn+;fork-events+;vfork-events+;exec-events+;vContSupported+;QThreadEvents+;QThreadOptions+;no-resumed+;memory-tagging+;xmlRegisters=i386;QNonStop+'
    )
  )
  write_packet(format_packet('QThreadEvents:1'))
  write_packet(format_packet('qXfer:threads:read::0,8000'))
})

async function repl_prompt(prompt) {
  const rl = readline.createInterface({ input, output })
  rl.setPrompt(prompt)

  for await (const line of rl) {
    if (line == 'exit') {
      return
    }
    console.log(`\n...sending command...\n`)
    if (line == '+') {
      write_packet('+')
    } else {
      const packet = format_packet(line)
      write_packet(packet)
    }
  }
}

repl_prompt('gdb packet>').then(() => {
  console.log('Exiting...')
  socket.destroy()
})
