import json

seq = 1


def serialize_request(req, args):
    """Serializes the request with name `req` and it's arguments `args`.
    `args` must be a Python dictionary."""
    global seq
    json_dict = {"seq": seq, "type": "request", "command": req, "arguments": args}
    seq += 1
    data = json.dumps(json_dict).encode()
    length = len(data)
    return f"Content-Length: {length}\r\n\r\n{data.decode()}"


print(serialize_request("initialize", {}), end="")
print(
    serialize_request(
        "launch",
        {
            "program": "/home/cx/dev/foss/cx/dbm/build-debug/bin/stackframes",
            "stopAtEntry": True,
        },
    ),
    end="",
)

print(
    serialize_request(
        "setFunctionBreakpoints", {"breakpoints": [{"name": "main"}, {"name": "baz"}]}
    ),
    end="",
)

print(
    serialize_request(
        "setInstructionBreakpoints",
        {"breakpoints": [{"instructionReference": "0x40127e"}]},
    ),
    end="",
)

print(serialize_request("configurationDone", {}))

print(
    serialize_request("threads", {}),
    end="",
)

print(
    serialize_request("readMemory", {"memoryReference": "0x418ec0", "count": 16}),
    end="",
)


print(serialize_request("stackTrace", {"threadId": 1}))

print(serialize_request("continue", {"threadId": 1}))
