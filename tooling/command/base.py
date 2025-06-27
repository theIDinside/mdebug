from abc import ABC, abstractmethod
from typing import List, Dict
import subprocess
from ..metadata import BuildMetadata

presets = ["debug", "release", "fulldebug", "fullrelease"]

# To create a new command, add a file into ./tooling/command, just cargo cult one of the
# existing commands. Then in __init__.py, add the import just like the other files. Be sure to also instantiate the command inside the new file (see other commands, again for how this is done)


def runCommand(cmd, cwd=None, env=None):
    print(f"running> {' '.join(cmd)}")
    subprocess.run(cmd, cwd=cwd, check=True, env=None)


class Argument:
    """Argument class. Defines contents and behaviors for arguments that a `Command` defines."""

    def __init__(
        self,
        name: str,
        description: str,
        typeName: str,
        type_: type,
        required: bool = True,
    ):
        self.name = name
        self.description = description
        self.typeName = typeName
        self.type = type_
        self.required = required

    def validate(self, value: str):
        try:
            self.type(value)
        except ValueError:
            raise ValueError(f"Argument '{self.name}' must be of type {self.typeName}.")


class CommandInterface(ABC):
    @abstractmethod
    def usage(self):
        pass

    @classmethod
    def name(cls):
        return cls.__name__.replace("Command", "").lower()

    @abstractmethod
    def validate(self, buildMetadata: BuildMetadata, args) -> list:
        raise NotImplementedError

    @abstractmethod
    def run(self, buildMetadata: BuildMetadata, args):
        raise NotImplementedError

    def execute(self, buildMetadata: BuildMetadata, args):
        """Execute the command. Performs validation implemented by the command."""
        validArguments = self.validate(buildMetadata=buildMetadata, args=args)
        self.run(buildMetadata=buildMetadata, args=validArguments)


class Command(CommandInterface):
    registeredCommands: Dict[str, CommandInterface] = {}
    useMessage = "No description provided by the command."
    arguments: List[Argument] = []
    hasFixedArguments = False

    def __init__(self, commandName, commandInstance):
        super().__init__()
        if commandName is None or commandName == "":
            raise ValueError("Command name must be a valid string.")

        if Command.registeredCommands.get(commandName):
            raise KeyError(
                f"Command with name '{commandName}' already registered. Duplicate command names not supported."
            )
        else:
            Command.registeredCommands[commandName] = commandInstance
        self.commandName = commandName

    def usage(self):
        parts = []
        for arg in self.arguments:
            part = f"<{arg.name}:{arg.typeName}>"
            if not arg.required:
                part = f"[{part}]"
            parts.append(part)
        argumentsString = " ".join(parts)
        print(f"Usage: mdbuild.py {self.name()} {argumentsString}\n")
        if self.arguments:
            print("  Arguments:")
            for arg in self.arguments:
                required = "required" if arg.required else "optional"
                print(
                    f"    - {arg.name} ({arg.typeName}, {required}): {arg.description}"
                )

        print(f"\n{self.useMessage}")

    @classmethod
    def name(cls):
        return cls.__name__.replace("Command", "").lower()

    def validate(self, buildMetadata: BuildMetadata, args) -> list:
        requiredArguments = [arg for arg in self.arguments if arg.required]

        if len(args) < len(requiredArguments):
            self.usage()
            raise ValueError(
                f"Missing required arguments. Expected at least {len(requiredArguments)} arguments."
            )

        if self.hasFixedArguments and len(args) > len(self.arguments):
            self.usage()
            raise ValueError(
                f"Too many arguments. Expected at most {len(self.arguments)} arguments."
            )
        return args

    @abstractmethod
    def run(self, buildMetadata: BuildMetadata, args):
        raise NotImplementedError


__all__ = ["presets"]
