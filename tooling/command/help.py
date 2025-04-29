from .base import Command, Argument
from tooling.metadata import BuildMetadata


class HelpCommand(Command):
    description = "Display help"
    useMessage = description
    arguments = [
        Argument(
            name="command",
            description=f"Display help for command",
            typeName="string",
            type_=str,
            required=False,
        )
    ]

    def __init__(self):
        super().__init__("help", commandInstance=self)

    def validate(self, buildMetadata: BuildMetadata, args):
        if not args:
            return
        command = Command.registeredCommands.get(args[0])
        if command is None:
            raise ValueError(f"Unknown command {args[0]}")

    def run(self, buildMetadata: BuildMetadata, args=None):
        if not args:
            print(
                "Type |mdbuild help <command>| for help on individual command.\n------------\nmdbuild "
            )
            for cmd in Command.registeredCommands.values():
                print(f"  {cmd.commandName:<25} -- {cmd.description}")
        else:
            Command.registeredCommands.get(args[0]).usage()
            print()


HelpCommand()
