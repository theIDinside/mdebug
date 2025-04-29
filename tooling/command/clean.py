from .base import Command, Argument, runCommand
import shutil
import os

from tooling.metadata import BuildMetadata


class CleanCommand(Command):
    description = "Clean a build preset directory"
    useMessage = "Clean the build directory (using the preset name). If no preset name was provided, clean all configured presets."
    arguments = [
        Argument(
            name="Clean preset",
            description=f"Specific configured preset to clean.",
            typeName="string",
            type_=str,
            required=True,
        )
    ]

    def __init__(self):
        super().__init__("clean", commandInstance=self)

    def validate(self, buildMetadata: BuildMetadata, args):
        raise NotImplementedError("Clean command has not yet been implemented")

    def run(self, buildMetadata: BuildMetadata, args):
        raise NotImplementedError("Clean command has not yet been implemented")


CleanCommand()
