from .base import Command, Argument
from tooling.metadata import BuildMetadata


class SelectCommand(Command):
    description = "Set selected build preset."
    useMessage = "Select the default build type to use for building. This way you can just say ./mdbuild"
    arguments = [
        Argument(
            name="Build type",
            description="Build type to select (must already be configured).",
            typeName="string",
            type_=str,
            required=True,
        )
    ]

    def __init__(self):
        super().__init__("select", commandInstance=self)

    def validate(self, buildMetadata: BuildMetadata, args):
        pass

    def run(self, buildMetadata: BuildMetadata, args):
        buildPreset = args[0]
        buildMetadata.setSelected(buildPreset)
        print(f"Selected build type '{buildPreset}'.")


SelectCommand()
