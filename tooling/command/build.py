from .base import Command, Argument, presets, runCommand
from tooling.metadata import BuildMetadata
from os import path


class BuildCommand(Command):
    description = "Builds a preset"
    useMessage = "Build the preset 'build preset'. If no build preset argument was provided, the currently selected one will be built. (see `mdbbuild help select`)"
    arguments = [
        Argument(
            name="Build preset",
            description=f"Build preset to configure, one of  [{", ".join(presets)}]",
            typeName="string",
            type_=str,
            required=False,
        )
    ]

    def __init__(self):
        super().__init__("build", commandInstance=self)

    def validate(self, buildMetadata: BuildMetadata, args):
        if args and args[0] not in presets:
            raise ValueError(f"Preset {args[0]} is not in the list of presets")

        if args and args[0] not in buildMetadata.getConfigured():
            raise ValueError(
                f"Build preset {args[0]} not in configured set: '{", ".join(buildMetadata.getConfigured())}'"
            )

        if not args and not buildMetadata.getSelected():
            raise ValueError(
                "No preset has been configured to build. Run `mdbbuild configure <preset>` or `mdbuild list-presets` to see presets."
            )

    def run(self, buildMetadata: BuildMetadata, args):
        buildDirectory = buildMetadata.getPresetBuildDir(
            buildMetadata.getSelected() if not args else args[0]
        )
        if not path.exists(buildDirectory):
            raise RuntimeError(
                f"Build directory for preset {buildMetadata.getSelected() if not args else args[0]} does not exist. Please run 'configure' first."
            )

        runCommand(["cmake", "--build", buildDirectory])
        runCommand(
            [
                "cp",
                f"{buildDirectory}/compile_commands.json",
                buildMetadata.getProjectPath(),
            ]
        )


BuildCommand()
