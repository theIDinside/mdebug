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
            description=f"Specific configured preset(s) to clean.",
            typeName="string | string[]",
            type_=list[str],
            required=True,
        )
    ]

    def __init__(self):
        super().__init__("clean", commandInstance=self)

    def validate(self, buildMetadata: BuildMetadata, args):
        super().validate(buildMetadata=buildMetadata, args=args)
        # "all" is a valid argument
        if args[0].lower() == "all":
            configured = buildMetadata.getConfigured()
            if len(configured) > 0:
                return configured
            else:
                raise ValueError("No configured builds to remove")

        configured_presets = buildMetadata.getConfigured()
        for arg in args:
            if not isinstance(arg, str):
                raise ValueError(f"Invalid argument type: '{arg}' (expected string)")
            if arg not in configured_presets:
                raise ValueError(
                    f"Unknown preset: '{arg}'. Valid options are: {', '.join(configured_presets)}"
                )
        return args

    def run(self, buildMetadata: BuildMetadata, args):
        for arg in args:
            try:
                path = f"{buildMetadata.getBuildRoot()}/{arg}"
                shutil.rmtree(path)
            except Exception as e:
                print(f"Removing of {path} failed\nError: {e}")
            if not os.path.exists(path):
                buildMetadata.removeConfigured(arg)
            if buildMetadata.getSelected() == arg:
                buildMetadata.setSelected(buildType=None)

        if len(buildMetadata.getConfigured()) == 0:
            try:
                buildMetadata.setSelected(buildType=None)
            except:
                pass


CleanCommand()
