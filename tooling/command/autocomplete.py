from .base import Command, Argument, presets, runCommand
from tooling.metadata import BuildMetadata

scriptPrelude = """
#!/bin/bash

_mdbuild_completion() {
    local cur prev cmd
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
"""
# Between these two, we insert commands="a b c"
scriptCompleter = """
    # If no command yet, complete the command
    if [[ $COMP_CWORD -eq 1 ]]; then 
        COMPREPLY=( $(compgen -W "${commands}" -- "${cur}") )
        return 0
    fi

    # Identify which command we're working under
    cmd="${COMP_WORDS[1]}"

    case "${cmd}" in"""


# The last part of the script. Between these two we insert the switch case statements
# and the individual complete logic required for that command.
def createScriptEpilogue(presets):
    return f"""         build)
            local build_opts="{" ".join(presets)}"
            COMPREPLY=( $(compgen -W "${{build_opts}}" -- "${{cur}}") )
            ;;
        configure)
            local configure_opts="{" ".join(presets)}"
            COMPREPLY=( $(compgen -W "${{configure_opts}}" -- "${{cur}}") )
            ;;
        help)
            COMPREPLY=( $(compgen -W "${{commands}}" -- "${{cur}}") )
            ;;
    esac
}}

# Attach the completion function to ./mdbuild
complete -F _mdbuild_completion ./mdbuild
complete -F _mdbuild_completion mdbuild
"""


class AutoCompleteCommand(Command):
    description = "Generate autocompletion for bash"
    useMessage = "Create auto-complete bash script that can auto complete the build system commands from the command line. You have to source that script."
    arguments = []

    def __init__(self):
        super().__init__("autocomplete", commandInstance=self)

    def validate(self, buildMetadata: BuildMetadata, args) -> list:
        if args:
            self.usage()
            raise ValueError("Build command does not accept any arguments.")
        return None

    def run(self, buildMetadata: BuildMetadata, args):
        optionsSource = f"""    local commands='{" ".join([x.commandName for x in Command.registeredCommands.values()])}'"""
        scriptSourceParts = [
            scriptPrelude,
            optionsSource,
            scriptCompleter,
            createScriptEpilogue(presets),
        ]
        scriptSource = "\n".join(scriptSourceParts)
        with open("autocomplete.sh", "w") as file:
            file.write(scriptSource)

        print("Auto-complete script successfully written to autocomplete.sh")


AutoCompleteCommand()
