from .base import Command, Argument, presets, runCommand
from tooling.metadata import BuildMetadata

import os
import subprocess

zshComplete = """
autoload -Uz compinit
compinit

# --- begin mdbuild completion ---
_mdbuild() {
    local -a commands build_opts configure_opts

    commands=(help build clean dev-setup configure-buildroot configure list-presets select autocomplete)
    build_opts=(debug release fulldebug fullrelease)
    configure_opts=(debug release fulldebug fullrelease)

    _arguments \
        '1:command:->cmd' \
        '*::arg:->args'

    case $state in
        cmd)
            _values 'mdbuild commands' $commands
            return
        ;;
    esac

    case $words[2] in
        build)      _values 'build options' $build_opts ;;
        configure)  _values 'configure options' $configure_opts ;;
        help)       _values 'help topics' $commands ;;
    esac
}

compdef _mdbuild mdbuild ./mdbuild
# --- end mdbuild completion ---

"""

def detect_shell():
    """
    Returns: 'bash', 'zsh', or None if unknown.
    """
    # --- Method 1: inspect parent process name ---
    try:
        ppid = os.getppid()
        proc_name = subprocess.check_output(
            ["ps", "-p", str(ppid), "-o", "comm="],
            text=True
        ).strip()

        if proc_name in ("bash", "zsh"):
            return proc_name
    except Exception:
        pass

    # --- Method 2: fallback to SHELL env var ---
    shell = os.environ.get("SHELL", "")
    if shell.endswith("bash"):
        return "bash"
    if shell.endswith("zsh"):
        return "zsh"

    return None

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
    description = "Generate autocompletion for bash or zsh"
    useMessage = "Create auto-complete bash/zsh script that can auto complete the build system commands from the command line. You have to source that script."
    arguments = []

    def __init__(self):
        super().__init__("autocomplete", commandInstance=self)

    def validate(self, buildMetadata: BuildMetadata, args) -> list:
        if args:
            self.usage()
            raise ValueError("Build command does not accept any arguments.")
        return None

    def getScriptSource(self, shell):
        if shell == "zsh":
            return zshComplete
        elif shell == "bash":
            optionsSource = f"""    local commands='{" ".join([x.commandName for x in Command.registeredCommands.values()])}'"""
            scriptSourceParts = [
                scriptPrelude,
                optionsSource,
                scriptCompleter,
                createScriptEpilogue(presets),
            ]
            scriptSource = "\n".join(scriptSourceParts)
            return scriptSource

    def run(self, buildMetadata: BuildMetadata, args):
        shell = detect_shell()
        scriptSource = self.getScriptSource(shell)
        with open("mdbuild-autocomplete", "w") as file:
            file.write(scriptSource)
        print(f"Auto-complete script successfully written to mdbuild-autocomplete for {shell}")


AutoCompleteCommand()
