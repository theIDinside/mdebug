#compdef mdbuild ./mdbuild

_mdbuild() {
    local -a commands build_opts configure_opts

    commands=(
        help
        build
        clean
        dev-setup
        configure-buildroot
        configure
        list-presets
        select
        autocomplete
    )

    build_opts=(
        debug
        release
        fulldebug
        fullrelease
    )

    configure_opts=(
        debug
        release
        fulldebug
        fullrelease
    )

    # First argument: choose one of the top-level commands
    _arguments \
        '1:command:->cmd' \
        '*::arg:->args'

    case $state in
        cmd)
            _values 'mdbuild commands' $commands
            return
        ;;
    esac

    # Handle subcommands
    case $words[2] in
        build)
            _values 'build options' $build_opts
            ;;
        configure)
            _values 'configure options' $configure_opts
            ;;
        help)
            _values 'help topics' $commands
            ;;
    esac
}

_mdbuild "$@"

