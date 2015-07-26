
# Save trace setting
XTRACE=$(set +o | grep xtrace)
set -o xtrace

echo_summary "Anchor's plugin.sh was called..."
source ${DEST}/anchor/devstack/lib/anchor
(set -o posix; set)

# check for service enabled
if is_service_enabled anchor; then

    if [[ "$1" == "stack" && "$2" == "pre-install" ]]; then
        # Set up system services
        echo_summary "Configuring system services anchor"
        pre_install_anchor

    elif [[ "$1" == "stack" && "$2" == "install" ]]; then
        # Perform installation of service source
        echo_summary "Installing anchor"
        install_anchor

    elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
        # Configure after the other layer 1 and 2 services have been configured
        echo_summary "Configuring anchor"
        configure_anchor

    elif [[ "$1" == "stack" && "$2" == "extra" ]]; then
        # Initialize and start the anchor service
        echo_summary "Initializing anchor"
        init_anchor
    fi

    if [[ "$1" == "unstack" ]]; then
        # Shut down anchor services
        # no-op
        shutdown_anchor
    fi

    if [[ "$1" == "clean" ]]; then
        # Remove state and transient data
        # Remember clean.sh first calls unstack.sh
        # no-op
        cleanup_anchor
    fi
fi
