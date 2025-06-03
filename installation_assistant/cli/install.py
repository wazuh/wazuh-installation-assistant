from typing import Annotated

import typer

app = typer.Typer()


@app.callback(
    help="""This command installs Wazuh components on this machine.
    It can install all components (AIO) or a specific component (Wazuh Server, Wazuh Indexer, Wazuh Dashboard).""",
)
def install_callback(
    ctx: typer.Context,
    ignore_checks: Annotated[
        bool, typer.Option("--ignore-checks", "-i", help="Ignore the check for minimum hardware requirements.")
    ] = False,
    overwrite: Annotated[
        bool,
        typer.Option(
            "--overwrite",
            "-o",
            help="Overwrites previously installed components. This will erase all the existing configuration and data.",
        ),
    ] = False,
    development: Annotated[
        bool,
        typer.Option(
            "--development",
            "-d",
            help="""Use development packages instead of the production ones.
            If the option --url-file is specified, the development packages will be downloaded from the URL file, otherwise,
            the development packages will be downloaded from the current pre-release version.""",
        ),
    ] = False,
    url_file: Annotated[
        str | None,
        typer.Option(
            "--url-file",
            "-f",
            help="This option must be used with --development|-d option. It allows to specify a file with the URLs of the development packages to be installed. The file must to follow the format given by Wazuh.",
        ),
    ] = None,
) -> None:
    """
    Callback function for the install command.

    This function is called when the install command is executed. It can be used to perform any setup or initialization tasks before the actual installation process begins.

    Args:
        ignore_checks (bool): If True, ignores the check for minimum hardware requirements.
        overwrite (bool): If True, overwrites previously installed components, erasing all existing configuration and data.
        development (bool): If True, uses development packages instead of production ones.
        url_file (str | None): Path to a file with URLs of development packages to be installed. Required if --development is specified.
    """
    pass


@app.command(name="aio", help="Install and configure Wazuh Server, Wazuh Indexer and Wazuh dashboard in this machine.")
def install_aio(
    config_file: Annotated[
        str | None,
        typer.Option(
            "--config-file",
            "-c",
            help="""Path to the configuration file used to generate
            wazuh-install-files.tar file containing the files that will be needed for installation.
            By default, the Wazuh installation assistant will search for a file named config.yml in the same path where the command is executed.""",
        ),
    ] = None,
):
    """
    Install and configure Wazuh Server, Wazuh Indexer, and Wazuh Dashboard in this machine as an All-in-One (AIO) installation.

    Args:
        config_file (str | None): Path to the configuration file used to generate
            wazuh-install-files.tar file containing the files that will be needed for installation.
            By default, the Wazuh installation assistant will search for a file named config.yml in the same path where the command is executed.
    """
    pass


@app.command(name="component", help="Install the specified Wazuh component.")
def install_component(
    name: Annotated[
        str,
        typer.Argument(
            help="Name of the component to install. The name must be one of the following: 'wazuh_server', 'wazuh_indexer', 'wazuh_dashboard'"
        ),
    ],
    node_name: Annotated[
        str,
        typer.Option(
            "--node",
            "-n",
            help="Name of the node to install the component on. If not provided,",
        ),
    ],
    install_files: Annotated[
        str | None,
        typer.Option(
            "--tar",
            "-t",
            help="""Path to tar file containing certificate files.
            By default, the Wazuh installation assistant will search for a file named wazuh-install-files.tar in the same path where the command is executed.""",
        ),
    ] = None,
):
    """
    Install the specified Wazuh component.
    Args:
        name (str): Name of the component to install. The name must be one of the following: 'wazuh_server', 'wazuh_indexer', 'wazuh_dashboard'.
        node_name (str): Name of the node to install the component on. If not provided, the component will be installed on the local machine.
        install_files (str | None): Path to tar file containing certificate files.
            By default, the Wazuh installation assistant will search for a file named wazuh-install-files.tar in the same path where the command is executed.
    """
    pass
