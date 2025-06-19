import typer

from installation_assistant.checks.global_checks import check_if_sudo

from . import create_certs, install

app = typer.Typer()
app.add_typer(install.app, name="install")
app.add_typer(create_certs.app, name="create-certs")


@app.callback(no_args_is_help=True)
def cli() -> None:
    """
    Wazuh Installation Assistant CLI.

    This CLI tool helps in installing and configuring Wazuh components such as Wazuh Server, Wazuh Indexer, and Wazuh Dashboard.
    It also provides functionality to create the components certificates and uninstall Wazuh components.
    """

    check_if_sudo()


def main():
    app(prog_name="wazuh-ia")


if __name__ == "__main__":
    main()
