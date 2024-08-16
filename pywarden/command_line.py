import click

from pywarden.app.bitwarden import backup

@click.group()
def entry_point():
    """
    pybw wraps Bitwarden CLI to provide higher level functionality

    The Bitwarden CLI is a convenient interface provided by Bitwarden for
    enabling automation. The default Bitwarden CLI provides mechanisms for
    perform single operation such as exporting a personal vault. However,
    the API does not provide ability easily backup all the vaults and organizations
    to which an account is responsible. These are the sort of higher level wrapping
    operations supported by this utility.
    """
    pass

entry_point.add_command(backup)

def main():
    entry_point()
