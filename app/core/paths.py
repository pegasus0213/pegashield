import os


# =================================================
# PegaShield application-data locations
# =================================================

PEGASHIELD_DATA_DIRECTORY = os.path.join(
    os.environ.get(
        "PROGRAMDATA",
        r"C:\ProgramData",
    ),
    "PegaShield",
)

DATABASE_DIRECTORY = os.path.join(
    PEGASHIELD_DATA_DIRECTORY,
    "database",
)

LOG_DIRECTORY = os.path.join(
    PEGASHIELD_DATA_DIRECTORY,
    "logs",
)

QUARANTINE_DIRECTORY = os.path.join(
    PEGASHIELD_DATA_DIRECTORY,
    "quarantine",
)

QUARANTINE_METADATA_PATH = os.path.join(
    QUARANTINE_DIRECTORY,
    "quarantine.json",
)

SCAN_HISTORY_PATH = os.path.join(
    PEGASHIELD_DATA_DIRECTORY,
    "scan_history.json",
)

FRESHCLAM_CONFIG_PATH = os.path.join(
    PEGASHIELD_DATA_DIRECTORY,
    "freshclam.conf",
)


# =================================================
# Application-data initialization
# =================================================

def create_application_directories(
    database_directory=None,
):
    """
    Create the directories required by PegaShield.

    A custom database directory may be supplied.
    Existing directories are preserved.
    """

    if database_directory is None:

        database_directory = (
            DATABASE_DIRECTORY
        )

    directories = [
        PEGASHIELD_DATA_DIRECTORY,
        database_directory,
        LOG_DIRECTORY,
        QUARANTINE_DIRECTORY,
    ]

    for directory in directories:

        os.makedirs(
            directory,
            exist_ok=True,
        )


# =================================================
# FreshClam configuration
# =================================================

def create_freshclam_configuration(
    database_directory=None,
):
    """
    Create the FreshClam configuration used by
    PegaShield.

    FreshClam stores virus databases in the
    selected PegaShield database directory.
    """

    if database_directory is None:

        database_directory = (
            DATABASE_DIRECTORY
        )

    database_directory = os.path.normpath(
        database_directory
    )

    configuration = (
        "DatabaseDirectory "
        f"{database_directory}\n"
        "DatabaseMirror "
        "database.clamav.net\n"
        "Checks 12\n"
    )

    with open(
        FRESHCLAM_CONFIG_PATH,
        "w",
        encoding="utf-8",
    ) as configuration_file:

        configuration_file.write(
            configuration
        )


def initialize_application_data(
    database_directory=None,
):
    """
    Initialize PegaShield application-data
    directories and generate the FreshClam
    configuration for the selected database.
    """

    if database_directory is None:

        database_directory = (
            DATABASE_DIRECTORY
        )

    create_application_directories(
        database_directory
    )

    create_freshclam_configuration(
        database_directory
    )