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

FRESHCLAM_CONFIG_PATH = os.path.join(
    PEGASHIELD_DATA_DIRECTORY,
    "freshclam.conf",
)


# =================================================
# Application-data initialization
# =================================================

def create_application_directories():
    """
    Create the directories required by PegaShield.

    Existing directories are preserved.
    """

    directories = [
        PEGASHIELD_DATA_DIRECTORY,
        DATABASE_DIRECTORY,
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

def create_freshclam_configuration():
    """
    Create the FreshClam configuration used by
    PegaShield.

    FreshClam stores virus databases in the
    PegaShield application-data directory so the
    GUI does not need administrator privileges.
    """

    configuration = (
        f"DatabaseDirectory "
        f"{DATABASE_DIRECTORY}\n"
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


def initialize_application_data():
    """
    Initialize all PegaShield application-data
    directories and configuration files.
    """

    create_application_directories()

    create_freshclam_configuration()