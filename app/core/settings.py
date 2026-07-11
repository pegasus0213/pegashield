import os

from PySide6.QtCore import (
    QSettings,
)

from app.core.paths import (
    DATABASE_DIRECTORY,
)


# =================================================
# Default application settings
# =================================================

DEFAULT_CLAMAV_DIRECTORY = (
    r"C:\Program Files\ClamAV"
)

DEFAULT_DATABASE_DIRECTORY = (
    DATABASE_DIRECTORY
)


# =================================================
# PegaShield settings manager
# =================================================

class SettingsManager:
    """
    Read and save persistent PegaShield settings.

    QSettings stores these values in the current
    Windows user profile.
    """

    def __init__(self):

        self.settings = QSettings(
            "PegaShield",
            "PegaShield",
        )


    def get_clamav_directory(
        self,
    ):

        value = self.settings.value(
            "clamav/directory",
            DEFAULT_CLAMAV_DIRECTORY,
            type=str,
        )

        return os.path.normpath(
            value
        )


    def set_clamav_directory(
        self,
        directory,
    ):

        self.settings.setValue(
            "clamav/directory",
            os.path.normpath(
                directory
            ),
        )


    def get_database_directory(
        self,
    ):

        value = self.settings.value(
            "database/directory",
            DEFAULT_DATABASE_DIRECTORY,
            type=str,
        )

        return os.path.normpath(
            value
        )


    def set_database_directory(
        self,
        directory,
    ):

        self.settings.setValue(
            "database/directory",
            os.path.normpath(
                directory
            ),
        )


    def get_open_log_on_startup(
        self,
    ):

        return self.settings.value(
            "interface/open_log_on_startup",
            False,
            type=bool,
        )


    def set_open_log_on_startup(
        self,
        enabled,
    ):

        self.settings.setValue(
            "interface/open_log_on_startup",
            enabled,
        )


    def get_clear_results_before_scan(
        self,
    ):

        return self.settings.value(
            "scan/clear_previous_results",
            True,
            type=bool,
        )


    def set_clear_results_before_scan(
        self,
        enabled,
    ):

        self.settings.setValue(
            "scan/clear_previous_results",
            enabled,
        )


    def reset_defaults(
        self,
    ):

        self.settings.clear()

        self.settings.sync()


    def sync(
        self,
    ):

        self.settings.sync()