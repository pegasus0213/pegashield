import os
import sys
import subprocess

from PySide6.QtCore import QThread, Signal
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QLabel,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)


# -------------------------------------------------
# PegaShield application-data paths
# -------------------------------------------------

PEGASHIELD_DATA_DIRECTORY = (
    r"C:\ProgramData\PegaShield"
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

FRESHCLAM_CONFIG_PATH = os.path.join(
    PEGASHIELD_DATA_DIRECTORY,
    "freshclam.conf",
)


# -------------------------------------------------
# ClamAV detection
# -------------------------------------------------

COMMON_CLAMAV_DIRECTORIES = [
    r"C:\Program Files\ClamAV",
    r"C:\Program Files (x86)\ClamAV",
    r"C:\ClamAV",
]


def find_clamav_directory():
    """
    Search common Windows installation locations
    for the required ClamAV executables.
    """

    for directory in COMMON_CLAMAV_DIRECTORIES:

        clamscan_path = os.path.join(
            directory,
            "clamscan.exe",
        )

        freshclam_path = os.path.join(
            directory,
            "freshclam.exe",
        )

        if (
            os.path.isfile(clamscan_path)
            and os.path.isfile(freshclam_path)
        ):
            return directory

    return None


def get_clamav_version(clamscan_path):
    """
    Run clamscan --version and return
    the installed engine version.
    """

    try:
        result = subprocess.run(
            [
                clamscan_path,
                "--version",
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

        output = (
            result.stdout.strip()
            or result.stderr.strip()
        )

        if output:
            return output

    except Exception:
        pass

    return "Version unavailable"


# -------------------------------------------------
# Background command worker
# -------------------------------------------------

class CommandWorker(QThread):

    log_signal = Signal(str)

    operation_finished = Signal(
        int
    )

    def __init__(
        self,
        command,
    ):
        super().__init__()

        self.command = command

    def run(self):

        return_code = -1

        try:

            process = subprocess.Popen(
                self.command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )

            if process.stdout:

                for line in process.stdout:

                    self.log_signal.emit(
                        line.rstrip()
                    )

            process.wait()

            return_code = (
                process.returncode
            )

            if return_code == 0:

                self.log_signal.emit(
                    "Operation completed "
                    "successfully."
                )

            elif return_code == 1:

                self.log_signal.emit(
                    "WARNING: Threats were "
                    "detected."
                )

            else:

                self.log_signal.emit(
                    "Operation failed with "
                    f"code {return_code}."
                )

        except FileNotFoundError:

            self.log_signal.emit(
                "ERROR: A required ClamAV "
                "executable was not found."
            )

        except Exception as error:

            self.log_signal.emit(
                f"ERROR: {error}"
            )

        self.operation_finished.emit(
            return_code
        )


# -------------------------------------------------
# Main PegaShield window
# -------------------------------------------------

class MainWindow(QWidget):

    def __init__(self):

        super().__init__()

        self.worker = None

        self.clamav_directory = None
        self.clamscan_path = None
        self.freshclam_path = None

        self.create_data_directories()

        self.create_freshclam_configuration()

        self.setWindowTitle(
            "PegaShield"
        )

        self.resize(
            900,
            650,
        )

        self.build_interface()

        self.detect_clamav()


    # ---------------------------------------------
    # Application setup
    # ---------------------------------------------

    def create_data_directories(self):

        directories = [
            DATABASE_DIRECTORY,
            LOG_DIRECTORY,
            QUARANTINE_DIRECTORY,
        ]

        for directory in directories:

            os.makedirs(
                directory,
                exist_ok=True,
            )


    def create_freshclam_configuration(self):

        configuration = (
            "DatabaseDirectory "
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


    # ---------------------------------------------
    # GUI
    # ---------------------------------------------

    def build_interface(self):

        layout = QVBoxLayout()

        title = QLabel(
            "PegaShield — Powered by ClamAV"
        )

        self.engine_status_label = QLabel(
            "ClamAV: Checking..."
        )

        self.version_label = QLabel(
            "Engine: Checking..."
        )

        self.database_label = QLabel(
            "Database: Checking..."
        )

        self.operation_status_label = QLabel(
            "Status: Starting..."
        )

        self.update_button = QPushButton(
            "Update Database"
        )

        self.scan_button = QPushButton(
            "Scan Folder"
        )

        self.log_output = QTextEdit()

        self.log_output.setReadOnly(
            True
        )

        layout.addWidget(
            title
        )

        layout.addWidget(
            self.engine_status_label
        )

        layout.addWidget(
            self.version_label
        )

        layout.addWidget(
            self.database_label
        )

        layout.addWidget(
            self.operation_status_label
        )

        layout.addWidget(
            self.update_button
        )

        layout.addWidget(
            self.scan_button
        )

        layout.addWidget(
            self.log_output
        )

        self.setLayout(
            layout
        )

        self.update_button.clicked.connect(
            self.update_database
        )

        self.scan_button.clicked.connect(
            self.scan_folder
        )


    # ---------------------------------------------
    # ClamAV diagnostics
    # ---------------------------------------------

    def detect_clamav(self):

        self.log_output.append(
            "PegaShield startup diagnostics..."
        )

        self.clamav_directory = (
            find_clamav_directory()
        )

        if not self.clamav_directory:

            self.engine_status_label.setText(
                "ClamAV: Not found"
            )

            self.version_label.setText(
                "Engine: Unavailable"
            )

            self.database_label.setText(
                "Database: Unavailable"
            )

            self.operation_status_label.setText(
                "Status: ClamAV installation "
                "required"
            )

            self.update_button.setEnabled(
                False
            )

            self.scan_button.setEnabled(
                False
            )

            self.log_output.append(
                "ERROR: ClamAV was not found "
                "in a supported location."
            )

            return

        self.clamscan_path = os.path.join(
            self.clamav_directory,
            "clamscan.exe",
        )

        self.freshclam_path = os.path.join(
            self.clamav_directory,
            "freshclam.exe",
        )

        version = get_clamav_version(
            self.clamscan_path
        )

        self.engine_status_label.setText(
            "ClamAV: Installed"
        )

        self.version_label.setText(
            f"Engine: {version}"
        )

        database_ready = (
            self.database_is_ready()
        )

        if database_ready:

            self.database_label.setText(
                "Database: Ready"
            )

        else:

            self.database_label.setText(
                "Database: Update required"
            )

        self.operation_status_label.setText(
            "Status: Ready"
        )

        self.log_output.append(
            "ClamAV detected:"
        )

        self.log_output.append(
            self.clamav_directory
        )

        self.log_output.append(
            f"Engine: {version}"
        )

        self.log_output.append(
            "Database directory:"
        )

        self.log_output.append(
            DATABASE_DIRECTORY
        )

        self.log_output.append(
            "Startup diagnostics completed."
        )


    def database_is_ready(self):

        database_files = [
            "daily.cvd",
            "daily.cld",
            "main.cvd",
            "main.cld",
            "bytecode.cvd",
            "bytecode.cld",
        ]

        for filename in database_files:

            path = os.path.join(
                DATABASE_DIRECTORY,
                filename,
            )

            if os.path.isfile(
                path
            ):

                return True

        return False


    # ---------------------------------------------
    # Command execution
    # ---------------------------------------------

    def start_command(
        self,
        command,
        status,
    ):

        self.update_button.setEnabled(
            False
        )

        self.scan_button.setEnabled(
            False
        )

        self.operation_status_label.setText(
            status
        )

        self.worker = CommandWorker(
            command
        )

        self.worker.log_signal.connect(
            self.append_log
        )

        self.worker.operation_finished.connect(
            self.command_finished
        )

        self.worker.start()


    def update_database(self):

        self.log_output.append(
            "\nStarting database update..."
        )

        command = [
            self.freshclam_path,
            "--config-file",
            FRESHCLAM_CONFIG_PATH,
        ]

        self.start_command(
            command,
            "Status: Updating database...",
        )


    def scan_folder(self):

        folder = (
            QFileDialog.getExistingDirectory(
                self,
                "Select Folder to Scan",
            )
        )

        if not folder:

            return

        self.log_output.append(
            f"\nStarting scan: {folder}"
        )

        command = [
            self.clamscan_path,
            "--recursive",
            "--database",
            DATABASE_DIRECTORY,
            folder,
        ]

        self.start_command(
            command,
            "Status: Scanning...",
        )


    def append_log(
        self,
        text,
    ):

        self.log_output.append(
            text
        )


    def command_finished(
        self,
        return_code,
    ):

        self.update_button.setEnabled(
            True
        )

        self.scan_button.setEnabled(
            True
        )

        if return_code == 0:

            self.operation_status_label.setText(
                "Status: Ready"
            )

        elif return_code == 1:

            self.operation_status_label.setText(
                "Status: Threat detected"
            )

        else:

            self.operation_status_label.setText(
                "Status: Operation failed"
            )

        if self.database_is_ready():

            self.database_label.setText(
                "Database: Ready"
            )


# -------------------------------------------------
# Application entry point
# -------------------------------------------------

if __name__ == "__main__":

    app = QApplication(
        sys.argv
    )

    window = MainWindow()

    window.show()

    sys.exit(
        app.exec()
    )