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


# ClamAV executable locations
CLAMAV_DIRECTORY = r"C:\Program Files\ClamAV"

FRESHCLAM_PATH = os.path.join(
    CLAMAV_DIRECTORY,
    "freshclam.exe",
)

CLAMSCAN_PATH = os.path.join(
    CLAMAV_DIRECTORY,
    "clamscan.exe",
)


# PegaShield application-data locations
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


class CommandWorker(QThread):
    log_signal = Signal(str)

    def __init__(self, command):
        super().__init__()

        self.command = command

    def run(self):
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

            if process.returncode == 0:
                self.log_signal.emit(
                    "Operation completed successfully."
                )

            elif process.returncode == 1:
                self.log_signal.emit(
                    "Threats were detected."
                )

            else:
                self.log_signal.emit(
                    "Operation failed with "
                    f"code {process.returncode}."
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


class MainWindow(QWidget):
    def __init__(self):
        super().__init__()

        self.worker = None

        self.create_data_directories()

        self.setWindowTitle(
            "PegaShield"
        )

        self.resize(
            900,
            600,
        )

        layout = QVBoxLayout()

        title = QLabel(
            "PegaShield — Powered by ClamAV"
        )

        self.status_label = QLabel(
            "Status: Ready"
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

        self.log_output.append(
            "PegaShield initialized."
        )

        self.log_output.append(
            "Database directory:"
        )

        self.log_output.append(
            DATABASE_DIRECTORY
        )

        layout.addWidget(
            title
        )

        layout.addWidget(
            self.status_label
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

        self.status_label.setText(
            status
        )

        self.worker = CommandWorker(
            command
        )

        self.worker.log_signal.connect(
            self.append_log
        )

        self.worker.finished.connect(
            self.command_finished
        )

        self.worker.start()

    def update_database(self):
        self.log_output.append(
            "\nStarting database update..."
        )

        command = [
            FRESHCLAM_PATH,
            "--config-file",
            r"C:\ProgramData\PegaShield\freshclam.conf",
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
            CLAMSCAN_PATH,
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

    def command_finished(self):
        self.update_button.setEnabled(
            True
        )

        self.scan_button.setEnabled(
            True
        )

        self.status_label.setText(
            "Status: Ready"
        )


if __name__ == "__main__":
    app = QApplication(
        sys.argv
    )

    window = MainWindow()

    window.show()

    sys.exit(
        app.exec()
    )