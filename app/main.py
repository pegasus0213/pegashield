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
FRESHCLAM_PATH = r"C:\Program Files\ClamAV\freshclam.exe"
CLAMSCAN_PATH = r"C:\Program Files\ClamAV\clamscan.exe"


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
                    self.log_signal.emit(line.rstrip())

            process.wait()

            if process.returncode == 0:
                self.log_signal.emit(
                    "Operation completed successfully."
                )
            else:
                self.log_signal.emit(
                    f"Operation finished with code "
                    f"{process.returncode}."
                )

        except FileNotFoundError:
            self.log_signal.emit(
                "ERROR: ClamAV executable was not found. "
                "Check that ClamAV is installed in "
                r"C:\Program Files\ClamAV."
            )

        except Exception as error:
            self.log_signal.emit(
                f"ERROR: {error}"
            )


class MainWindow(QWidget):
    def __init__(self):
        super().__init__()

        self.worker = None

        self.setWindowTitle("PegaShield")
        self.resize(900, 600)

        layout = QVBoxLayout()

        title = QLabel("PegaShield — Powered by ClamAV")

        self.update_button = QPushButton(
            "Update Database"
        )

        self.scan_button = QPushButton(
            "Scan Folder"
        )

        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.append(
            "PegaShield initialized."
        )

        layout.addWidget(title)
        layout.addWidget(self.update_button)
        layout.addWidget(self.scan_button)
        layout.addWidget(self.log_output)

        self.setLayout(layout)

        self.update_button.clicked.connect(
            self.update_database
        )

        self.scan_button.clicked.connect(
            self.scan_folder
        )

    def start_command(self, command):
        self.update_button.setEnabled(False)
        self.scan_button.setEnabled(False)

        self.worker = CommandWorker(command)

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

        self.start_command(
            [FRESHCLAM_PATH]
        )

    def scan_folder(self):
        folder = QFileDialog.getExistingDirectory(
            self,
            "Select Folder to Scan",
        )

        if not folder:
            return

        self.log_output.append(
            f"\nStarting scan: {folder}"
        )

        command = [
            CLAMSCAN_PATH,
            "--recursive",
            folder,
        ]

        self.start_command(command)

    def append_log(self, text):
        self.log_output.append(text)

    def command_finished(self):
        self.update_button.setEnabled(True)
        self.scan_button.setEnabled(True)


if __name__ == "__main__":
    app = QApplication(sys.argv)

    window = MainWindow()
    window.show()

    sys.exit(app.exec())