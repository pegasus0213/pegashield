import os

from PySide6.QtCore import (
    Signal,
)

from PySide6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from app.core.settings import (
    DEFAULT_CLAMAV_DIRECTORY,
    DEFAULT_DATABASE_DIRECTORY,
    SettingsManager,
)


class SettingsWindow(QWidget):
    """
    Configure persistent PegaShield options.
    """

    settings_saved = Signal()


    def __init__(
        self,
        settings_manager,
    ):

        super().__init__()

        self.settings_manager = (
            settings_manager
        )

        self.setWindowTitle(
            "PegaShield Settings"
        )

        self.setMinimumWidth(
            720
        )

        self.resize(
            780,
            480,
        )

        self.build_interface()

        self.load_settings()


    # =============================================
    # Interface
    # =============================================

    def build_interface(self):

        main_layout = QVBoxLayout(
            self
        )

        main_layout.setContentsMargins(
            22,
            20,
            22,
            20,
        )

        main_layout.setSpacing(
            14
        )

        title = QLabel(
            "PEGASHIELD SETTINGS"
        )

        title.setObjectName(
            "settingsTitle"
        )

        description = QLabel(
            "Configure ClamAV locations and "
            "PegaShield interface behavior."
        )

        description.setObjectName(
            "settingsDescription"
        )

        main_layout.addWidget(
            title
        )

        main_layout.addWidget(
            description
        )

        main_layout.addWidget(
            self.create_clamav_section()
        )

        main_layout.addWidget(
            self.create_interface_section()
        )

        main_layout.addStretch()

        main_layout.addLayout(
            self.create_button_row()
        )


    def create_clamav_section(
        self,
    ):

        panel = QFrame()

        panel.setObjectName(
            "settingsPanel"
        )

        layout = QVBoxLayout(
            panel
        )

        layout.setContentsMargins(
            18,
            16,
            18,
            16,
        )

        layout.setSpacing(
            10
        )

        title = QLabel(
            "CLAMAV LOCATIONS"
        )

        title.setObjectName(
            "sectionTitle"
        )

        clamav_label = QLabel(
            "ClamAV installation folder"
        )

        self.clamav_path_edit = (
            QLineEdit()
        )

        self.clamav_path_edit.setPlaceholderText(
            DEFAULT_CLAMAV_DIRECTORY
        )

        clamav_browse_button = (
            QPushButton(
                "Browse"
            )
        )

        clamav_browse_button.clicked.connect(
            self.browse_clamav_directory
        )

        clamav_row = QHBoxLayout()

        clamav_row.addWidget(
            self.clamav_path_edit
        )

        clamav_row.addWidget(
            clamav_browse_button
        )

        database_label = QLabel(
            "Virus database folder"
        )

        self.database_path_edit = (
            QLineEdit()
        )

        self.database_path_edit.setPlaceholderText(
            DEFAULT_DATABASE_DIRECTORY
        )

        database_browse_button = (
            QPushButton(
                "Browse"
            )
        )

        database_browse_button.clicked.connect(
            self.browse_database_directory
        )

        database_row = QHBoxLayout()

        database_row.addWidget(
            self.database_path_edit
        )

        database_row.addWidget(
            database_browse_button
        )

        layout.addWidget(
            title
        )

        layout.addWidget(
            clamav_label
        )

        layout.addLayout(
            clamav_row
        )

        layout.addWidget(
            database_label
        )

        layout.addLayout(
            database_row
        )

        return panel


    def create_interface_section(
        self,
    ):

        panel = QFrame()

        panel.setObjectName(
            "settingsPanel"
        )

        layout = QVBoxLayout(
            panel
        )

        layout.setContentsMargins(
            18,
            16,
            18,
            16,
        )

        layout.setSpacing(
            10
        )

        title = QLabel(
            "APPLICATION BEHAVIOR"
        )

        title.setObjectName(
            "sectionTitle"
        )

        self.open_log_checkbox = (
            QCheckBox(
                "Show the activity log "
                "when PegaShield starts"
            )
        )

        self.clear_results_checkbox = (
            QCheckBox(
                "Clear previous results "
                "before starting a new scan"
            )
        )

        layout.addWidget(
            title
        )

        layout.addWidget(
            self.open_log_checkbox
        )

        layout.addWidget(
            self.clear_results_checkbox
        )

        return panel


    def create_button_row(
        self,
    ):

        layout = QHBoxLayout()

        self.reset_button = QPushButton(
            "Restore Defaults"
        )

        self.cancel_button = QPushButton(
            "Cancel"
        )

        self.save_button = QPushButton(
            "Save Settings"
        )

        self.save_button.setObjectName(
            "primaryButton"
        )

        self.reset_button.clicked.connect(
            self.restore_defaults
        )

        self.cancel_button.clicked.connect(
            self.close
        )

        self.save_button.clicked.connect(
            self.save_settings
        )

        layout.addWidget(
            self.reset_button
        )

        layout.addStretch()

        layout.addWidget(
            self.cancel_button
        )

        layout.addWidget(
            self.save_button
        )

        return layout


    # =============================================
    # Settings
    # =============================================

    def load_settings(
        self,
    ):

        self.clamav_path_edit.setText(
            self.settings_manager
            .get_clamav_directory()
        )

        self.database_path_edit.setText(
            self.settings_manager
            .get_database_directory()
        )

        self.open_log_checkbox.setChecked(
            self.settings_manager
            .get_open_log_on_startup()
        )

        self.clear_results_checkbox.setChecked(
            self.settings_manager
            .get_clear_results_before_scan()
        )


    def save_settings(
        self,
    ):

        clamav_directory = (
            self.clamav_path_edit
            .text()
            .strip()
        )

        database_directory = (
            self.database_path_edit
            .text()
            .strip()
        )

        if not self.validate_clamav_directory(
            clamav_directory
        ):

            QMessageBox.warning(
                self,
                "Invalid ClamAV Folder",
                (
                    "The selected folder must "
                    "contain both:\n\n"
                    "clamscan.exe\n"
                    "freshclam.exe"
                ),
            )

            return

        if not os.path.isdir(
            database_directory
        ):

            create_answer = (
                QMessageBox.question(
                    self,
                    "Create Database Folder",
                    (
                        "The selected database "
                        "folder does not exist."
                        "\n\nCreate it now?"
                    ),
                    (
                        QMessageBox.Yes
                        | QMessageBox.No
                    ),
                    QMessageBox.Yes,
                )
            )

            if (
                create_answer
                != QMessageBox.Yes
            ):

                return

            try:

                os.makedirs(
                    database_directory,
                    exist_ok=True,
                )

            except OSError as error:

                QMessageBox.critical(
                    self,
                    "Folder Creation Failed",
                    str(error),
                )

                return

        self.settings_manager.set_clamav_directory(
            clamav_directory
        )

        self.settings_manager.set_database_directory(
            database_directory
        )

        self.settings_manager.set_open_log_on_startup(
            self.open_log_checkbox
            .isChecked()
        )

        self.settings_manager.set_clear_results_before_scan(
            self.clear_results_checkbox
            .isChecked()
        )

        self.settings_manager.sync()

        self.settings_saved.emit()

        QMessageBox.information(
            self,
            "Settings Saved",
            (
                "PegaShield settings were "
                "saved successfully."
            ),
        )

        self.close()


    def restore_defaults(
        self,
    ):

        confirmation = (
            QMessageBox.question(
                self,
                "Restore Defaults",
                (
                    "Restore all PegaShield "
                    "settings to their default "
                    "values?"
                ),
                (
                    QMessageBox.Yes
                    | QMessageBox.No
                ),
                QMessageBox.No,
            )
        )

        if (
            confirmation
            != QMessageBox.Yes
        ):

            return

        self.clamav_path_edit.setText(
            DEFAULT_CLAMAV_DIRECTORY
        )

        self.database_path_edit.setText(
            DEFAULT_DATABASE_DIRECTORY
        )

        self.open_log_checkbox.setChecked(
            False
        )

        self.clear_results_checkbox.setChecked(
            True
        )


    # =============================================
    # Folder selection
    # =============================================

    def browse_clamav_directory(
        self,
    ):

        directory = (
            QFileDialog
            .getExistingDirectory(
                self,
                "Select ClamAV Folder",
                self.clamav_path_edit
                .text(),
            )
        )

        if directory:

            self.clamav_path_edit.setText(
                directory
            )


    def browse_database_directory(
        self,
    ):

        directory = (
            QFileDialog
            .getExistingDirectory(
                self,
                "Select Database Folder",
                self.database_path_edit
                .text(),
            )
        )

        if directory:

            self.database_path_edit.setText(
                directory
            )


    # =============================================
    # Validation
    # =============================================

    def validate_clamav_directory(
        self,
        directory,
    ):

        clamscan_path = os.path.join(
            directory,
            "clamscan.exe",
        )

        freshclam_path = os.path.join(
            directory,
            "freshclam.exe",
        )

        return (
            os.path.isfile(
                clamscan_path
            )
            and os.path.isfile(
                freshclam_path
            )
        )