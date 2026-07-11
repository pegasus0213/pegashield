import sys

from PySide6.QtGui import (
    QFont,
)

from PySide6.QtWidgets import (
    QApplication,
)

from app.gui.main_window import (
    MainWindow,
)

from app.gui.theme import (
    PEGASHIELD_STYLESHEET,
)


def main():
    """
    Start the PegaShield desktop application.
    """

    application = QApplication(
        sys.argv
    )

    application.setApplicationName(
        "PegaShield"
    )

    application.setApplicationDisplayName(
        "PegaShield"
    )

    application.setOrganizationName(
        "PegaShield"
    )

    application.setFont(
        QFont(
            "Segoe UI",
            10,
        )
    )

    application.setStyleSheet(
        PEGASHIELD_STYLESHEET
    )

    window = MainWindow()

    window.show()

    return application.exec()


if __name__ == "__main__":

    sys.exit(
        main()
    )