import json
import os
import shutil
import uuid

from datetime import datetime

from app.core.paths import (
    QUARANTINE_DIRECTORY,
    QUARANTINE_METADATA_PATH,
)


# =================================================
# Quarantine metadata
# =================================================

def load_quarantine_records():
    """
    Load all quarantine records.

    Return an empty list if the metadata file does
    not exist or cannot be read.
    """

    if not os.path.isfile(
        QUARANTINE_METADATA_PATH
    ):
        return []

    try:

        with open(
            QUARANTINE_METADATA_PATH,
            "r",
            encoding="utf-8",
        ) as metadata_file:

            records = json.load(
                metadata_file
            )

        if isinstance(
            records,
            list,
        ):
            return records

    except (
        OSError,
        json.JSONDecodeError,
    ):
        pass

    return []


def save_quarantine_records(
    records,
):
    """
    Save quarantine metadata using a temporary
    file to reduce the risk of corrupting the
    metadata during a write operation.
    """

    temporary_path = (
        QUARANTINE_METADATA_PATH
        + ".tmp"
    )

    with open(
        temporary_path,
        "w",
        encoding="utf-8",
    ) as metadata_file:

        json.dump(
            records,
            metadata_file,
            indent=4,
            ensure_ascii=False,
        )

    os.replace(
        temporary_path,
        QUARANTINE_METADATA_PATH,
    )


# =================================================
# Quarantine operations
# =================================================

def quarantine_file(
    file_path,
    threat_name,
):
    """
    Move a detected file into the PegaShield
    quarantine directory and create its metadata
    record.

    Return the new quarantine record.
    """

    if not os.path.isfile(
        file_path
    ):

        raise FileNotFoundError(
            "The detected file no longer exists."
        )

    quarantine_id = (
        uuid.uuid4().hex
    )

    quarantine_path = os.path.join(
        QUARANTINE_DIRECTORY,
        f"{quarantine_id}.psq",
    )

    record = {
        "id": quarantine_id,
        "original_path": file_path,
        "quarantine_path": quarantine_path,
        "original_name": os.path.basename(
            file_path
        ),
        "threat_name": threat_name,
        "quarantined_at": (
            datetime.now()
            .astimezone()
            .isoformat(
                timespec="seconds"
            )
        ),
    }

    file_was_moved = False

    try:

        shutil.move(
            file_path,
            quarantine_path,
        )

        file_was_moved = True

        records = (
            load_quarantine_records()
        )

        records.append(
            record
        )

        save_quarantine_records(
            records
        )

        return record

    except Exception:

        if (
            file_was_moved
            and os.path.isfile(
                quarantine_path
            )
            and not os.path.exists(
                file_path
            )
        ):

            try:

                shutil.move(
                    quarantine_path,
                    file_path,
                )

            except Exception:

                pass

        raise


def restore_quarantined_file(
    record,
    overwrite=False,
):
    """
    Restore a quarantined file to its original
    location.

    If overwrite is False and a file already
    exists at the original location,
    FileExistsError is raised.
    """

    original_path = record.get(
        "original_path",
        "",
    )

    quarantine_path = record.get(
        "quarantine_path",
        "",
    )

    if not original_path:

        raise ValueError(
            "The original file path is missing."
        )

    if not quarantine_path:

        raise ValueError(
            "The quarantine file path is missing."
        )

    if not os.path.isfile(
        quarantine_path
    ):

        raise FileNotFoundError(
            "The quarantined file could not "
            "be found."
        )

    if os.path.exists(
        original_path
    ):

        if not overwrite:

            raise FileExistsError(
                "A file already exists at the "
                "original location."
            )

        if os.path.isdir(
            original_path
        ):

            raise IsADirectoryError(
                "The original path is currently "
                "a directory."
            )

        os.remove(
            original_path
        )

    original_directory = os.path.dirname(
        original_path
    )

    if original_directory:

        os.makedirs(
            original_directory,
            exist_ok=True,
        )

    shutil.move(
        quarantine_path,
        original_path,
    )

    try:

        records = (
            load_quarantine_records()
        )

        updated_records = [
            existing_record
            for existing_record in records
            if existing_record.get("id")
            != record.get("id")
        ]

        save_quarantine_records(
            updated_records
        )

    except Exception:

        if (
            os.path.isfile(
                original_path
            )
            and not os.path.exists(
                quarantine_path
            )
        ):

            try:

                shutil.move(
                    original_path,
                    quarantine_path,
                )

            except Exception:

                pass

        raise

    return original_path


def delete_quarantined_file(
    record,
):
    """
    Permanently delete a quarantined file and
    remove its metadata record.
    """

    quarantine_path = record.get(
        "quarantine_path",
        "",
    )

    if (
        quarantine_path
        and os.path.isfile(
            quarantine_path
        )
    ):

        os.remove(
            quarantine_path
        )

    records = (
        load_quarantine_records()
    )

    updated_records = [
        existing_record
        for existing_record in records
        if existing_record.get("id")
        != record.get("id")
    ]

    save_quarantine_records(
        updated_records
    )