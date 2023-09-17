from pathlib import Path

BLOCK_SIZE = 16
PAGE_SIZE = 1024

FLASH_PAGES = 256
FLASH_SIZE = FLASH_PAGES * PAGE_SIZE
EEPROM_PAGES = 2
EEPROM_SIZE = EEPROM_PAGES * PAGE_SIZE

FW_FLASH_PAGES = 110
FW_FLASH_SIZE = FW_FLASH_PAGES * PAGE_SIZE
FW_FLASH_BLOCKS = FW_FLASH_SIZE // BLOCK_SIZE

FW_EEPROM_PAGES = 2
FW_EEPROM_SIZE = FW_EEPROM_PAGES * PAGE_SIZE
FW_EEPROM_BLOCKS = FW_EEPROM_SIZE // BLOCK_SIZE

TOTAL_FW_SIZE = FW_FLASH_SIZE + FW_EEPROM_SIZE
TOTAL_FW_PAGES = FW_FLASH_PAGES + FW_EEPROM_PAGES
TOTAL_FW_BLOCKS = FW_FLASH_BLOCKS + FW_EEPROM_BLOCKS


def package_device(
    bin_path: Path,
    eeprom_path: Path,
    image_path: Path,
    replace_secrets: bool,
    unlock_secret: str,
    feature1_secret: str,
    feature2_secret: str,
    feature3_secret: str,
):
    """
    Package a device image for use with the bootstrapper

    Accepts up to 64 bytes (encoded in hex) to insert as a secret in EEPROM
    """
    # Read input bin file
    bin_data = bin_path.read_bytes()

    # Pad bin data to max size
    image_bin_data = bin_data.ljust(FW_FLASH_SIZE, b"\xff")

    # Read EEPROM data
    eeprom_data = eeprom_path.read_bytes()

    # Pad EEPROM to max size
    image_eeprom_data = eeprom_data.ljust(FW_EEPROM_SIZE, b"\xff")

    # Put secrets in EEPROM if used
    if replace_secrets:
        # Convert secrets to bytes
        unlock_secret = unlock_secret.encode()
        feature1_secret = feature1_secret.encode()
        feature2_secret = feature2_secret.encode()
        feature3_secret = feature3_secret.encode()

        # Check secret lengths
        if len(unlock_secret) > 64:
            raise Exception(f"Unlock secret too long ({len(unlock_secret)} > 64)")

        if len(feature1_secret) > 64:
            raise Exception(f"Feature 1 secret too long ({len(feature1_secret)} > 64)")

        if len(feature2_secret) > 64:
            raise Exception(f"Feature 2 secret too long ({len(feature2_secret)} > 64)")

        if len(feature3_secret) > 64:
            raise Exception(f"Feature 3 secret too long ({len(feature3_secret)} > 64)")

        # Pad secrets to 64 bytes
        unlock_secret = unlock_secret.ljust(64, b".")
        feature1_secret = feature1_secret.ljust(64, b".")
        feature2_secret = feature2_secret.ljust(64, b".")
        feature3_secret = feature3_secret.ljust(64, b".")

        # Replace end of EEPROM data with secret values
        image_eeprom_data = (
            image_eeprom_data[: FW_EEPROM_SIZE - 256]
            + feature3_secret
            + feature2_secret
            + feature1_secret
            + unlock_secret
        )

    # Create phys_image.bin
    image_data = image_bin_data + image_eeprom_data

    # Write output binary
    image_path.write_bytes(image_data)


package_device(
    Path("./car.bin"), Path("./car.eeprom"), Path("./car.img"), False, "", "", "", ""
)
