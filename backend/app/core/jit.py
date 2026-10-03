from pathlib import Path


JIT_KEY_FILES = {
    "developer01": Path(
        "/home/developer01/.ssh/authorized_keys.jit"
    )
}


def grant_ssh_key(
    linux_username: str,
    public_key: str,
) -> None:
    key_file = JIT_KEY_FILES.get(linux_username)

    if key_file is None:
        raise ValueError(
            "Linux user is not allowed for JIT access"
        )

    key = public_key.strip()

    if not key:
        raise ValueError(
            "Public key cannot be empty"
        )

    existing = []

    if key_file.exists():
        existing = [
            line.strip()
            for line in key_file.read_text().splitlines()
            if line.strip()
        ]

    if key not in existing:
        existing.append(key)

    key_file.write_text(
        "\n".join(existing) + "\n"
        if existing
        else ""
    )


def revoke_ssh_key(
    linux_username: str,
    public_key: str,
) -> None:
    key_file = JIT_KEY_FILES.get(linux_username)

    if key_file is None:
        raise ValueError(
            "Linux user is not allowed for JIT access"
        )

    key = public_key.strip()

    if not key_file.exists():
        return

    existing = [
        line.strip()
        for line in key_file.read_text().splitlines()
        if line.strip()
    ]

    remaining = [
        line
        for line in existing
        if line != key
    ]

    key_file.write_text(
        "\n".join(remaining) + "\n"
        if remaining
        else ""
    )
