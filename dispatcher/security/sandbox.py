import ctypes
import errno
import os
import socket
from pathlib import Path
from tempfile import TemporaryFile


def verify() -> None:
    """Проверяет ограничения запущенного контейнера исполнителя."""
    status = dict(
        line.split(":", 1)
        for line in Path("/proc/self/status").read_text().splitlines()
        if ":" in line
    )
    assert os.getuid() != 0 and int(status["CapEff"].strip(), 16) == 0, (
        "Проверьте UID и capabilities."
    )
    assert status["NoNewPrivs"].strip() == "1", "no-new-privileges не активирован."
    assert status["Seccomp"].strip() == "2", "Фильтр seccomp не активирован."

    libc = ctypes.CDLL(None, use_errno=True)
    assert libc.unshare(0x00020000) == -1 and ctypes.get_errno() == errno.EPERM, (
        "Создание пространства имён монтирования должно быть запрещено."
    )
    print("Ядро: непривилегированный UID, capabilities отключены, seccomp активен.")

    mounts = Path("/proc/self/mountinfo").read_text().splitlines()
    root = next(line.split(" - ", 1)[0].split() for line in mounts if line.split()[4] == "/")
    assert "ro" in root[5].split(","), "Корневая файловая система доступна на запись."
    # Временные файлы проверяют права записи в корне и томе состояния.
    try:
        with TemporaryFile(dir="/app"):
            raise AssertionError("Исполнитель смог записать файл в корневую файловую систему.")
    except OSError as error:
        assert error.errno == errno.EROFS, "Ожидался отказ из-за режима только для чтения."
    with TemporaryFile(dir="/app/state") as state:
        state.write(b"sandbox-check")
    assert not Path("/var/run/docker.sock").exists(), "Контейнер видит сокет Docker."
    assert not Path("/app/.env").exists(), "Контейнер видит локальный .env."
    assert not Path("/run/certs/gigachat-ca.pem").exists(), (
        "Сертификат должен быть смонтирован у шлюза."
    )
    assert not any(
        os.environ.get(key)
        for key in ("OPENAI_API_KEY", "GIGACHAT_AUTH_KEY", "GIGACHAT_CREDENTIALS")
    ), "Контейнер получил ключ облачной модели."
    print("Файлы: корень только для чтения, том состояния доступен, .env и сокета Docker нет.")

    with TemporaryFile(dir="/tmp") as temporary:
        temporary.write(b"sandbox-check")

    # Прямое подключение по IP проверяет внешний маршрут отдельно от DNS.
    try:
        with socket.create_connection(("1.1.1.1", 443), timeout=2):
            raise AssertionError("Исполнитель установил внешнее соединение.")
    except OSError:
        pass
    print("Сеть: прямое внешнее соединение из исполнителя заблокировано.")


if __name__ == "__main__":
    verify()
