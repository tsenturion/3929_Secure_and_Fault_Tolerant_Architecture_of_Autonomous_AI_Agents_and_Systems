import logging
import os
import subprocess
from base64 import b64encode
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic, sleep

from dispatcher.identity.workload_identity.identity_pki import atomic_write
from dispatcher.identity.workload_identity.workload import TpmSignature, challenge_message

logger = logging.getLogger(__name__)
STATE = Path("/app/tpm-state")
PUBLIC_KEY = Path("/app/tpm-trust/agent.pem")
HANDLE = "0x81010021"
ATTRIBUTES = "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign"


def command(*args: str) -> bytes:
    return subprocess.run(
        args,
        env={**os.environ, "TPM2TOOLS_TCTI": "swtpm:host=127.0.0.1,port=2321"},
        check=True,
        capture_output=True,
        timeout=5,
    ).stdout


@contextmanager
def emulator() -> Iterator[subprocess.Popen]:
    with subprocess.Popen(
        [
            "swtpm",
            "socket",
            "--tpm2",
            "--tpmstate",
            f"dir={STATE}",
            "--server",
            "type=tcp,port=2321,bindaddr=127.0.0.1",
            "--ctrl",
            "type=tcp,port=2322,bindaddr=127.0.0.1",
            "--flags",
            "startup-clear",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ) as process:
        try:
            deadline = monotonic() + 5
            while True:
                try:
                    command("tpm2_getcap", "properties-fixed")
                    break
                except subprocess.CalledProcessError:
                    if process.poll() is not None or monotonic() >= deadline:
                        raise RuntimeError("Программный TPM не запустился.") from None
                    sleep(0.1)
            yield process
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()


def provision() -> None:
    """Создаёт ключ подписи в программном TPM и сохраняет открытую часть для исполнителя."""
    if PUBLIC_KEY.exists():
        return
    with emulator(), TemporaryDirectory() as workdir:
        path = Path(workdir)
        context = str(path / "key.ctx")
        if HANDLE.encode() not in command("tpm2_getcap", "handles-persistent").lower():
            command(
                "tpm2_createprimary",
                "-C",
                "o",
                "-G",
                "rsa2048:rsassa",
                "-g",
                "sha256",
                "-a",
                ATTRIBUTES,
                "-c",
                context,
            )
            command("tpm2_evictcontrol", "-C", "o", "-c", context, HANDLE)
        public = path / "agent.pem"
        command("tpm2_readpublic", "-c", HANDLE, "-f", "pem", "-o", str(public))
        atomic_write(PUBLIC_KEY, public.read_bytes())
        PUBLIC_KEY.chmod(0o644)
    logger.info("Открытый ключ программного TPM зарегистрирован")


def sign(nonce: str) -> TpmSignature:
    """Подписывает запрос ключом программного TPM по сохранённому дескриптору."""
    with TemporaryDirectory() as workdir:
        message = Path(workdir) / "message"
        signature = Path(workdir) / "signature"
        message.write_bytes(challenge_message(nonce))
        command(
            "tpm2_sign",
            "-c",
            HANDLE,
            "-g",
            "sha256",
            "-s",
            "rsassa",
            "-f",
            "plain",
            "-o",
            str(signature),
            str(message),
        )
        return TpmSignature(signature=b64encode(signature.read_bytes()).decode("ascii"))


if __name__ == "__main__":
    from dispatcher.observability.tracing.diagnostics import configure_logging

    configure_logging("tpm-provision")
    try:
        provision()
    except subprocess.CalledProcessError as error:
        logger.error("Ошибка регистрации TPM команда=%s код=%s", error.cmd[0], error.returncode)
        raise SystemExit(f"Регистрация TPM остановлена на команде {error.cmd[0]}.") from None
    except subprocess.SubprocessError, OSError, RuntimeError:
        logger.error("Не удалось подготовить ключ программного TPM")
        raise SystemExit("Подготовка программного TPM завершилась ошибкой.") from None
