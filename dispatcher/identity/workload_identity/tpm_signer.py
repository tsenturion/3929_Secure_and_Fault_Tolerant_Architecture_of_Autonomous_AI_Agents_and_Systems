import logging
import subprocess
from contextlib import asynccontextmanager
from threading import Lock

from fastapi import FastAPI, HTTPException

from dispatcher.identity.workload_identity.tpm import HANDLE, command, emulator, sign
from dispatcher.identity.workload_identity.workload import Challenge, TpmSignature
from dispatcher.observability.tracing.diagnostics import configure_logging

configure_logging("tpm-signer")
logger = logging.getLogger(__name__)
signing_lock = Lock()


@asynccontextmanager
async def lifespan(app: FastAPI):
    with emulator() as process:
        if HANDLE.encode() not in command("tpm2_getcap", "handles-persistent").lower():
            raise RuntimeError("В программном TPM отсутствует зарегистрированный ключ.")
        app.state.emulator = process
        logger.info("Устройство подписи TPM готово")
        yield


app = FastAPI(title="Подпись учебного TPM", lifespan=lifespan)


@app.get("/health")
def health() -> dict[str, str]:
    if app.state.emulator.poll() is not None:
        raise HTTPException(503, "Программный TPM остановлен.")
    return {"status": "ok"}


@app.post("/sign")
def sign_challenge(challenge: Challenge) -> TpmSignature:
    if not signing_lock.acquire(blocking=False):
        raise HTTPException(503, "Программный TPM занят.")
    try:
        return sign(challenge.nonce)
    except subprocess.SubprocessError, OSError, ValueError:
        logger.warning("Устройство TPM не подписало запрос")
        raise HTTPException(503, "Программный TPM не подписал запрос.") from None
    finally:
        signing_lock.release()
