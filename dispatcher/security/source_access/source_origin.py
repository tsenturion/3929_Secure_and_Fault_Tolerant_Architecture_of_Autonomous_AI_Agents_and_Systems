import httpx2


def configured_origin(value: str) -> httpx2.URL:
    """Читает базовый адрес из конфигурации. Маршруты строятся из разрешённых идентификаторов."""
    try:
        url = httpx2.URL(value)
    except httpx2.InvalidURL, ValueError:
        raise ValueError("В конфигурации источника ожидается базовый адрес HTTP(S).") from None
    if (
        url.scheme not in {"http", "https"}
        or not url.host
        or url.userinfo
        or url.raw_path != b"/"
        or url.fragment
    ):
        raise ValueError("В конфигурации источника ожидается базовый адрес HTTP(S).")
    return url
