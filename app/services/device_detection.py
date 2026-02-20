import re


def is_mobile(user_agent: str) -> bool:
    mobile_keywords = [
        "Android", "webOS", "iPhone", "iPad", "iPod",
        "BlackBerry", "IEMobile", "Opera Mini", "Mobile", "Tablet",
    ]
    return any(kw.lower() in user_agent.lower() for kw in mobile_keywords)


def detect_os(user_agent: str) -> str:
    ua = user_agent.lower()

    if "iphone" in ua or "ipad" in ua or "ipod" in ua:
        return "iOS"
    if "android" in ua:
        return "Android"
    if "macintosh" in ua or "mac os" in ua:
        return "macOS"
    if "windows" in ua:
        return "Windows"
    if "linux" in ua:
        return "Linux"
    if "cros" in ua:
        return "ChromeOS"

    return "Desconocido"
