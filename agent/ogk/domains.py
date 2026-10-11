_SECOND = {"co", "com", "net", "org", "gov", "edu", "ac"}


def sld(host: str) -> str:
    """Tên miền cấp hai (NT2: không lưu URL/subdomain đầy đủ). vd a.b.example.com -> example.com; x.edu.vn -> x.edu.vn"""
    p = host.lower().rstrip(".").split(".")
    if len(p) <= 2:
        return ".".join(p)
    if len(p[-1]) == 2 and p[-2] in _SECOND:
        return ".".join(p[-3:])
    return ".".join(p[-2:])


def matches(host: str, domain: str) -> bool:
    return host == domain or host.endswith("." + domain)
