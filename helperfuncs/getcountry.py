import pycountry

def get_countries():
    return sorted(
        [(c.alpha_2, c.name) for c in pycountry.countries],
        key=lambda x: x[1]
    )


def country_name_from_code(code: str):
    """
    Convert ISO 3166 alpha-2 code (e.g., 'US') into full country name.
    Returns None if not found.
    """
    try:
        country = pycountry.countries.get(alpha_2=code.upper())
        if country:
            return country.name
    except LookupError:
        return None
    return None