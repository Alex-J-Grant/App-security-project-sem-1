import pycountry

def get_countries():
    return sorted(
        [(c.alpha_2, c.name) for c in pycountry.countries],
        key=lambda x: x[1]
    )
