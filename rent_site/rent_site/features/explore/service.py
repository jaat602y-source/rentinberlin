# rent_site/features/explore/service.py
from rent_site.features.listings.service import search_listings

def explore_search(country: str | None, city: str | None, max_price: int | None):
    return search_listings(country=country, city=city, max_price=max_price)
