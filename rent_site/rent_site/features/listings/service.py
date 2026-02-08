# rent_site/features/listings/service.py
from rent_site.core.db import get_db
from rent_site.core.models import Listing

def create_listing(owner_id: int, title: str, description: str, country: str, city: str, price: int) -> Listing:
    db = get_db()
    listing = Listing(
        owner_id=owner_id,
        title=title.strip(),
        description=(description or "").strip() or None,
        country=country.strip(),
        city=city.strip(),
        price_per_month_eur=int(price),
    )
    db.add(listing)
    db.commit()
    db.refresh(listing)
    return listing

def get_listing(listing_id: int) -> Listing | None:
    db = get_db()
    return db.get(Listing, listing_id)

def search_listings(country: str | None, city: str | None, max_price: int | None):
    db = get_db()
    q = db.query(Listing)
    if country:
        q = q.filter(Listing.country.ilike(f"%{country.strip()}%"))
    if city:
        q = q.filter(Listing.city.ilike(f"%{city.strip()}%"))
    if max_price is not None:
        q = q.filter(Listing.price_per_month_eur <= int(max_price))
    return q.order_by(Listing.created_at.desc()).all()
