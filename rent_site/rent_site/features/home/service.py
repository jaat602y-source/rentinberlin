# rent_site/features/home/service.py
from rent_site.core.db import get_db
from rent_site.core.models import Listing

def get_featured_listings(limit: int = 6):
    db = get_db()
    return db.query(Listing).order_by(Listing.created_at.desc()).limit(limit).all()
