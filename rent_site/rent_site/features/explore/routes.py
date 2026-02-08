# rent_site/features/explore/routes.py
from flask import Blueprint, render_template, request
from rent_site.features.explore.service import explore_search

explore_bp = Blueprint("explore", __name__, template_folder="templates")

@explore_bp.get("/explore")
def explore():
    country = request.args.get("country") or None
    city = request.args.get("city") or None
    max_price_raw = request.args.get("max_price") or None
    max_price = None
    if max_price_raw:
        try:
            max_price = int(max_price_raw)
        except ValueError:
            max_price = None

    listings = explore_search(country, city, max_price)
    return render_template("explore/explore.html", listings=listings, country=country, city=city, max_price=max_price_raw)
