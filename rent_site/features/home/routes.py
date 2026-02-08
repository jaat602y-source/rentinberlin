# rent_site/features/home/routes.py
from flask import Blueprint, render_template
from rent_site.features.home.service import get_featured_listings

home_bp = Blueprint("home", __name__, template_folder="templates")

@home_bp.get("/")
def home():
    listings = get_featured_listings()
    return render_template("home/home.html", listings=listings)
