# rent_site/features/listings/routes.py
from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user

from rent_site.features.listings.service import create_listing, get_listing

listings_bp = Blueprint("listings", __name__, template_folder="templates")

@listings_bp.get("/listings/new")
@login_required
def new_listing():
    return render_template("listings/new.html")

@listings_bp.post("/listings/new")
@login_required
def new_listing_post():
    title = request.form.get("title", "")
    country = request.form.get("country", "")
    city = request.form.get("city", "")
    price = request.form.get("price", "0")
    description = request.form.get("description", "")

    if not title.strip() or not country.strip() or not city.strip():
        flash("Title, country and city are required.", "error")
        return redirect(url_for("listings.new_listing"))

    try:
        price_int = int(price)
        if price_int <= 0:
            raise ValueError
    except ValueError:
        flash("Price must be a positive number.", "error")
        return redirect(url_for("listings.new_listing"))

    listing = create_listing(current_user.id, title, description, country, city, price_int)
    flash("Listing created.", "success")
    return redirect(url_for("listings.detail", listing_id=listing.id))

@listings_bp.get("/listings/<int:listing_id>")
def detail(listing_id: int):
    listing = get_listing(listing_id)
    if not listing:
        return render_template("errors/404.html"), 404
    return render_template("listings/detail.html", listing=listing)
