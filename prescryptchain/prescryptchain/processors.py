# -*- encoding: utf-8 -*-
# Define custom processors to all templates
# This actions add custom var to templating use
from django.conf import settings

def add_wallet_url(request):
    # add production var to templates
    return {"WALLET_URL": settings.WALLET_URL}
