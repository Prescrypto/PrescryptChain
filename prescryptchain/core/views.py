# -*- coding: utf-8 -*-
from django.http import JsonResponse
from django.views.generic import View
from blockchain.models import Prescription
from django.utils import timezone


class TxStatistics(View):
    ''' Endpoint to view TX Statics '''

    def get(self, request):
        ''' GET endpoint for Txs '''
        total_tx = Prescription.objects.all().count()  # TODO modify for Transactions after merge!
        data = [ int(timezone.now().strftime('%Y%m%d%H%M%S')), total_tx ]
        return JsonResponse(data, safe=False)

