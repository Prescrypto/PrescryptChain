# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.contrib import admin
from .models import Block, Prescription, Medication, Transaction


class PrescriptionAdmin(admin.ModelAdmin):
    ''' Custom Prescription Admin  '''
    def has_add_permission(self, request, obj=None):
        return True

    def has_delete_permission(self, request, obj=None):
        return False

    search_fields = ['id']
    list_per_page = 25
    fields = ('id','public_key', 'medic_name', 'patient_name','timestamp')
    exclude = ('public_key','private_key',)
    readonly_fields = ("public_key", "private_key", "medic_name",
        "medic_cedula", "medic_hospital", "patient_name", "patient_age",
        "diagnosis", "timestamp", "location", "details", "extras", "bought", "signature")
    # inlines = [MedicationInline, ]


# Register your models here.
admin.site.register(Block)
admin.site.register(Prescription)
admin.site.register(Medication)
admin.site.register(Transaction)
