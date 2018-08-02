# -*- encoding: utf-8 -*-
# From Forms
from django import forms
from django.forms import extras
from django.core.exceptions import ValidationError
# Models
from blockchain.models import Prescription

class NewPrescriptionForm(forms.ModelForm):
    class Meta:
        model = Prescription
        fields = ('public_key', 'medic_name', 'medic_cedula', 'patient_name', 'patient_age', 'diagnosis')
        labels = {
            'diagnosis': '* Diágnostico:',
        }

        widgets = {
            'diagnosis': forms.TextInput(attrs={
                'placeholder': 'Retinopatía diabética',
                'title': "Un resumen aproximado del diagnóstico del caso"
            })
        }