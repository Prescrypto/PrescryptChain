# -*- coding: utf-8 -*-
from __future__ import unicode_literals

# REST
from rest_framework.viewsets import ViewSetMixin
from rest_framework import routers, serializers, viewsets
from rest_framework.authentication import SessionAuthentication, BasicAuthentication, TokenAuthentication
from rest_framework.permissions import IsAuthenticated, BasePermission
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.views import APIView
from rest_framework import mixins, generics
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
# our models
from blockchain.models import Block, Prescription, Medication

# Define router
router = routers.DefaultRouter()


class MedicationNestedSerializer(serializers.ModelSerializer):
    """ Medication Nested in Prescription """
    class Meta:
        model = Medication
        fields = ('id', 'presentation', 'instructions', 'drug_upc',)
        read_only_fields = ('id',)
        extra_kwargs = {
            'presentation': { 'required': 'False', 'min_length': 4},
            'instructions': { 'required': 'False', 'min_length': 4}
        }

class PrescriptionSerializer(serializers.ModelSerializer):
    """ Prescription serializer """
    medications = MedicationNestedSerializer(
        many=True, required=False,
        help_text = "Medication Nested Serializer"
    )
    timestamp = serializers.DateTimeField(read_only=False)

    class Meta:
        model = Prescription
        fields = (
            'id',
            'public_key',
            'medic_name',
            'medic_cedula',
            'medic_hospital',
            'patient_name',
            'patient_age',
            'diagnosis',
            'medications',
            'location',
            'timestamp',
            'signature',
            'previous_hash',
            'raw_size',
            'rxid',
            'is_valid',
            'block',
        )
        read_only_fields = ('id', 'rxid', 'previous_hash', 'is_valid', 'block')

    def create(self, validated_data):
        rx = Prescription.objects.create_rx(data=validated_data)
        return rx


class PrescriptionViewSet(viewsets.ModelViewSet):
    """ Prescription Viewset """
    # Temporally without auth
    # authentication_classes = (TokenAuthentication, BasicAuthentication, )
    # permission_classes = (IsAuthenticated, )
    serializer_class = PrescriptionSerializer

    def get_queryset(self):
        return Prescription.objects.all().order_by('-id')


# add patient filter by email, after could modify with other
router.register(r'rx-endpoint', PrescriptionViewSet, 'prescription-endpoint')


class BlockSerializer(serializers.ModelSerializer):
    """ Prescription serializer """
    class Meta:
        model = Block
        fields = (
            'id',
            'hash_block',
            'previous_hash',
            'raw_size',
            'data',
            'timestamp',
            'merkleroot',
            'hashcash',
            'nonce',
        )
        read_only_fields = ('id', 'hash_block','timestamp','previous_hash', 'raw_size', 'data', 'merkleroot','hashcash','nonce',)


class BlockViewSet(viewsets.ModelViewSet):
    """ Prescription Viewset """
    serializer_class = BlockSerializer

    def get_queryset(self):
        return Block.objects.all().order_by('-timestamp')


# add patient filter by email, after could modify with other
router.register(r'block', BlockViewSet, 'block-endpoint')
