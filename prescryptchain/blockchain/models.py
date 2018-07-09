# -*- encoding: utf-8 -*-
# Python Libs
## Hash lib
import hashlib
import base64
import merkletools
import json
import logging
# Date
from datetime import timedelta, datetime
from operator import itemgetter
# Unicode shite
import unicodedata
# Django Libs
from django.db import models
from django.conf import settings
from django.contrib.postgres.fields import JSONField
from django.utils.encoding import python_2_unicode_compatible
from django.utils import timezone
from django.utils.functional import cached_property
from django.utils.dateformat import DateFormat
from django.core.cache import cache

# Our methods
from core.helpers import safe_set_cache
from core.utils import Hashcash
from .utils import (
    un_savify_key, savify_key,
    encrypt_with_public_key, decrypt_with_private_key,
    calculate_hash, bin2hex, hex2bin,  get_new_asym_keys, get_merkle_root,
    verify_signature, PoE, pubkey_string_to_rsa, pubkey_base64_to_rsa
)
from .helpers import genesis_hash_generator, GENESIS_INIT_DATA, get_genesis_merkle_root
from api.exceptions import EmptyMedication, FailedVerifiedSignature


# Setting block size
BLOCK_SIZE = settings.BLOCK_SIZE
logger = logging.getLogger('django_info')


class BlockManager(models.Manager):
    ''' Model Manager for Blocks '''

    def create_block(self, rx_queryset):
        # Do initial block or create next block
        last_block = Block.objects.last()
        if last_block is None:
            genesis = self.get_genesis_block()
            return self.generate_next_block(genesis.hash_block, rx_queryset)

        else:
            return self.generate_next_block(last_block.hash_block, rx_queryset)

    def get_genesis_block(self):
        # Get the genesis arbitrary block of the blockchain only once in life
        genesis_block = Block.objects.create(
            hash_block=genesis_hash_generator(),
            data=GENESIS_INIT_DATA,
            merkleroot=get_genesis_merkle_root())
        genesis_block.hash_before = "0"
        genesis_block.save()
        return genesis_block

    def generate_next_block(self, hash_before, rx_queryset):
        # Generete a new block

        new_block = self.create(previous_hash=hash_before)
        new_block.save()
        data_block = new_block.get_block_data(rx_queryset)
        new_block.hash_block = calculate_hash(new_block.id, hash_before, str(new_block.timestamp), data_block["sum_hashes"])
        # Add Merkle Root
        new_block.merkleroot = data_block["merkleroot"]
        # Proof of Existennce layer
        try:
            _poe = PoE() # init proof of existence element
            txid = _poe.journal(new_block.merkleroot)
            if txid is not None:
                new_block.poetxid = txid
            else:
                new_block.poetxid = ""
        except Exception as e:
            logger.error("[PoE generate Block Error]: {}, type:{}".format(e, type(e)))

        # Save
        new_block.save()

        return new_block


@python_2_unicode_compatible
class Block(models.Model):
    ''' Our Model for Blocks '''
    # Id block
    hash_block = models.CharField(max_length=255, blank=True, default="")
    previous_hash = models.CharField(max_length=255, blank=True, default="")
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    data = JSONField(default={}, blank=True)
    merkleroot = models.CharField(max_length=255, default="")
    poetxid = models.CharField(max_length=255, default="", blank=True)
    nonce = models.CharField(max_length=50, default="", blank=True)
    hashcash = models.CharField(max_length=255, default="", blank=True)

    objects = BlockManager()

    @cached_property
    def raw_size(self):
        # get the size of the raw html
        size = (len(self.get_before_hash)+len(self.hash_block)+ len(self.get_formatted_date())) * 8
        return size

    def get_block_data(self, rx_queryset):
        # Get the sum of hashes of last prescriptions in block size
        sum_hashes = ""
        try:
            self.data["hashes"] = []
            for rx in rx_queryset:
                sum_hashes += rx.rxid
                self.data["hashes"].append(rx.rxid)
                rx.block = self
                rx.save()
            merkleroot = get_merkle_root(rx_queryset)
            return {"sum_hashes": sum_hashes, "merkleroot": merkleroot}

        except Exception as e:
            logger.error("[BLOCK ERROR] get block data error : %s" % e)
            return ""


    def get_formatted_date(self, format_time='d/m/Y'):
        # Correct date and format
        localised_date = self.timestamp
        if not settings.DEBUG:
            localised_date = localised_date - timedelta(hours=6)
        return DateFormat(localised_date).format(format_time)

    @cached_property
    def get_before_hash(self):
        ''' Get before hash block '''
        return self.previous_hash

    def __str__(self):
        return self.hash_block


class PrescriptionQueryset(models.QuerySet):
    ''' Add custom querysets'''

    def non_validated_rxs(self):
        return self.filter(is_valid=False).filter(block=None)

    def validated_rxs(self):
        return self.filter(is_valid=True).filter(block=None)

    def has_not_block(self):
        return self.filter(block=None)



class PrescriptionManager(models.Manager):
    ''' Manager for prescriptions '''

    def get_queryset(self):
        return PrescriptionQueryset(self.model, using=self._db)

    def non_validated_rxs(self):
        return self.get_queryset().non_validated_rxs()

    def validated_rxs(self):
        return self.get_queryset().validated_rxs()

    def has_not_block(self):
        return self.get_queryset().has_not_block()

    def create_block_attempt(self):
        ''' Use PoW hashcash algoritm to attempt to create a block '''
        _hashcash_tools = Hashcash(debug=True)
        if not cache.get('challenge') and not cache.get('counter') == 0:
            challenge = _hashcash_tools.create_challenge(word_initial=settings.HC_WORD_INITIAL)
            safe_set_cache('challenge', challenge)
            safe_set_cache('counter', 0)

        is_valid_hashcash, hashcash_string = _hashcash_tools.calculate_sha(cache.get('challenge'), cache.get('counter'))

        if is_valid_hashcash:
            block = Block.objects.create_block(self.has_not_block())
            block.hashcash = hashcash_string
            block.nonce = cache.get('counter')
            block.save()
            safe_set_cache('challenge', None)
            safe_set_cache('counter', None)

        else:
            counter = cache.get('counter') + 1
            safe_set_cache('counter', counter)


    def create_rx(self, data, **kwargs):

        rx = self.create_raw_rx(data)

        if "medications" in data and len(data["medications"]) != 0:
            for med in data["medications"]:
                Medication.objects.create_medication(prescription=rx, **med)

        return rx

    def create_raw_rx(self, data, **kwargs):
        # This calls the super method saving all clean data first
        rx = Prescription()
        # Get Public Key from API
        raw_pub_key = data.get("public_key")

        try:
            pub_key = pubkey_string_to_rsa(raw_pub_key) # Make it usable
        except Exception as e:
            # Attempt to create public key with base64
            pub_key, raw_pub_key = pubkey_base64_to_rsa(raw_pub_key)

        hex_raw_pub_key = savify_key(pub_key)

        # Extract signature
        _signature = data.pop("signature", None)

        # This is basically the address
        rx.public_key = hex_raw_pub_key

        if "data" in data:
            rx.data = data["data"]

        if "location" in data:
            rx.location = data["location"]

        rx.timestamp = data["timestamp"]

        # Save signature
        rx.signature = _signature

        # Clean data to verify signature
        _msg = json.dumps(rx.data, separators=(',',':'))

        if verify_signature(_msg, _signature, pub_key):
            rx.is_valid = True
        else:
            rx.is_valid = False

        # Save previous hash
        if self.last() is None:
            rx.previous_hash = "0"
        else:
            rx.previous_hash = self.last().rxid

        rx.create_raw_msg()
        rx.hash()

        rx.save()
        # SUCCESS creation of TX
        # Attempt creation of block
        self.create_block_attempt()

        return rx


# Simplified Rx Model
@python_2_unicode_compatible
class Prescription(models.Model):
    # Cryptographically enabled fields
    public_key = models.TextField(blank=True, default="")
    private_key = models.TextField(blank=True, default="") # Aquí puedes guardar el PrivateKey para desencriptar
    ### Patient and Medic data (encrypted)
    medic_name = models.TextField(blank=True, default="")
    medic_cedula = models.TextField(blank=True, default="")
    medic_hospital = models.TextField(blank=True, default="")
    patient_name = models.TextField(blank=True, default="")
    patient_age = models.TextField(blank=True, default="")
    diagnosis = models.TextField(default="")
    ### Public fields (not encrypted)
    # Misc
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)
    location = models.TextField(blank=True, default="")
    raw_msg = models.TextField(blank=True, default="") # Anything can be stored here
    location_lat = models.FloatField(null=True, blank=True, default=0) # For coordinates
    location_lon = models.FloatField(null=True, blank=True, default=0)
    # Rx Specific
    details = models.TextField(blank=True, default="")
    extras = models.TextField(blank=True, default="")
    bought = models.BooleanField(default=False)
    # Main
    block = models.ForeignKey('blockchain.Block', related_name='block', null=True, blank=True)
    signature = models.TextField(null=True, blank=True, default="")
    is_valid = models.BooleanField(default=True, blank=True)
    rxid = models.TextField(blank=True, default="")
    previous_hash = models.TextField(blank=True, default="")

    data = JSONField(default={}, blank=True)

    objects = PrescriptionManager()

    # Hashes msg_html with utf-8 encoding, saves this in and hash in _signature
    def hash(self):
        hash_object = hashlib.sha256(self.raw_msg)
        self.rxid = hash_object.hexdigest()

    @cached_property
    def get_data_base64(self):
        # Return data of prescription on base64
        return {
            "medic_name" : base64.b64encode(hex2bin(self.medic_name)),
            "medic_cedula" : base64.b64encode(hex2bin(self.medic_cedula)),
            "medic_hospital" : base64.b64encode(hex2bin(self.medic_hospital)),
            "patient_name" : base64.b64encode(hex2bin(self.patient_name)),
            "patient_age" : base64.b64encode(hex2bin(self.patient_age)),
            "diagnosis" : base64.b64encode(hex2bin(self.diagnosis))
        }

    @property
    def get_priv_key(self):
        ''' Get private key on Pem string '''
        _key = un_savify_key(self.private_key)
        return _key.save_pkcs1(format="PEM")

    @property
    def get_pub_key(self):
        ''' Get public key on Pem string '''
        _public_key = un_savify_key(self.public_key)
        return _public_key.save_pkcs1(format="PEM")

    def create_raw_msg(self):
        # Create raw html and encode
        msg = (
            json.dumps(self.data) +
            timezone.now().isoformat() +
            self.previous_hash
        )
        self.raw_msg = msg.encode('utf-8')


    def get_formatted_date(self, format_time='d/m/Y'):
        # Correct date and format
        localised_date = self.timestamp
        if not settings.DEBUG:
            localised_date = localised_date - timedelta(hours=6)

        return DateFormat(localised_date).format(format_time)

    @cached_property
    def get_delta_datetime(self):
        ''' Fix 6 hours timedelta on rx '''
        return self.timestamp - timedelta(hours=6)

    @cached_property
    def raw_size(self):
        # get the size of the raw rx
        size = (
            len(self.raw_msg) + len(self.diagnosis) +
            len(self.location) + len(self.rxid) +
            len(self.medic_name) + len(self.medic_cedula) +
            len(self.medic_hospital) + len(self.patient_name) +
            len(self.patient_age) + len(str(self.get_formatted_date()))
        )
        if self.medications.all() is not None:
            for med in self.medications.all():
                size += len(med.presentation) +len(med.instructions)
        return size * 8

    @cached_property
    def get_before_hash(self):
        ''' Get before hash prescription '''
        return self.previous_hash


    def __str__(self):
        return self.rxid


class MedicationManager(models.Manager):
    ''' Manager to create Medication from API '''
    def create_medication(self, prescription, **kwargs):
        med = self.create(prescription=prescription, **kwargs)
        med.save()
        return med


@python_2_unicode_compatible
class Medication(models.Model):
    prescription = models.ForeignKey('blockchain.Prescription',
        related_name='medications'
        )
    active = models.CharField(blank=True, max_length=255, default="")
    presentation = models.TextField(
        blank=True
    )
    instructions = models.TextField(blank=True, default="")
    frequency = models.CharField(blank=True, max_length=255, default="")
    dose = models.CharField(blank=True, max_length=255, default="")
    bought = models.BooleanField(default=False)
    drug_upc = models.CharField(blank=True, max_length=255, default="", db_index=True)

    objects = MedicationManager()

    def __str__(self):
        return self.presentation
