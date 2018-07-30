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
    verify_signature, PoE
)
from .helpers import genesis_hash_generator, GENESIS_INIT_DATA, get_genesis_merkle_root
from api.exceptions import EmptyMedication, FailedVerifiedSignature


# Setting block size
BLOCK_SIZE = settings.BLOCK_SIZE
logger = logging.getLogger('django_info')

# =====================================================================
# =============================BLOCKS==================================
# =====================================================================

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
            new_block.poetxid = txid
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
        size = (len(self.get_previous_hash)+len(self.hash_block)+ len(self.get_formatted_date())) * 8
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
    def get_previous_hash(self):
        ''' Get before hash block '''
        return self.previous_hash

    def __str__(self):
        return self.hash_block

# =====================================================================
# =============================TRANSACTION=============================
# =====================================================================

class TransactionQueryset(models.QuerySet):
    ''' Add custom querysets'''

    def non_validated_txs(self):
        return self.filter(is_valid=True).filter(block=None)


class TransactionManager(models.Manager):
    ''' Manager for prescriptions '''

    def get_queryset(self):
        return TransactionQueryset(self.model, using=self._db)

    def non_validated_txs(self):
        return self.get_queryset().non_validated_txs()

    def create_block_attempt(self): # This is where PoW happens
        ''' Use PoW hashcash algoritm to attempt to create a block '''
        _hashcash_tools = Hashcash(debug=settings.DEBUG)
        if not cache.get('challenge') and not cache.get('counter') == 0:
            challenge = _hashcash_tools.create_challenge(word_initial=settings.HC_WORD_INITIAL)
            safe_set_cache('challenge', challenge)
            safe_set_cache('counter', 0)

        is_valid_hashcash, hashcash_string = _hashcash_tools.calculate_sha(cache.get('challenge'), cache.get('counter'))

        if is_valid_hashcash:
            block = Block.objects.create_block(self.non_validated_txs()) # TODO add on creation hash and merkle
            block.hashcash = hashcash_string
            block.nonce = cache.get('counter')
            block.save()
            safe_set_cache('challenge', None)
            safe_set_cache('counter', None)

        else:
            counter = cache.get('counter') + 1
            safe_set_cache('counter', counter)


    def create_tx(self, data, **kwargs):
        ''' Custom method for create Tx with rx item '''

        ''' Get initial data '''
        _signature = data.pop("signature", None)
        raw_pub_key = data.get("public_key", "")
        pub_key = un_savify_key(raw_pub_key) # Make it usable

        ''' FIRST Create the Transaction '''
        tx = self.create_raw_tx(data, _signature=_signature, pub_key=pub_key)

        ''' THEN Create the Data Item(prescription) '''
        rx = Prescription.objects.create_rx(
            data,
            _signature=_signature,
            pub_key=pub_key,
            raw_pub_key=raw_pub_key,
            transaction=tx
        )

        # Assing rx to TX
        tx.rx = rx
        tx.save()

        # This is necessary until medications will be json instead of a model
        if "medications" in data and len(data["medications"]) != 0:
            for med in data["medications"]:
                Medication.objects.create_medication(prescription=rx, **med)

        ''' LAST do create block attempt '''
        self.create_block_attempt()


        # Return the transaction object
        return tx

    def create_raw_tx(self, data, **kwargs):
        ''' This method just create the transaction instance '''

        ''' START TX creation '''
        # This calls the super method saving all clean data first
        tx = Transaction()
        # Get Public Key from API
        pub_key = kwargs.get("pub_key", None) # Make it usable
        _signature = kwargs.get("_signature", None)

        # Save signature and timestamp
        tx.signature = _signature
        tx.timestamp = timezone.now()

        # Check later ======>>
        # tx.sender = bin2hex(encrypt_with_public_key(data["medic_name"].encode("utf-8"), pub_key))
        # tx.receiver = bin2hex(encrypt_with_public_key(data["medic_cedula"].encode("utf-8"), pub_key))
        # This is basically the address
        # tx.public_key = raw_pub_key

        # Transactional validation
        if verify_signature(json.dumps(sorted(data)), _signature, pub_key):
            tx.is_valid = True
        else:
            tx.is_valid = False

        # Set previous hash
        if self.last() is None:
            tx.previous_hash = "0"
        else:
            tx.previous_hash = self.last().txid

        # Create raw data to generate hash and save it
        tx.create_raw_msg()
        tx.hash()
        tx.save()

        ''' RETURN TX '''
        return tx

# Simplified Tx Model
@python_2_unicode_compatible
class Transaction(models.Model):
    # Cryptographically enabled fields
    # Necessary infomation
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)
    raw_msg = models.TextField(blank=True, default="") # Anything can be stored here
    # block information
    block = models.ForeignKey('blockchain.Block', related_name='transactions', null=True, blank=True)
    signature = models.TextField(blank=True, default="")
    is_valid = models.BooleanField(default=False, blank=True)
    txid = models.TextField(blank=True, default="")
    previous_hash = models.TextField(blank=True, default="")
    # Details
    details = JSONField(default={}, blank=True)

    objects = TransactionManager()

    # Hashes msg_html with utf-8 encoding, saves this in and hash in _signature
    def hash(self):
        hash_object = hashlib.sha256(self.raw_msg)
        self.txid = hash_object.hexdigest()


    @property
    def get_pub_key_receiver(self):
        ''' Get public key of receiver on Pem string '''
        _public_key = un_savify_key(self.public_key_receiver)
        return _public_key.save_pkcs1(format="PEM")

    def create_raw_msg(self):
        # Create raw html and encode
        msg = (
            self.timestamp.isoformat() +
            self.signature +
            str(self.is_valid) +
            self.previous_hash
        )
        self.raw_msg = msg.encode('utf-8')

    def get_formatted_date(self, format_time='d/m/Y'):
        # Correct date and format
        localised_date = self.timestamp
        if not settings.DEBUG:
            # Remember to change the time each time change
            localised_date = localised_date - timedelta(hours=6)

        return DateFormat(localised_date).format(format_time)

    @cached_property
    def get_delta_datetime(self):
        ''' Fix 6 hours timedelta on tx '''
        return self.timestamp - timedelta(hours=6)

    # THIS NEEDS TO be update to account for Prescriptions
    @cached_property
    def raw_size(self):
        # get the size of the raw tx
        size = (
            len(self.signature)+
            len(str(self.get_formatted_date()))
        )
        return size * 8

    @cached_property
    def get_previous_hash(self):
        ''' Get before hash transaction '''
        return self.previous_hash


    def __str__(self):
        return self.txid



# =====================================================================
# =============================PRESCRIPTION============================
# =====================================================================
class PrescriptionQueryset(models.QuerySet):
    ''' Add custom querysets '''
    def non_validated_rxs(self):
        return self.filter(is_valid=True).filter(block=None)

class PrescriptionManager(models.Manager):
    ''' Manager for prescriptions '''

    def get_queryset(self):
        return PrescriptionQueryset(self.model, using=self._db)

    def create_rx(self, data, **kwargs):
        ''' Custom Create Rx manager '''

        ''' START RX creation '''
        rx = Prescription(
            medic_name=data.get("medic_name", ""),
            medic_cedula=data.get("medic_cedula", ""),
            medic_hospital=data.get("medic_cedula", ""),
            patient_name=data.get("patient_name", ""),
            patient_age=data.get("patient_age", ""),
            diagnosis=data.get("diagnosis", ""),
            timestamp=data.get("timestamp", None),
            public_key=kwargs.get("raw_pub_key", ""),
            signature=kwargs.get("_signature", ""),
            transaction=kwargs.get("transaction", None)
        )
        if "location" in data:
            rx.location = data["location"]

        if verify_signature(json.dumps(sorted(data)), rx.signature, kwargs.get("pub_key", None)):
            rx.is_valid = True
        else:
            rx.is_valid = False

        # Save previous hash
        if self.last() is None:
            rx.previous_hash = "0"
        else:
            rx.previous_hash = self.last().rxid

        # Generate raw msg, create hash and save it
        rx.create_raw_msg()
        rx.hash()
        rx.save()

        ''' Return RX object'''
        return rx


# Simplified Rx Model
@python_2_unicode_compatible
class Prescription(models.Model):
    # MAIN
    transaction = models.ForeignKey('blockchain.Transaction', related_name='prescriptions', null=True, blank=True)
    readable = models.BooleanField(default=False, blank=True) # Filter against this when
    # Cryptographically enabled fields
    public_key = models.TextField(blank=True, default="")
    ### Encrypted data payload
    ## Patient and Medic data (encrypted data payload)
    # Note to self, I think that this could be a JSON field with a non fixed structure
    medic_name = models.TextField(blank=True, default="")
    medic_cedula = models.TextField(blank=True, default="")
    medic_hospital = models.TextField(blank=True, default="")
    patient_name = models.TextField(blank=True, default="")
    patient_age = models.TextField(blank=True, default="")
    diagnosis = models.TextField(default="")
    encrypted_data = JSONField(default={}, blank=True)
    ## Non encrypted data payload
    ## Public fields (non encrypted data payload)
    # Misc
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)
    location = models.TextField(blank=True, default="")
    raw_msg = models.TextField(blank=True, default="") # Anything can be stored here
    location_lat = models.FloatField(null=True, blank=True, default=0) # For coordinates
    location_lon = models.FloatField(null=True, blank=True, default=0)
    public_data = JSONField(default={}, blank=True)
    # Rx Specific
    details = models.TextField(blank=True, default="")
    extras = models.TextField(blank=True, default="")
    bought = models.BooleanField(default=False)
    # Transactional validation
    signature = models.TextField(null=True, blank=True, default="")
    is_valid = models.BooleanField(default=True, blank=True)
    rxid = models.TextField(blank=True, default="")
    previous_hash = models.TextField(default="") # this should not exist

    # Business logic
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
    def get_pub_key(self):
        ''' Get public key on Pem string '''
        _public_key = un_savify_key(self.public_key)
        return _public_key.save_pkcs1(format="PEM")

    def create_raw_msg(self):
        # Create raw html and encode
        msg = (
            self.medic_name +
            self.medic_cedula +
            self.medic_hospital +
            self.patient_name +
            self.patient_age +
            self.diagnosis
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
    def get_previous_hash(self):
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
    presentation = models.CharField(
        blank=True, max_length=255,
    )
    instructions = models.TextField(blank=True, default="")
    frequency = models.CharField(blank=True, max_length=255, default="")
    dose = models.CharField(blank=True, max_length=255, default="")
    bought = models.BooleanField(default=False)
    drug_upc = models.CharField(blank=True, max_length=255, default="", db_index=True)

    objects = MedicationManager()

    def __str__(self):
        return self.presentation
