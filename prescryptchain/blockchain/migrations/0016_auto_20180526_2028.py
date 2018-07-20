# -*- coding: utf-8 -*-
# Generated by Django 1.11.11 on 2018-05-27 01:28
from __future__ import unicode_literals

import django.contrib.postgres.fields.jsonb
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('blockchain', '0015_auto_20180328_1704'),
    ]

    operations = [
        migrations.CreateModel(
            name='Transaction',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('timestamp', models.DateTimeField(db_index=True, default=django.utils.timezone.now)),
                ('raw_msg', models.TextField(blank=True, default=b'')),
                ('signature', models.CharField(blank=True, default=b'', max_length=255, null=True)),
                ('is_valid', models.BooleanField(default=True)),
                ('txid', models.CharField(blank=True, default=b'', max_length=255)),
                ('previous_hash', models.CharField(default=b'', max_length=255)),
                ('details', django.contrib.postgres.fields.jsonb.JSONField(blank=True, default={})),
                ('block', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='block', to='blockchain.Block')),
            ],
        ),
        migrations.RemoveField(
            model_name='prescription',
            name='block',
        ),
        migrations.RemoveField(
            model_name='prescription',
            name='private_key',
        ),
        migrations.AddField(
            model_name='prescription',
            name='encrypted_data',
            field=django.contrib.postgres.fields.jsonb.JSONField(blank=True, default={}),
        ),
        migrations.AddField(
            model_name='prescription',
            name='public_data',
            field=django.contrib.postgres.fields.jsonb.JSONField(blank=True, default={}),
        ),
        migrations.AddField(
            model_name='prescription',
            name='readable',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='prescription',
            name='transaction',
            field=models.ManyToManyField(blank=True, null=True, related_name='transaction', to='blockchain.Transaction'),
        ),
    ]
