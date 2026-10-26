# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""SZTO: device common_name and rfc_4122_uuid are unique PER DOMAIN, not globally.

This lets the same physical device (same IDevID) onboard into more than one
domain/tenant (change of ownership / resale). Reapplied on top of Trustpoint
v1.0.0 as part of the domain-scoped AOKI patch (OP-1).
"""

import uuid

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('devices', '0001_initial'),
    ]

    operations = [
        # Drop the global uniqueness on the two identity fields so they can
        # repeat across domains; per-domain uniqueness is enforced by the
        # UniqueConstraints added below.
        migrations.AlterField(
            model_name='devicemodel',
            name='common_name',
            field=models.CharField(default='', max_length=100, verbose_name='Device'),
        ),
        migrations.AlterField(
            model_name='devicemodel',
            name='rfc_4122_uuid',
            field=models.UUIDField(
                default=uuid.uuid4,
                editable=False,
                help_text=(
                    'RFC 4122 version 4 UUID uniquely identifying this device. '
                    'Auto-generated on device creation and immutable thereafter.'
                ),
                verbose_name='Device UUID',
            ),
        ),
        migrations.AddConstraint(
            model_name='devicemodel',
            constraint=models.UniqueConstraint(
                fields=('common_name', 'domain'),
                name='unique_device_common_name_per_domain',
            ),
        ),
        migrations.AddConstraint(
            model_name='devicemodel',
            constraint=models.UniqueConstraint(
                fields=('rfc_4122_uuid', 'domain'),
                name='unique_device_uuid_per_domain',
            ),
        ),
    ]
