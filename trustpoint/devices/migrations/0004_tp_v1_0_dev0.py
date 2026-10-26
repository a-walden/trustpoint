# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

import uuid
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('devices', '0003_tp_v0_6_0'),
        ('onboarding', '0003_tp_v1_0_dev0'),
        ('pki', '0003_tp_v1_0_dev0'),
    ]

    operations = [
        migrations.AlterField(
            model_name='devicemodel',
            name='common_name',
            field=models.CharField(default='', max_length=100, verbose_name='Device'),
        ),
        migrations.AlterField(
            model_name='devicemodel',
            name='rfc_4122_uuid',
            field=models.UUIDField(default=uuid.uuid4, editable=False, help_text='RFC 4122 version 4 UUID uniquely identifying this device. Auto-generated on device creation and immutable thereafter.', verbose_name='Device UUID'),
        ),
        migrations.AddConstraint(
            model_name='devicemodel',
            constraint=models.UniqueConstraint(fields=('common_name', 'domain'), name='unique_device_common_name_per_domain'),
        ),
        migrations.AddConstraint(
            model_name='devicemodel',
            constraint=models.UniqueConstraint(fields=('rfc_4122_uuid', 'domain'), name='unique_device_uuid_per_domain'),
        ),
    ]
