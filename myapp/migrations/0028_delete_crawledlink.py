# Generated by Django 4.2.16 on 2024-10-29 15:53

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('myapp', '0027_crawledlink_delete_alllinkscrap'),
    ]

    operations = [
        migrations.DeleteModel(
            name='CrawledLink',
        ),
    ]