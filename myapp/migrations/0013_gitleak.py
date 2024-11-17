# Generated by Django 4.2.16 on 2024-10-24 15:57

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('myapp', '0012_directoryenumeration'),
    ]

    operations = [
        migrations.CreateModel(
            name='GitLeak',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('repo_url', models.URLField()),
                ('leak_type', models.CharField(max_length=255)),
                ('leak_value', models.TextField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
        ),
    ]
