# Generated by Django 4.2.16 on 2024-10-25 05:45

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('myapp', '0014_delete_gitleak'),
    ]

    operations = [
        migrations.CreateModel(
            name='GitHubScan',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('repository_url', models.URLField(max_length=255)),
                ('scan_results', models.JSONField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
        ),
        migrations.CreateModel(
            name='SecretScan',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('url', models.URLField(max_length=500)),
                ('secret_type', models.CharField(max_length=100)),
                ('secret_value', models.TextField()),
                ('scanned_at', models.DateTimeField(auto_now_add=True)),
            ],
        ),
    ]
