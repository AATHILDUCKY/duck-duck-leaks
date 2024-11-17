# Generated by Django 4.2.16 on 2024-10-23 10:27

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('myapp', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='DomainResult',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('domain', models.CharField(max_length=255)),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
            ],
        ),
        migrations.CreateModel(
            name='DecodedResult',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('encoded_str', models.TextField()),
                ('decoded_str', models.TextField()),
                ('domain_result', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='myapp.domainresult')),
            ],
        ),
    ]