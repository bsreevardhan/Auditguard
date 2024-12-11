from django.contrib import admin
from .models import UserSystemConfig,AuditResult,GroupList

# Register your models here.
admin.site.register(UserSystemConfig)
admin.site.register(AuditResult)