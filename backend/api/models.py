from django.db import models
from django.db.models.signals import pre_save

class UserSystemConfig(models.Model):
    os_name = models.CharField(
        max_length=255,
        help_text="Full OS name (e.g., 'Microsoft Windows 11 Home' or 'Ubuntu 22.04 LTS')"
    )
    os_version = models.CharField(
        max_length=255,
        help_text="OS version or kernel version"
    )
    os_config = models.CharField(
        max_length=100,
        help_text="System configuration (e.g., 'Standalone Workstation', 'Server', 'Desktop')"
    )
    architecture = models.CharField(
        max_length=20,
        choices=[('x86', 'x86'), ('x64', 'x64'), ('ARM', 'ARM')],
        help_text="System architecture"
    )
    hostname = models.CharField(
        max_length=255,
        help_text="System hostname"
    )
    ip_address = models.GenericIPAddressField(
        null=True,
        blank=True,
        help_text="System IP address"
    )
    os_index = models.IntegerField(default=-1)
    audit_results_path = models.CharField(
        max_length=255,
    )
    last_updated = models.DateTimeField(
        auto_now=True,
        help_text="Path where audit results are stored"
    )

    class Meta:
        verbose_name = "System Configuration"
        verbose_name_plural = "System Configurations"

    def __str__(self):
        return f"{self.hostname} - {self.os_name} ({self.os_config})"


class AuditResult(models.Model):
    csv_file_location = models.CharField(max_length=255,null=True,blank=True)
    pdf_file_location = models.CharField(max_length=255,null=True,blank=True)
    level = models.CharField(max_length=10,null=True,blank=True)
    pass_policy_count = models.IntegerField()
    fail_policy_count = models.IntegerField()
    compliance_percentage = models.FloatField()
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "audit_result"
        ordering = ["-timestamp"]
    
    def __str__(self) -> str:
        return f"{str(self.id)} - {str(self.timestamp)}"

class GroupList(models.Model):
    group_name = models.CharField(max_length=50,unique=True,null=False,blank=False,db_index=True)
    level = models.CharField(max_length=10,choices=(("L1","L1"),("L2","L2"),("BL","BL"),("Custom","Custom")),null=False,blank=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.group_name
    
    class Meta:
        unique_together = ('group_name','level')

class GroupPolicy(models.Model):
    group = models.ForeignKey(GroupList, on_delete=models.CASCADE,db_index=True)
    policy_id = models.IntegerField(null=False,blank=False)

    class Meta:
        unique_together = ('group_id','policy_id')
    

    

    