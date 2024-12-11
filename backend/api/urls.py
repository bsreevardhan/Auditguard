from django.urls import path
from . import views

urlpatterns = [
    path('os_get/',views.get_os_system),
    path('run_script/',views.run_script),
    path('get_policies/',views.get_policy),
    path('get_specific_policy/',views.get_specific_policy),
    path('create-group/', views.create_group, name='create-group'),
    path('audit_results/',views.get_audit_results,name="audit-results"),
    
]



