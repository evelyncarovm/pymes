from django.contrib import admin
from django.conf.urls import patterns, url, include
from django.views.generic import DetailView, ListView, TemplateView
from pymes.models import client, user
from pymes import views, admin, views1
from admin import loan_admin_site
from django.views.generic.edit import CreateView
from django.contrib.auth.forms import UserCreationForm

urlpatterns = patterns('',
    url(r'^register/$', views.register, name='register'),
    url(r'^login/$', views.user_login, name='login'),
    url(r'^logout/$', views.user_logout, name='logout'),
    url(r'^$',
        ListView.as_view(
            queryset=user.pk,
            context_object_name='latest_loantype_list',
            template_name='pymes/index.html'),
            name='index'),
    url(r'^loan_req/(?P<slug>\d+)/$', views1.loan_req, name='loan_req'),    
    url(r'^add_loan/$', views.add_loan, name='add_loan'),
    url(r'^loans/$', views.LoanList, name='loans'),
    url (r'^update/$', views.update, name='update'),
    url (r'^update/(?P<idloantype>\D+\d+\.\d+)/$', views.update, name='update'),
    url (r'^delete/(?P<idloantype>\D+\d+\.\d+)/$', views.delete, name='delete'),
    url (r'^detail_records/(?P<idclient>\d+)/$', views.detail_records, name='detail_records'),

    url (r'^client_records/$',views.ClientList, name='ClientList'),
    url(r'^client_details/$', views1.cliupdate, name='detail_records'),
)
