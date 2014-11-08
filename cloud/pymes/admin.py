from django.contrib import admin
from django.contrib.admin.sites import AdminSite

#from pymes.models import LoanType, Client
from pymes.forms import LoanAdminAuthForm

admin.autodiscover()

#class ClientInline(admin.TabularInline):
#	model = Client
#	extra = 1

#class LoanTAdmin(admin.ModelAdmin):
#    fieldsets = [
#        ('Code Admin', {'fields': ['idadmin']}),
#        ('Loan Type', {'fields': ['ltype']}),
#        ('Rate', {'fields': ['rate']}),
#    ]
#    inlines = [ClientInline]
#    list_display = ('idadmin', 'ltype', 'rate')

class LoanAdmin(AdminSite):

    login_form = LoanAdminAuthForm

    def has_permission(self, request):
        return request.user.is_active

loan_admin_site = LoanAdmin(name='loansadmin')
