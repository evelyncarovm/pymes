from django.contrib import admin
from pymes.models import LoanType, Client

class ClientInline(admin.TabularInline):
	model = Client
	extra = 1

class LoanTAdmin(admin.ModelAdmin):
    fieldsets = [
        ('Code Admin', {'fields': ['idadmin']}),
        ('Loan Type', {'fields': ['ltype']}),
        ('Rate', {'fields': ['rate']}),
    ]
    inlines = [ClientInline]
    list_display = ('idadmin', 'ltype', 'rate')

admin.site.register(LoanType, LoanTAdmin)