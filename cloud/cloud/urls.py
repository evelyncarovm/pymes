from django.conf.urls import patterns, include, url

from django.contrib import admin
admin.autodiscover()

urlpatterns = patterns('',
    # Examples:
    # url(r'^$', 'cloud.views.home', name='home'),
    # url(r'^blog/', include('blog.urls')),
    url(r'^pymes/', include('pymes.urls', namespace="pymes")),
    #url(r'^simu/', include(admin.site.urls)),
    url(r'^admin/', include(admin.site.urls)),
)
