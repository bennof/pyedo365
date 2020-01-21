from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^(?P<provider>[^/]+)/',views.login_page),
    url(r'',views.login_page,name='login'),
    url(r'^cms/login', views.login_page, name='wagtailadmin_login'),
    url(r'^logout/$', views.login_page, name='wagtailadmin_logout'),
]