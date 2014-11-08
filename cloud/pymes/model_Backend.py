from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from pymes.models import user, client
from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.middleware.csrf import rotate_token
from django.core.cache import cache
import sha, time


SESSION_KEY = '_auth_user_id'
BACKEND_SESSION_KEY = '_auth_user_backend'
REDIRECT_FIELD_NAME = 'next'

def authenticate(username, password):
    UserModel = get_user_model()
    if username is None or password is None:
        return False
    try:
        user1 = user()
        user1.get_user(username)
        if user1.check_password(password):
            user2 = user1.get_user_all(user1.pk())
            return user2
    except UserModel.DoesNotExist:
        # Run the default password hasher once to reduce the timing
        # difference between an existing and a non-existing user (#20760).
        return False

def load_user(us_id):
    user1 = user()
    user2 = user1.get_user_all(us_id)
    return user2

def check_session(request):
    try:
        key = request.COOKIES['sess_id']
    except Exception, e:
        return False
    dato = cache.get(key)
    if dato > 0:
        return dato
    else:
        return False

def delete_ltype(us_id, ltype):
    user1 = user()
    user2 = user1.get_user_all(us_id)
    user2.loantype.remove(ltype)
    return user2

def get_cats(us_id):
    user1 = user()
    user2 = user1.get_user_all(us_id)
    i = 1
    cat_choices = []
    for l in user2.loantype:
        a = (i,l.split(":")[0])
        cat_choices.append(a)
        i += 1
    return cat_choices

def get_rates(us_id):
    user1 = user()
    user2 = user1.get_user_all(us_id)
    i = 1
    rate_dict = {}
    for l in user2.loantype:
        a = l.split(":")[1]
        rate_dict[i] = a 
        i += 1
    return rate_dict

def id_cats(us_id):
    user1 = user()
    user2 = user1.get_user_all(us_id)
    i = 1
    cat_dict = {}
    for l in user2.loantype:
        a = l.split(":")[0]
        cat_dict[i] = a 
        i += 1
    return cat_dict

def load_clients(us_id):
    cli1 = client()
    info = cli1.get_clients(us_id)
    return info

def load_cli_details(cli_id, us_id):
    cli1 = client()
    info = cli1.get_client_all(cli_id)
    if info.idadmin == us_id:
        return info
    else:
        return False

def organize_records(data):
    organized = []
    for d in data:
        organized.append(d.split(";"))
    return organized

def load_cli_info(cli_id):
    cli1 = client()
    info = cli1.get_client_all(cli_id)
    return info