from django.shortcuts import render, render_to_response, get_object_or_404
from django.http import HttpResponseRedirect, HttpResponse   
from django.contrib import auth, admin
from django.contrib.auth import logout
from django.core.context_processors import csrf 
from django.core.urlresolvers import reverse
from django.template import RequestContext
from django.views.generic.list import ListView
from django.views.generic.edit import CreateView, UpdateView, DeleteView
from django.views.generic.detail import DetailView
from pymes.model_Backend import authenticate, load_user, check_session, delete_ltype, load_clients, load_cli_details, organize_records
from forms import UserForm, LoanForm, ClientForm
from pymes.models import client, user
from django.core.cache import cache
import sha, time


def register(request):
    context = RequestContext(request)
    registered = False
    
    # Valida si recibe un post
    if request.method == 'POST':
        # Attempt to grab information from the raw form information.
        user_form = UserForm(data=request.POST)

        # valida si el formulario esta correctamente diligenciado
        if user_form.is_valid(): 
            # Guarda info en la DB.
            user = user_form.save()

            #Se aplica hash al password y sse guarda en la DB
            #user.set_pass(user.password)
            user.save()
            registered = True
            return HttpResponseRedirect('/pymes/')

        #Imprime errores
        else:
            print user_form.errors,

    # Si no se recibe el post se carga el formulario de registro
    else:
        user_form = UserForm()
    
    #Vuelve a cargar la URL de register.html
    return render_to_response('pymes/register.html',
            {'user_form': user_form, 'registered': registered},
            context)    

def user_login(request):
    # Like before, obtain the context for the user's request.
    context = RequestContext(request)

    # If the request is a HTTP POST, try to pull out the relevant information.
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(username=username, password=password)
        
        if user:
            request.is_authenticated = True
            key = sha.new(str(time.time())).hexdigest()
            cache.set(key,user.pk())
            response = render_to_response('pymes/loans.html',{'data': cache.get(key),'is_authenticated': request.is_authenticated, 'user': user},context)
            response.set_cookie('sess_id', key)
            return response
        else:
            print "Invalid login details: {0}, {1}".format(username, password)
            return HttpResponse("Invalid login details supplied.")
    else:
        #key = request.COOKIES['sess_id']
        #dato = cache.get(key)
        user_id = check_session(request)
        if user_id != False:
            key = request.COOKIES['sess_id']
            cache.delete(key)
            request.is_authenticated = True
            key = sha.new(str(time.time())).hexdigest()
            user1 = load_user(user_id)
            user2 = user1
            cache.set(key,user2.pk())
            response = render_to_response('pymes/loans.html',{'data': user2.pk(),'is_authenticated': request.is_authenticated, 'user': user2},context)
            response.set_cookie('sess_id', key)
            return response
        else:
            return render_to_response('pymes/login.html', {}, context)

def user_logout(request):
    # Since we know the user is logged in, we can now just log them out.
    key = request.COOKIES['sess_id']
    dato = cache.get(key)
    if dato > 0:
        cache.delete(key)
    # Take the user back to the homepage.
    return HttpResponseRedirect('/pymes/')

def detail_records(request,idclient):
    # Like before, obtain the context for the user's request.
    context = RequestContext(request)
    user_id = check_session(request)
    if user_id != False:
        key = request.COOKIES['sess_id']
        cache.delete(key)
        request.is_authenticated = True
        key = sha.new(str(time.time())).hexdigest()
        user2 = load_user(user_id)
        cli = load_cli_details(idclient, user_id)
        recs = organize_records(cli.record)
        cache.set(key,user2.pk())
        response = render_to_response('pymes/detail_records.html',{'data': cli,'records': recs,'is_authenticated': request.is_authenticated, 'user': user2},context)
        response.set_cookie('sess_id', key)
        return response
    else:
        return render_to_response('pymes/login.html', {}, context)
    
def update(request, idloantype):
    # Get the context from the request.
    context = RequestContext(request)
    created = False
    user_id = check_session(request)
    if user_id != False:
        key = request.COOKIES['sess_id']
        cache.delete(key)
        request.is_authenticated = True
        key = sha.new(str(time.time())).hexdigest()
        cache.set(key,user_id)
        categ, rate = idloantype.split(":")
        data = {'category': categ, 'rate': rate}
        form = LoanForm(data)
        user1 = delete_ltype(user_id, idloantype)
        user1.save()    
        response = render_to_response('pymes/add_loan.html', {'form': form, 'created': created, 'data': key}, context)
        response.set_cookie('sess_id', key)
        return response
    else:
        return render_to_response('pymes/login.html', {'data': user_id}, context)

def delete(request, idloantype):
    context=RequestContext(request)
    #loan = 'LoanType.objects.get(idloantype=idloantype).delete()'
    #created = True
    user_id = check_session(request)
    if user_id != False:
        key = request.COOKIES['sess_id']
        cache.delete(key)
        request.is_authenticated = True
        key = sha.new(str(time.time())).hexdigest()
        cache.set(key,user_id)
        # Have we been provided with a valid form?
        user1 = delete_ltype(user_id, idloantype)
        user1.save()
        response = render_to_response('pymes/loans.html',{'is_authenticated': request.is_authenticated, 'user': user1},context)
        response.set_cookie('sess_id', key)
        return response
    else:
        return render_to_response('pymes/login.html', {'data': user_id}, context)

def add_loan(request):
    # Get the context from the request.
    context = RequestContext(request)
    created = False
    user_id = check_session(request)
    if user_id != False:
        key = request.COOKIES['sess_id']
        cache.delete(key)
        request.is_authenticated = True
        key = sha.new(str(time.time())).hexdigest()
        cache.set(key,user_id)
        form = LoanForm(request.POST or None)
        response = render_to_response('pymes/add_loan.html', {'form': form, 'created': created, 'data': key}, context)
        response.set_cookie('sess_id', key)
        # A HTTP POST?
        if request.method == 'POST':
            # Have we been provided with a valid form?
            if form.is_valid():
                user1 = form.save(user_id)
                user1.save()
                created = True
                response = render_to_response('pymes/loans.html',{'is_authenticated': request.is_authenticated, 'user': user1},context)
                response.set_cookie('sess_id', key)
                return response
            else:
                print form.errors
            # Now call the index() view.
            # The user will be shown the homepage.
            #return index(request)
        else:
        # Bad form (or form details), no form supplied...
        # Render the form with error messages (if any).
            return response
    else:
        return render_to_response('pymes/login.html', {'data': user_id}, context)
        

def loan_req(request, slug):
    loantype = get_object_or_404('LoanType', slug=slug)
    form = ClientForm(request.POST or None)
    if form.is_valid():
        client = form.save(commit=False)
        client.loanpurpose = loantype
        client.save()
        return redirect('pymes/')

    return render_to_response('pymes/',
                              {
                                  'form': form,
                              },
                              context)

def LoanList(request):
    key = request.COOKIES['sess_id']
    request.CACHE['cache_data']=cache.get(key)
    datos = cache.get('primera')
    return render_to_response('pymes/loans.html',
                          {
                              'user_num': datos.user_id,
			      'sess_guard': datos.session_id,
                          },
                          context)
    #return HttpResponseRedirect('/pymes/loans.html')
        
def ClientList(request):
    # Like before, obtain the context for the user's request.
    context = RequestContext(request)
    user_id = check_session(request)
    if user_id != False:
        key = request.COOKIES['sess_id']
        cache.delete(key)
        request.is_authenticated = True
        key = sha.new(str(time.time())).hexdigest()
        user2 = load_user(user_id)
        client_list = load_clients(user_id)
        cache.set(key,user2.pk())
        response = render_to_response('pymes/client_records.html',{'data': client_list,'is_authenticated': request.is_authenticated, 'user': user2},context)
        response.set_cookie('sess_id', key)
        return response
    else:
        return render_to_response('pymes/login.html', {}, context)

#class RecordList(ListView):
#    model = 'Record'
#    paginate_by = 50 
#    def get_queryset(self):
#        queryset = super(RecordList, self).get_queryset().filter(idclient_id=self.request.idclient)
#        return queryset
