from dynamodb_mapper.model import DynamoDBModel, _dynamodb_to_python
from django.db import models
from django.contrib.auth.hashers import make_password, check_password
from boto.dynamodb2.table import Table
from django.utils.crypto import salted_hmac
from django.forms.models import model_to_dict

class user(DynamoDBModel):
    __table__ = u"user"
    __hash_key__ = u"UserID"
    __schema__ = {
        u"UserID": int,
        u"username": unicode,
        u"password": unicode,
        u"firstname": unicode,
        u"lastname": unicode,
        u"email": unicode,
        u"loantype": set,
        }
    def __unicode__(self):
    	return self.username

    def pk(self):
    	return self.UserID

    def get_user(self, raw_username):
    	t1 = Table('user') 
    	query = t1.scan(username__eq=raw_username, limit=1)
    	for q in query:
    		self.UserID = int(q['UserID'])
    		self.password = q['password']
    		self.username = raw_username
    	return self

    def get_user_all(self, ID_num):
	usr2 = user.get(int(ID_num))
	return usr2

    def set_password(self, raw_password):
    	self.password = make_password(raw_password)

    def check_password(self, raw_password):
    	def setter(raw_password):
    		self.set_password(raw_password)
    		self.save(update_fields=["password"])
    	return check_password(raw_password, self.password, setter)

    def get_session_auth_hash(self):
        key_salt = "django.contrib.auth.models.AbstractBaseUser.get_session_auth_hash"
        return salted_hmac(key_salt, self.password).hexdigest()

    def is_authenticated(self):
    	return True


class client(DynamoDBModel):
        __table__=u"client"
        __hash_key__=u"idclient"
        __schema__ = {
                u"idclient": unicode,
                u"idadmin": int,
                u"birthdate": unicode,
		u"loanamount": unicode,
                u"loanperiod": int,
                u"loanpurpose": unicode,
                u"loanrate": unicode,
                u"status": unicode,
                u"risk": unicode,
                u"created": unicode,
                u"modified": unicode,
                u"record": set,
        		}

	def get_clients(self, raw_idadmin):
		t1 = Table('client') 
    		query = t1.scan(idadmin__eq=raw_idadmin, limit=50)
    		j = 0
		arr1 = []
		arr2 = []
		datos = {0:'idclient',
		        1:'birthdate',
		        2:'loanamount',
		        3:'loanperiod',
		        4:'loanpurpose',
		        5:'status',
		        6:'risk',
		        7:'created',
		        8:'modified'
		        }

		for q in query:
		    for i in range(9):
		        arr2.append(q[datos[i]])
		    print arr2
		    arr1.append(arr2)
		    arr2 = []
		    j += 1
	    	return arr1

	def get_client_all(self, ID_num):
		cli = client.get(ID_num)
		return cli

	#def getIdclient(self):
	#        return self.idclient
	#def setIdclient(idclient, self):
	#	self.idclient=idclient
	#def getIdadmin(self):
	#	return self.idadmin
	#def setIdadmin(idadmin):
	#	self.idadmin=idadmin
	#def setBirthdate(birthdate, self):
    #            self.idadmin=idadmin
	#def setLoanPeriod(loanperiod, self):
	#	self.loanperiod=loanperiod
	#def setLoanPurpose(loanpurpose, self):
	#	self.loanpurpose=loanpurpose
	#def setLoanRate(loanrate, self):
	#	self.loanrate=loanrate
	#def setStatus(status, self):
	#	self.status=status
	#def setRisk(risk, self):
	#	self.risk=risk
	#def setCreated(created, self):
	#	self.created=created
	#def setModified(modified, self):
	#	self.modified=modified
	#def setRecord(record, self):
	#	self.record=record
 
