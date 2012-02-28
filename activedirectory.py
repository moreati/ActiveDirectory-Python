# External Dependencies
import ldap

# Internal Dependencies
import datetime

class activedirectory:

	domain_pw_policy = {}
	granular_pw_policy = {} # keys are DNs policy applies to
	priv = 0 # set to 1 if bind_dn is member of Administrators

	def __init__(self, uri, base, bind_dn, bind_pw):
		ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, 0)
		ldap.set_option(ldap.OPT_REFERRALS, 0)
		ldap.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
		self.conn = None
		self.uri = uri
		self.base = base
		self.bind_dn = bind_dn
		try:
			self.conn = ldap.initialize(uri)
			self.conn.simple_bind_s(bind_dn, bind_pw)
			if not self.is_admin(bind_dn):
				self.priv = 0
			else:
				self.priv = 1
		except Exception, e:
			return None

	def user_set_pwd(self, user, old_pwd, new_pwd):
		# Change user's account using their own creds.
		# This forces adherence to length/complexity/history.
		print "hi"

	def priv_set_pwd(self, user, new_pwd):
		# Change the user's password using priv'd
		# Make sure user exists
		status = self.priv_get_user_status(user)
		if not status:
			print "Could not load status for",user,"are you sure they are real?"
			return None
		user_dn = status['user_dn']
		# Do not change an already priv'd user's password!
		if self.is_admin(user_dn):
			print user_dn,"is an admin! I'm not changing their password!"
			return None
		# Even priv'd user must respect min password length.
		if not len(new_pwd) >= status['acct_pwd_policy']['pwd_length_min']:
			print "Password must be longer than" , status['acct_pwd_policy']['pwd_length_min']
			return None
		new_pwd = unicode('\"' + new_pwd + '\"', "iso-8859-1").encode("utf-16-le")
		pass_mod = [((ldap.MOD_REPLACE, "unicodePwd", [new_pwd]))]
		try:
			self.conn.modify_s(user_dn, pass_mod)
		except Exception, e:
			raise e
		return 1

	def priv_get_user_status(self, user):
		user_base = "CN=Users," + self.base
		status_attribs = ['pwdLastSet', 'accountExpires', 'userAccountControl', 'memberOf']
		user_status = {'user_dn':'', 'acct_pwd_expiry_enabled':'', 'acct_pwd_expiry':'', 'acct_pwd_last_set':'', 'acct_pwd_expired':'', 'acct_pwd_policy':'', 'acct_disabled':'', 'acct_locked':'', 'acct_expired':'', 'acct_expiry':'', 'acct_can_auth':''}
		if not self.conn or not self.priv:
			return None
		# todo: sanitize user string
		try:
			# Load attribs to determine if user could authn
			results = self.conn.search_s(user_base, ldap.SCOPE_SUBTREE, "(sAMAccountName=" + user + ")", status_attribs)
		except Exception, e:
			raise e
		if len(results) != 1: # sAMAccountName should be unique
			return None
		result = results[0]
		user_dn = result[0]
		user_attribs = result[1]
		uac = int(user_attribs['userAccountControl'][0])
		s = user_status
		s['user_dn'] = user_dn
		s['acct_locked'] = (1 if (uac & 0x00000010) else 0)
		s['acct_disabled'] = (1 if (uac & 0x00000002) else 0)
		s['acct_expiry'] = self.ad_time_to_unix(user_attribs['accountExpires'][0])
		s['acct_expired'] = (0 if datetime.datetime.fromtimestamp(s['acct_expiry']) > datetime.datetime.now() or s['acct_expiry'] == 0 else 1)
		s['acct_pwd_last_set'] = self.ad_time_to_unix(user_attribs['pwdLastSet'][0])
		s['acct_pwd_expiry_enabled'] = (0 if (uac & 0x00010000) else 1)
		# Even though there is a password expired flag in uac, it is not exposed to LDAP.
		# For password expiration need to determine which policy, if any, applies to this user.
		# PSO precedence:
		# 1) applied directly to user
		# 2) applied to group with lowest priority
		# 3) domain default policy
		if user_dn not in self.granular_pw_policy:
			granular_candidates = []
			for group in user_attribs['memberOf']:
				if group in self.granular_pw_policy:
					granular_candidates.append(self.granular_pw_policy[group])
			if len(granular_candidates) > 0:
				# Inefficient linear search here.
				candidate = granular_candidates[0]
				for c in granular_candidates[1:]:
					if c['pwd_policy_priority'] < candidate['pwd_policy_priority']:
						candidate = c
				s['acct_pwd_policy'] = candidate
		else:
			s['acct_pwd_policy'] = self.granular_pw_policy[user_dn]
		if not s['acct_pwd_policy']:
			s['acct_pwd_policy'] = self.domain_pw_policy
		s['acct_pwd_expiry'] = s['acct_pwd_last_set'] + s['acct_pwd_policy']['pwd_ttl']
		s['acct_pwd_expired'] = 0
		if datetime.datetime.fromtimestamp(s['acct_pwd_expiry']) < datetime.datetime.now() and s['acct_pwd_expiry_enabled']:
			s['acct_pwd_expired'] = 1
		s['acct_can_auth'] = (0 if s['acct_pwd_expired'] or s['acct_expired'] or s['acct_disabled'] or s['acct_locked'] else 1)
		return s

	def priv_get_pw_policies(self):
		default_policy_container = self.base
		default_policy_attribs = ['maxPwdAge', 'minPwdLength', 'pwdHistoryLength', 'pwdProperties', 'lockoutThreshold', 'lockOutObservationWindow', 'lockoutDuration']
		default_policy_map = {'maxPwdAge':'pwd_ttl', 'minPwdLength':'pwd_length_min', 'pwdHistoryLength':'pwd_history_depth', 'pwdProperties':'pwd_complexity_enforced', 'lockoutThreshold':'pwd_lockout_threshold', 'lockOutObservationWindow':'pwd_lockout_window', 'lockoutDuration':'pwd_lockout_ttl'}
		granular_policy_container = 'CN=Password Settings Container,CN=System,' + self.base
		granular_policy_filter = '(objectClass=msDS-PasswordSettings)'
		granular_policy_attribs = ['msDS-LockoutDuration', 'msDS-LockoutObservationWindow', 'msDS-PasswordSettingsPrecedence', 'msDS-MaximumPasswordAge', 'msDS-PSOAppliesTo', 'msDS-LockoutThreshold', 'msDS-MinimumPasswordLength', 'msDS-PasswordComplexityEnabled', 'msDS-PasswordHistoryLength']
		granular_policy_map = {'msDS-MaximumPasswordAge':'pwd_ttl', 'msDS-MinimumPasswordLength':'pwd_length_min', 'msDS-PasswordComplexityEnabled':'pwd_complexity_enforced', 'msDS-PasswordHistoryLength':'pwd_history_depth', 'msDS-LockoutThreshold':'pwd_lockout_threshold', 'msDS-LockoutObservationWindow':'pwd_lockout_window', 'msDS-LockoutDuration':'pwd_lockout_ttl','msDS-PasswordSettingsPrecedence':'pwd_policy_priority'}
		if not self.conn or not self.priv:
			return None
		try:
			# Load domain-wide policy.
			results = self.conn.search_s(default_policy_container, ldap.SCOPE_BASE)
			dpp = dict([(default_policy_map[k], results[0][1][k][0]) for k in default_policy_map.keys()])
			dpp["pwd_policy_priority"] = 0 # 0 Indicates don't use it in priority calculations
			self.domain_pw_policy = self.sanitize_pw_policy(dpp)
			# Server 2008r2 only. Per-group policies in CN=Password Settings Container,CN=System
			results = self.conn.search_s(granular_policy_container, ldap.SCOPE_ONELEVEL, granular_policy_filter, granular_policy_attribs)
			for policy in results:
				gpp = dict([(granular_policy_map[k], policy[1][k][0]) for k in granular_policy_map.keys()])
				for target in policy[1]['msDS-PSOAppliesTo']:
					self.granular_pw_policy[target] = self.sanitize_pw_policy(gpp)
		except Exception, e:
			raise e

	def sanitize_pw_policy(self, pw_policy):
		valid_policy_entries = ['pwd_ttl', 'pwd_length_min', 'pwd_history_depth', 'pwd_complexity_enforced', 'pwd_lockout_threshold', 'pwd_lockout_window', 'pwd_lockout_ttl', 'pwd_policy_priority']
		if len(set(valid_policy_entries) - set(pw_policy.keys())) != 0:
			return None
		pw_policy['pwd_history_depth'] = int(pw_policy['pwd_history_depth'])
		pw_policy['pwd_length_min'] = int(pw_policy['pwd_length_min'])
		pw_policy['pwd_complexity_enforced'] = (int(pw_policy['pwd_complexity_enforced']) & 0x1 if pw_policy['pwd_complexity_enforced'] not in ['TRUE', 'FALSE'] else int({'TRUE':1, 'FALSE':0}[pw_policy['pwd_complexity_enforced']]))
		pw_policy['pwd_ttl'] = self.ad_time_to_seconds(pw_policy['pwd_ttl'])
		pw_policy['pwd_lockout_ttl'] = self.ad_time_to_seconds(pw_policy['pwd_lockout_ttl'])
		pw_policy['pwd_lockout_window'] = self.ad_time_to_seconds(pw_policy['pwd_lockout_window'])
		pw_policy['pwd_lockout_threshold'] = int(pw_policy['pwd_lockout_threshold'])
		pw_policy['pwd_policy_priority'] = int(pw_policy['pwd_policy_priority'])
		return pw_policy

	def is_admin(self, search_dn, admin = 0):
		# Recursively look at what groups search_dn is a member of.
		# If we find a search_dn is a member of the builtin Administrators group, return true.
		if not self.conn:
			return None
		try:
			results = self.conn.search_s(search_dn, ldap.SCOPE_BASE, '(memberOf=*)', ['memberOf'])
			if not results:
				return 0
			if ("CN=Administrators,CN=Builtin,"+self.base).lower() in [g.lower() for g in results[0][1]['memberOf']]:
				return 1
			for group in results[0][1]['memberOf']:
					admin |= self.is_admin(group)
					# Break early once we detect admin
					if admin:
						return admin
		except Exception, e:
			raise e
		return admin

    # AD's date format is 100 nanosecond intervals since Jan 1 1601 in UTC.
    # To convert to seconds, divide by 10000000.
    # To convert to UNIX, convert to positive seconds and add 11676009600 to be seconds since Jan 1 1970 (epoch).
	def ad_time_to_seconds(self, ad_time):
		return -(int(ad_time) / 10000000)

	def ad_seconds_to_unix(self, ad_seconds):
		return ((int(ad_seconds) + 11676009600) if int(ad_seconds) != 0 else 0)

	def ad_time_to_unix(self, ad_time):
		ad_seconds = self.ad_time_to_seconds(ad_time)
		return -self.ad_seconds_to_unix(ad_seconds)
