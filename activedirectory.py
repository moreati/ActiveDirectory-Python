# External Dependencies
import ldap

# Internal Dependencies
import datetime
import re

class activedirectory:

	domain_pw_policy = {}
	granular_pw_policy = {} # keys are policy DNs

	def __init__(self, host, base, bind_dn, bind_pw):
		ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, 0)
		ldap.set_option(ldap.OPT_REFERRALS, 0)
		ldap.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
		self.conn = None
		self.host = host
		self.uri = "ldaps://%s" % (host)
		self.base = base
		self.bind_dn = bind_dn
		try:
			self.conn = ldap.initialize(self.uri)
			self.conn.simple_bind_s(bind_dn, bind_pw)
			if not self.is_admin(bind_dn):
				return None
		except ldap.INVALID_CREDENTIALS, e:
			raise self.authn_failure(bind_dn, bind_pwd, self.uri)
		except ldap.LDAPError, e:
			raise self.ldap_error(e[0]['desc'])

	def user_set_pwd(self, user, current_pwd, new_pwd):
		# Change user's account using their own creds
		# This forces adherence to length/complexity/history
		# They must exist, not be priv'd, and be able to authn
		status = self.get_user_status(user)
		user_dn = status['user_dn']
		if self.is_admin(user_dn):
			raise self.user_protected(user)
		if not status['acct_can_authn']:
			raise self.user_cannot_authn(user, status)
		# The new password must respect policy
		if not len(new_pwd) >= status['acct_pwd_policy']['pwd_length_min']:
			msg = 'New password for %s must be at least %d characters, submitted password has only %d.' % (user, status['acct_pwd_policy']['pwd_length_min'], len(new_pwd))
			raise self.pwd_vette_failure(user, new_pwd, msg, status)
		patterns = [r'.*(?P<digit>[0-9]).*', r'.*(?P<lowercase>[a-z]).*', r'.*(?P<uppercase>[A-Z]).*', r'.*(?P<special>[~!@#$%^&*_\-+=`|\\(){}\[\]:;"\'<>,.?/]).*']
		matches = []
		for pattern in patterns:
			match = re.match(pattern, new_pwd)
			if match and match.groupdict() and match.groupdict().keys():
				matches.append(match.groupdict().keys()[0])
		if status['acct_pwd_policy']['pwd_complexity_enforced'] and len(matches) < 3:
			msg = 'New password for %s must contain 3 of 4 character types (lowercase, uppercase, digit, special), only found %s.' % (user, (', ').join(matches))
			raise self.pwd_vette_failure(user, new_pwd, msg, status)
		# Encode password and attempt change. If server is unwilling, history is likely fault.
		bind_pw = current_pwd
		current_pwd = unicode('\"' + current_pwd + '\"', 'iso-8859-1').encode('utf-16-le')
		new_pwd = unicode('\"' + new_pwd + '\"', 'iso-8859-1').encode('utf-16-le')
		pass_mod = [(ldap.MOD_DELETE, 'unicodePwd', [current_pwd]), (ldap.MOD_ADD, 'unicodePwd', [new_pwd])]
		try:
			user_conn = ldap.initialize(self.uri)
			user_conn.simple_bind_s(user_dn, bind_pw)
			user_conn.modify_s(user_dn, pass_mod)
			user_conn.unbind_s()
		except ldap.INVALID_CREDENTIALS, e:
			raise self.authn_failure(user_dn, bind_pw, self.uri)
		except ldap.CONSTRAINT_VIOLATION:
			# There may be some case in which a constraint violation is not history violation,
			# but for now this is the best I can come up with.
			msg = 'New password for %s must not match any of the past %d passwords.' % (user, status['acct_pwd_policy']['pwd_history_depth'])
			raise self.pwd_vette_failure(user, new_pwd, msg, status)
		except ldap.LDAPError, e:
			raise self.ldap_error(e[0]['desc'])

	def set_pwd(self, user, new_pwd):
		# Change the user's password using priv'd creds
		# They must exist, not be priv'd
		status = self.get_user_status(user)
		user_dn = status['user_dn']
		if self.is_admin(user_dn):
			raise self.user_protected(user)
		# Even priv'd user must respect min password length.
		if not len(new_pwd) >= status['acct_pwd_policy']['pwd_length_min']:
			msg = 'New password for %s must be at least %d characters, submitted password has only %d.' % (user, status['acct_pwd_policy']['pwd_length_min'], len(new_pwd))
			raise self.pwd_vette_failure(user, new_pwd, msg, status)
		new_pwd = unicode('\"' + new_pwd + '\"', "iso-8859-1").encode('utf-16-le')
		pass_mod = [((ldap.MOD_REPLACE, 'unicodePwd', [new_pwd]))]
		try:
			self.conn.modify_s(user_dn, pass_mod)
		except ldap.LDAPError, e:
			raise self.ldap_error(e[0]['desc'])

	def get_user_status(self, user):
		user_base = "CN=Users,%s" % (self.base)
		user_filter = "(sAMAccountName=%s)" % (user)
		user_scope = ldap.SCOPE_SUBTREE
		status_attribs = ['pwdLastSet', 'accountExpires', 'userAccountControl', 'memberOf', 'msDS-User-Account-Control-Computed', 'msDS-UserPasswordExpiryTimeComputed', 'msDS-ResultantPSO', 'lockoutTime']
		user_status = {'user_dn':'', 'acct_pwd_expiry_enabled':'', 'acct_pwd_expiry':'', 'acct_pwd_last_set':'', 'acct_pwd_expired':'', 'acct_pwd_policy':'', 'acct_disabled':'', 'acct_locked':'', 'acct_locked_expiry':'', 'acct_expired':'', 'acct_expiry':'', 'acct_can_authn':''}
		# todo: sanitize user string
		try:
			# Load attribs to determine if user could authn
			results = self.conn.search_s(user_base, user_scope, user_filter, status_attribs)
		except ldap.LDAPError, e:
			raise self.ldap_error(e[0]['desc'])
		if len(results) != 1: # sAMAccountName should be unique
			raise self.user_not_found(user)
		result = results[0]
		user_dn = result[0]
		user_attribs = result[1]
		uac = int(user_attribs['userAccountControl'][0])
		uac_live = int(user_attribs['msDS-User-Account-Control-Computed'][0])
		s = user_status
		s['user_dn'] = user_dn
		# uac_live (msDS-User-Account-Control-Computed) contains locked + pw_expired status live.
		s['acct_locked'] = (1 if (uac_live & 0x00000010) else 0)
		s['acct_disabled'] = (1 if (uac & 0x00000002) else 0)
		s['acct_expiry'] = self.ad_time_to_unix(user_attribs['accountExpires'][0])
		s['acct_expired'] = (0 if datetime.datetime.fromtimestamp(s['acct_expiry']) > datetime.datetime.now() or s['acct_expiry'] == 0 else 1)
		s['acct_pwd_last_set'] = self.ad_time_to_unix(user_attribs['pwdLastSet'][0])
		s['acct_pwd_expiry_enabled'] = (0 if (uac & 0x00010000) else 1)
		# For password expiration need to determine which policy, if any, applies to this user.
		# msDS-ResultantPSO will be present in Server 2008+ and if the user has a PSO applied.
		# If not present, use the domain default.
		if 'msDS-ResultantPSO' in user_attribs:
			s['acct_pwd_policy'] = self.granular_pw_policy[user_attribs['msDS-ResultantPSO'][0]]
		else:
			s['acct_pwd_policy'] = self.domain_pw_policy
		# If account is locked, expiry comes from lockoutTime + policy lockout ttl.
		# lockoutTime is only reset to 0 on next successful login.
		s['acct_locked_expiry'] = (self.ad_time_to_unix(user_attribs['lockoutTime'][0]) + s['acct_pwd_policy']['pwd_lockout_ttl'] if s['acct_locked'] else 0)
		# msDS-UserPasswordExpiryTimeComputed is when a password expires. If never it is very high.
		s['acct_pwd_expiry'] = self.ad_time_to_unix(user_attribs['msDS-UserPasswordExpiryTimeComputed'][0])
		s['acct_pwd_expired'] = (1 if (uac_live & 0x00800000) else 0)
		s['acct_can_authn'] = (0 if s['acct_pwd_expired'] or s['acct_expired'] or s['acct_disabled'] or s['acct_locked'] else 1)
		return s

	def get_pw_policies(self):
		default_policy_container = self.base
		default_policy_attribs = ['maxPwdAge', 'minPwdLength', 'pwdHistoryLength', 'pwdProperties', 'lockoutThreshold', 'lockOutObservationWindow', 'lockoutDuration']
		default_policy_map = {'maxPwdAge':'pwd_ttl', 'minPwdLength':'pwd_length_min', 'pwdHistoryLength':'pwd_history_depth', 'pwdProperties':'pwd_complexity_enforced', 'lockoutThreshold':'pwd_lockout_threshold', 'lockOutObservationWindow':'pwd_lockout_window', 'lockoutDuration':'pwd_lockout_ttl'}
		granular_policy_container = 'CN=Password Settings Container,CN=System,%s' % (self.base)
		granular_policy_filter = '(objectClass=msDS-PasswordSettings)'
		granular_policy_attribs = ['msDS-LockoutDuration', 'msDS-LockoutObservationWindow', 'msDS-PasswordSettingsPrecedence', 'msDS-MaximumPasswordAge', 'msDS-LockoutThreshold', 'msDS-MinimumPasswordLength', 'msDS-PasswordComplexityEnabled', 'msDS-PasswordHistoryLength']
		granular_policy_map = {'msDS-MaximumPasswordAge':'pwd_ttl', 'msDS-MinimumPasswordLength':'pwd_length_min', 'msDS-PasswordComplexityEnabled':'pwd_complexity_enforced', 'msDS-PasswordHistoryLength':'pwd_history_depth', 'msDS-LockoutThreshold':'pwd_lockout_threshold', 'msDS-LockoutObservationWindow':'pwd_lockout_window', 'msDS-LockoutDuration':'pwd_lockout_ttl','msDS-PasswordSettingsPrecedence':'pwd_policy_priority'}
		if not self.conn:
			return None
		try:
			# Load domain-wide policy.
			results = self.conn.search_s(default_policy_container, ldap.SCOPE_BASE)
		except ldap.LDAPError, e:
			raise self.ldap_error(e[0]['desc'])
		dpp = dict([(default_policy_map[k], results[0][1][k][0]) for k in default_policy_map.keys()])
		dpp["pwd_policy_priority"] = 0 # 0 Indicates don't use it in priority calculations
		self.domain_pw_policy = self.sanitize_pw_policy(dpp)
		# Server 2008r2 only. Per-group policies in CN=Password Settings Container,CN=System
		results = self.conn.search_s(granular_policy_container, ldap.SCOPE_ONELEVEL, granular_policy_filter, granular_policy_attribs)
		for policy in results:
			gpp = dict([(granular_policy_map[k], policy[1][k][0]) for k in granular_policy_map.keys()])
			self.granular_pw_policy[policy[0]] = self.sanitize_pw_policy(gpp)
			self.granular_pw_policy[policy[0]]['pwd_policy_dn'] = policy[0]

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
		except ldap.LDAPError, e:
			raise self.ldap_error(e[0]['desc'])
		if not results:
			return 0
		if ('CN=Administrators,CN=Builtin,'+self.base).lower() in [g.lower() for g in results[0][1]['memberOf']]:
			return 1
		for group in results[0][1]['memberOf']:
				admin |= self.is_admin(group)
				# Break early once we detect admin
				if admin:
					return admin
		return admin

    # AD's date format is 100 nanosecond intervals since Jan 1 1601 in GMT.
    # To convert to seconds, divide by 10000000.
    # To convert to UNIX, convert to positive seconds and add 11644473600 to be seconds since Jan 1 1970 (epoch).
	def ad_time_to_seconds(self, ad_time):
		return -(int(ad_time) / 10000000)

	def ad_seconds_to_unix(self, ad_seconds):
		return  ((int(ad_seconds) + 11644473600) if int(ad_seconds) != 0 else 0)

	def ad_time_to_unix(self, ad_time):
		ad_seconds = self.ad_time_to_seconds(ad_time)
		return -self.ad_seconds_to_unix(ad_seconds)

	class user_not_found(Exception):
		def __init__(self, user):
			self.msg = 'Could not locate user %s.' % (user)
		def __str__(self):
			return repr(self.msg)

	class user_protected(Exception):
		def __init__(self, user):
			self.msg = '%s is a protected user; their password cannot be changed using this tool.' % (user)
		def __str__(self):
			return repr(self.msg)

	class user_cannot_authn(Exception):
		def __init__(self, user, status):
			self.status = status
			self.msg = '%s cannot authn for the following reasons: ' % (user)
			for test in ['acct_disabled', 'acct_locked', 'acct_expired', 'acct_pwd_expired']:
				if status[test]:
					self.msg += test + ' '
		def __str__(self):
			return repr(self.msg.rstrip() + '.')

	class pwd_vette_failure(Exception):
		def __init__(self, user, new_pwd, msg, status):
			self.user = user
			self.new_pwd = new_pwd
			self.msg = msg
			self.status = status
		def __str__(self):
			return repr(self.msg)

	class authn_failure(Exception):
		def __init__(self, user_dn, pwd, host):
			self.user_dn = user_dn
			self.pwd = pwd
			self.host = host
			self.msg = '%s failed to authn in a simple LDAP bind to %s' % (user_dn, host)
		def __str__(self):
			return repr(self.msg)

	class ldap_error(Exception):
		def __init__(self, msg):
			self.msg = msg
		def __str__(self):
			return repr(self.msg)
