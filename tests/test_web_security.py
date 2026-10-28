from email.message import Message
import unittest

from relay.web_security import (GuardError,WebConfig,WebSecurity,check_host,check_origin,
    check_fetch_site,check_json_mutation,parse_cookie,session_cookie,clear_cookie,security_headers)


class WebSecurityTests(unittest.TestCase):
    def setUp(self):
        self.guard = WebSecurity('http://127.0.0.1:8767')
        self.headers = {'Host':'127.0.0.1:8767','Origin':self.guard.origin,
                        'Content-Type':'application/json','Sec-Fetch-Site':'same-origin'}

    def rejected(self,fn,*args,**kwargs):
        with self.assertRaises(GuardError):
            fn(*args,**kwargs)

    def test_origin_normalization_and_https_cookie(self):
        cfg = WebConfig.parse('https://EXAMPLE.COM:443')
        self.assertEqual((cfg.origin,cfg.host,cfg.secure),('https://example.com','example.com',True))
        check_host(cfg,'EXAMPLE.com:443')
        check_origin(cfg,'https://example.com')
        self.assertIn('; Secure',session_cookie(cfg,'x'*43,300))
        self.assertNotIn('; Secure',self.guard.session_cookie('x'*43))
        ipv6 = WebConfig.parse('http://[::1]:8767')
        check_host(ipv6,'[0:0:0:0:0:0:0:1]:8767')

    def test_bad_configured_origins_rejected(self):
        for value in ('https://user:pass@host','ftp://host','http://host/path','http://host/',
                      'http://host?x=1','http://host#x','http://host:65536','http://host:0',
                      'http://[::1]junk','http://host:','http://a..b','http://-host',
                      'http://host\\evil',' http://host','http://host\r\nX: y','null','//host'):
            self.rejected(WebConfig.parse,value)

    def test_host_and_origin_are_not_derived_from_forwarded_headers(self):
        good = dict(self.headers,**{'X-Forwarded-Host':'attacker','X-Forwarded-Proto':'https'})
        self.guard.check_request(good,mutation=True)
        for host in ('attacker','127.0.0.1:8768','127.0.0.1:8767@evil','127.0.0.1:8767/path','[::1]junk'):
            self.rejected(self.guard.check_request,dict(self.headers,Host=host),mutation=True)
        for origin in ('null','http://attacker','http://127.0.0.1:8767/','HTTP://127.0.0.1:8767',None):
            changed = dict(self.headers)
            if origin is None:
                del changed['Origin']
            else:
                changed['Origin'] = origin
            self.rejected(self.guard.check_request,changed,mutation=True)

    def test_api_get_allows_absent_origin_but_denies_cross_site(self):
        self.guard.check_request({'Host':self.guard.authority})
        self.guard.check_host({'Host':self.guard.authority,'Sec-Fetch-Site':'cross-site'})
        for site in ('cross-site','same-site','','same-origin,none'):
            self.rejected(self.guard.check_request,{'Host':self.guard.authority,'Sec-Fetch-Site':site})
        for site in ('same-origin','none'):
            check_fetch_site({'Sec-Fetch-Site':site})

    def test_json_media_type_checks(self):
        for value in ('application/json','application/json; charset=utf-8','APPLICATION/JSON; Charset="UTF-8"'):
            check_json_mutation({'Content-Type':value})
        for value in ('text/plain','application/jsonp','application/json; charset=utf-16',
                      'application/json; x=y','application/json; charset=utf-8; x=y','application/json;'):
            self.rejected(check_json_mutation,{'Content-Type':value})
        self.rejected(check_json_mutation,{})

    def test_duplicate_security_headers_are_rejected(self):
        for name in ('Host','Origin','Content-Type','Sec-Fetch-Site'):
            headers = Message()
            for key,value in self.headers.items():
                headers[key] = value
            headers[name] = self.headers[name]
            self.rejected(self.guard.check_request,headers,mutation=True)

    def test_cookies_are_strict_and_http_only(self):
        value = 'x'*43
        cookie = self.guard.session_cookie(value,100)
        for expected in ('HttpOnly','SameSite=Strict','Path=/ui','Max-Age=100'):
            self.assertIn(expected,cookie)
        self.assertNotIn('Domain=',cookie)
        self.assertEqual(parse_cookie('other=ok; b2b_session='+value),value)
        for raw in ('b2b_session=x; b2b_session=y','b2b_session="x"','b2b_session=bad value',
                    'b2b_session=','b2b_session','b2b_session='+'x'*129,'b2b_session=x\r\nHeader:y'):
            self.assertIsNone(parse_cookie(raw))
        headers = Message()
        headers['Cookie'] = 'b2b_session='+value
        headers['Cookie'] = 'b2b_session='+value
        self.assertIsNone(self.guard.cookie_session(headers))
        self.assertIn('Max-Age=0',self.guard.clear_cookie())
        self.assertIn('Secure',clear_cookie(WebConfig.parse('https://host')))

    def test_cookie_header_injection_and_invalid_age_rejected(self):
        for value in ('x; Domain=evil','x\r\nOther:y','"x"',''):
            self.rejected(self.guard.session_cookie,value)
        for age in (-1,0,28801,True,'100'):
            self.rejected(self.guard.session_cookie,'x'*43,age)

    def test_security_headers_include_strict_csp_and_no_cache(self):
        headers = dict(security_headers())
        self.assertEqual(headers['Cache-Control'],'no-store')
        self.assertEqual(headers['X-Frame-Options'],'DENY')
        self.assertEqual(headers['X-Content-Type-Options'],'nosniff')
        self.assertEqual(headers['Referrer-Policy'],'no-referrer')
        self.assertIn("default-src 'none'",headers['Content-Security-Policy'])
        self.assertNotIn('unsafe-inline',headers['Content-Security-Policy'])
        self.assertNotIn('Access-Control-Allow-Origin',headers)
