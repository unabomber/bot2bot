"""Origin, cookie and browser response guards shared by the optional web UI."""
from dataclasses import dataclass
import ipaddress
import re
from urllib.parse import urlsplit


class GuardError(Exception):
    def __init__(self,status,message):
        super().__init__(message)
        self.status,self.message = status,message


def _authority(scheme, raw):
    if not isinstance(raw,str) or not raw or not raw.isascii() or any(ord(c)<=32 or ord(c)==127 for c in raw) or any(c in raw for c in '/?#@\\'):
        raise GuardError(400,'invalid public host')
    try:
        parsed = urlsplit(scheme+'://'+raw)
        host,port = parsed.hostname,parsed.port
        if not host or parsed.username or parsed.password or port==0:
            raise ValueError()
        if ':' in host:
            if '%' in host or not re.fullmatch(r'\[[0-9A-Fa-f:.]+\](?::[0-9]+)?',raw):
                raise ValueError()
            host = '['+ipaddress.IPv6Address(host).compressed+']'
        else:
            if not re.fullmatch(r'[A-Za-z0-9.-]+(?::[0-9]+)?',raw) or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]*[a-z0-9])?',part) for part in host.split('.')):
                raise ValueError()
        if port is not None and port != (443 if scheme=='https' else 80):
            host += ':'+str(port)
        return host
    except (ValueError,TypeError):
        raise GuardError(400,'invalid public host') from None


@dataclass(frozen=True)
class WebConfig:
    origin: str
    host: str
    secure: bool

    @property
    def authority(self):
        return self.host

    @classmethod
    def parse(cls,origin):
        if not isinstance(origin,str) or not origin.isascii() or any(ord(c)<=32 or ord(c)==127 for c in origin):
            raise GuardError(400,'invalid public origin')
        try:
            parsed = urlsplit(origin)
        except ValueError:
            raise GuardError(400,'invalid public origin') from None
        if parsed.scheme not in ('http','https') or not parsed.netloc or parsed.path or '?' in origin or '#' in origin:
            raise GuardError(400,'public origin must be an http(s) origin without a path')
        host = _authority(parsed.scheme,parsed.netloc)
        return cls(parsed.scheme+'://'+host,host,parsed.scheme=='https')


def _values(headers,name):
    if hasattr(headers,'get_all'):
        return headers.get_all(name) or []
    return [v for k,v in headers.items() if k.lower()==name.lower()]


def _single(headers,name,required=False):
    values = _values(headers,name)
    if len(values)>1 or (values and not isinstance(values[0],str)):
        raise GuardError(403,'ambiguous security header')
    if not values:
        if required:
            raise GuardError(403,'required security header missing')
        return None
    return values[0]


def check_host(config,host_header):
    try:
        host = _authority('https' if config.secure else 'http',host_header)
    except GuardError:
        raise GuardError(403,'host is not allowed') from None
    if host != config.host:
        raise GuardError(403,'host is not allowed')


def check_origin(config,origin_header):
    if origin_header != config.origin:
        raise GuardError(403,'origin is not allowed')


def check_fetch_site(headers):
    value = _single(headers,'Sec-Fetch-Site')
    if value is not None and value not in ('same-origin','none'):
        raise GuardError(403,'cross-origin request is not allowed')


def check_json_mutation(headers):
    value = _single(headers,'Content-Type')
    if value is None:
        raise GuardError(415,'application/json is required')
    parts = [p.strip().lower() for p in value.split(';')]
    if parts[0]!='application/json' or len(parts)>2:
        raise GuardError(415,'application/json is required')
    if len(parts)==2:
        param = parts[1].split('=',1)
        if len(param)!=2 or param[0].strip()!='charset' or param[1].strip() not in ('utf-8','"utf-8"'):
            raise GuardError(415,'only UTF-8 JSON is supported')


def parse_cookie(cookie_header,name='b2b_session'):
    if not isinstance(cookie_header,str) or len(cookie_header)>8192 or any(ord(c)<32 or ord(c)==127 for c in cookie_header):
        return None
    matches = []
    for item in cookie_header.split(';'):
        key,sep,value = item.strip().partition('=')
        if key==name:
            if not sep:
                return None
            matches.append(value)
    if len(matches)!=1 or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}',matches[0]):
        return None
    return matches[0]


def session_cookie(config,value,max_age=28800):
    if not isinstance(value,str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}',value) or type(max_age) is not int or not 0<max_age<=28800:
        raise GuardError(400,'invalid session cookie')
    return 'b2b_session='+value+'; HttpOnly; SameSite=Strict; Path=/ui; Max-Age='+str(max_age)+('; Secure' if config.secure else '')


def clear_cookie(config):
    return 'b2b_session=; HttpOnly; SameSite=Strict; Path=/ui; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT'+('; Secure' if config.secure else '')


def security_headers():
    return [('Cache-Control','no-store'),('X-Content-Type-Options','nosniff'),
            ('X-Frame-Options','DENY'),('Referrer-Policy','no-referrer'),
            ('Content-Security-Policy',"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")]


class WebSecurity:
    """Facade that also validates duplicate headers before the string helpers."""
    def __init__(self,public_origin):
        self.config = WebConfig.parse(public_origin)
        self.origin,self.authority,self.secure = self.config.origin,self.config.host,self.config.secure

    def check_host(self,headers):
        check_host(self.config,_single(headers,'Host',required=True))

    def check_request(self,headers,mutation=False):
        self.check_host(headers)
        origin = _single(headers,'Origin',required=mutation)
        if origin is not None:
            check_origin(self.config,origin)
        check_fetch_site(headers)
        if mutation:
            check_json_mutation(headers)

    def cookie_session(self,headers):
        values = _values(headers,'Cookie')
        return parse_cookie(values[0]) if len(values)==1 else None

    def session_cookie(self,value,max_age=28800):
        return session_cookie(self.config,value,max_age)

    def clear_cookie(self):
        return clear_cookie(self.config)

    def headers(self):
        return security_headers()
