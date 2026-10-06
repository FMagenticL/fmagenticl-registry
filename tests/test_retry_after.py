import datetime
from fmagenticl.client.middleware import parse_retry_after

def test_parse_retry_after_integer():
    assert parse_retry_after("120") == 120.0
    assert parse_retry_after("0") == 0.0
    assert parse_retry_after(None) == 5.0

def test_parse_retry_after_http_date():
    # Future timestamp in RFC 2822 format
    now = datetime.datetime.now(datetime.timezone.utc)
    future = now + datetime.timedelta(seconds=60)
    http_date = future.strftime("%a, %d %b %Y %H:%M:%S GMT")
    
    delay = parse_retry_after(http_date)
    assert 55.0 <= delay <= 65.0

def test_parse_retry_after_invalid_fallback():
    assert parse_retry_after("not-a-valid-date-or-int") == 5.0
