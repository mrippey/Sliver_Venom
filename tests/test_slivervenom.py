import pytest
import shodan
from slivervenom import __version__


def test_version():
    assert __version__ == '0.1.0'


def test_incorrect_shodan_key_except():
    
    api = shodan.Shodan('asdfasdflkajdskfajiajsdfj')

    with pytest.raises(shodan.APIError):

        api.search('VNC')
        

def test_normal_shodan_query():
    api = shodan.Shodan('Your Key')

    shodan_output = api.search('Cisco')

    assert 'matches' in shodan_output
    assert 'total' in shodan_output

    assert shodan_output['matches']
    assert shodan_output['total']
