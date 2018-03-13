import sys
import re
import socket
import subprocess
import argparse
from urllib.request import urlopen


def tracert(domain):
    output = subprocess.check_output('tracert ' + domain, shell=True)
    lines = output.decode('cp866').split('\n')[1:]
    addreses = []
    for line in lines:
        try:
            mo = re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", line)
            addreses.append(mo.group(0))
        except Exception:
            continue
    print(addreses)
    return addreses


def get_info(ip):
    with socket.socket() as s:
        try:
            whois = get_whois(ip)
            ip += '\n'
            result = ''
            s.connect((whois, 43))
            s.send(ip.encode())
            while True:
                buffer = s.recv(4096)
                if buffer:
                    result += buffer.decode()
                else:
                    break
            return result
        except Exception:
            return 'failed'


def get_whois(ip):
    with urlopen('http://www.iana.org/whois?q=' + ip) as page:
        page = page.read().decode()
        try:
            return re.search(r'whois:.+', page).group().split()[-1]
        except Exception:
            return 'undefine'


def get_provider(ip):
    with urlopen('https://www.whoismyisp.org/ip/' + ip) as page:
        page = page.read().decode()
        try:
            prov = re.search(r'<p class="isp">(.+)</p>', page)
            return prov.group(1)
        except:
            return 'undefine'


def get_country(info, ip):
    mo = re.search(r'country:.+', info, re.IGNORECASE)
    if mo:
        return mo.group().split()[-1]
    else:
        with urlopen('http://iplocation.com/?ip=' + ip) as page:
            page = page.read().decode()
            mo = re.search(r'"country_name">(.+)</s', page, re.IGNORECASE)
            if mo:
                return mo.group(1)
            else:
                return 'undefine'


def get_as_number(info):
    mo = re.search(r'origin:(.+)', info, re.IGNORECASE)
    if not mo:
        mo = re.search(r'originas:(.+)', info, re.IGNORECASE)
    if mo:
        return mo.group(1).strip()
    else:
        return 'undefine'


def create_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('domain', help="write domain", type=str)
    return parser


def main():
    parser = create_parser()
    namespace = parser.parse_args(sys.argv[1:])
    domain = namespace.domain
    ip_list = tracert(domain)
    for ip in ip_list[1:]:
        info = get_info(ip)
        country = get_country(info, ip)
        as_number = get_as_number(info)
        provider = get_provider(ip)
        whois = get_whois(ip)
        print('IP: {0} AS: {1} Country: {2} Whois: {4} Provider: {3}'
              .format(ip, as_number, country, provider, whois))


if __name__ == '__main__':
    main()
