import argparse
import copy
import logging
import re
import sys
from urllib.parse import urlparse, quote, unquote
from core import config
from core import log
from core.checker import checker
from urllib.parse import urlparse
import logging
from core.colors import end, green, que
import core.config
from core.config import xsschecker, minEfficiency
from core.dom import dom
from core.filterChecker import filterChecker
from core.generator import generator
from core.htmlParser import htmlParser
from core.requester import requester
from core.utils import getUrl, getParams, getVar
from core.wafDetector import wafDetector
from core.log import setup_logger

logger = setup_logger(__name__)

def parse_args():
    parser = argparse.ArgumentParser(epilog='\tExample: \r\npython ' + sys.argv[0] + " -u google.com")
    parser.add_argument('-u', '--url', help='url', dest='target')
    parser.add_argument('--data', help='post data', dest='paramData')
    parser.add_argument('-E', '--encode', help='encode payloads', dest='encode')
    parser.add_argument('--fuzzer', help='fuzzer', dest='fuzz', action='store_true')
    parser.add_argument('--update', help='update', dest='update', action='store_true')
    parser.add_argument('--timeout', help='timeout', dest='timeout', type=int, default=config.timeout)
    parser.add_argument('--proxy', help='use prox(y|ies)', dest='proxy', action='store_true')
    parser.add_argument('--crawl', help='crawl', dest='recursive', action='store_true')
    parser.add_argument('--json', help='treat post data as json', dest='jsonData', action='store_true')
    parser.add_argument('--path', help='inject payloads in the path', dest='path', action='store_true')
    parser.add_argument('--seeds', help='load crawling seeds from a file', dest='args_seeds')
    parser.add_argument('-f', '--file', help='load payloads from a file', dest='args_file')
    parser.add_argument('-l', '--level', help='level of crawling', dest='level', type=int, default=2)
    parser.add_argument('--headers', help='add headers', dest='add_headers', nargs='?', const=True)
    parser.add_argument('-t', '--threads', help='number of threads', dest='threadCount', type=int, default=config.threadCount)
    parser.add_argument('-d', '--delay', help='delay between requests', dest='delay', type=int, default=config.delay)
    parser.add_argument('--skip', help="don't ask to continue", dest='skip', action='store_true')
    parser.add_argument('--skip-dom', help='skip dom checking', dest='skipDOM', action='store_true')
    parser.add_argument('--blind', help='inject blind XSS payload while crawling', dest='blindXSS', action='store_true')
    parser.add_argument('--console-log-level', help='Console logging level', dest='console_log_level', default=logging.INFO, choices=logging._nameToLevel.keys())
    parser.add_argument('--file-log-level', help='File logging level', dest='file_log_level', choices=log.log_config.keys(), default=None)
    parser.add_argument('--log-file', help='Name of the file to log', dest='log_file', default=log.log_file)
    parser.add_argument('--dorks', help='search webs with dorks', dest='dorks', type=str)
    parser.add_argument('-o', '--output', help='specify output directory', required=False)
    parser.add_argument('-n', '--number-pages', help='search dorks number page limit', dest='numberpage', type=int)
    parser.add_argument('-i', '--input', help='specify input file of domains to scan', dest='input_file', required=False)
    parser.add_argument('-L', '--dork-list', help='list names of dorks exploits', dest='dorkslist', choices=['wordpress', 'prestashop', 'joomla', 'lokomedia', 'drupal', 'all'])
    parser.add_argument('-p',  '--ports', help='ports to scan', dest='scanports')
    parser.add_argument('-X', '--exploit', help='searching vulnerability & run exploits', dest='exploit', action='store_true')
    parser.add_argument('--it', help='interactive mode.', dest='cli', action='store_true')
    parser.add_argument('--cms', help='search cms info[themes,plugins,user,version..]', dest='cms', action='store_true')
    parser.add_argument('-w', '--web-info', help='web informations gathering', dest='webinfo', action='store_true')
    parser.add_argument('-D', '--domain-info', help='subdomains informations gathering', dest='subdomains', action='store_true')
    parser.add_argument('--dns', help='dns informations gatherings', dest='dnsdump', action='store_true')
    parser.add_argument('-b','--bruteforce', help='enable bruteforce', dest='bruteforce', action='store_true')
    parser.add_argument('-W','--wordlist', help='wordlist file or no file',dest='wordlist',action='store_true')
    parser.add_argument('-us','--username', help='username file or no username file',dest='username',action='store_true')
    parser.add_argument('-ps','--password', help='password file or no password file',dest='password',action='store_true')
    return parser.parse_args()

args = parse_args()

def validate_url(url):
    parsed_url = urlparse(url)
    if parsed_url.scheme and parsed_url.netloc:
        return True
    else:
        return False

def check_network_connection():
    # Periksa koneksi jaringan
    if network_connection_is_stable():
        logger.info("Koneksi jaringan stabil.")
    else:
        logger.info("Masalah koneksi jaringan.")

def scan(args, paramData, encoding, headers, delay, timeout, skipDOM, skip):
    GET, POST = (False, True) if paramData else (True, False)

    # Jika pengguna tidak memberikan URL target, berikan pesan kesalahan yang jelas
    if not args.target:
        logger.error('URL target tidak diberikan.')
        quit()

    if not args.target.startswith('http'):
        try:
            paramsCopy = {}
            response = requester(args.target, paramsCopy, headers, GET, delay, timeout)
            args.target = 'https://' + args.target
        except Exception as e:
            logger.error(f"Error: {e}")
            args.target = 'http://' + args.target

    logger.debug('Scan target: {}'.format(args))
    response = requester(args, {}, headers, GET, delay, timeout).text

    if not skipDOM:
        logger.run('Memeriksa kerentanan DOM')
        highlighted = dom(response)
        if highlighted:
            logger.good('Objek yang berpotensi rentan ditemukan')
            logger.red_line(level='good')
            for line in highlighted:
                logger.no_format(line, level='good')
            logger.red_line(level='good')

    host = urlparse(args.target).netloc  # Ekstrak host dari URL
    logger.debug('Host yang akan dipindai: {}'.format(host))
    url = getUrl(args.target, GET)
    logger.debug('URL yang akan dipindai: {}'.format(url))
    params = getParams(args, paramData, "GET")
    logger.debug_json('Parameter yang akan dipindai:', params)

    # Jika tidak ada parameter yang ditemukan, berikan pesan kesalahan yang jelas
    if not params:
        logger.info("Tidak ada parameter yang diuji.")
        return

    WAF = wafDetector(
        url, {list(params.keys())[0]: xsschecker}, headers, GET, delay, timeout)
    
    if WAF:
        logger.error('WAF terdeteksi: %s%s%s' % (green, WAF, end))
    else:
        logger.good('Status WAF: %sOffline%s' % (green, end))

    for paramName in params.keys():
        paramsCopy = copy.deepcopy(params)
        logger.info('Menguji parameter: %s' % paramName)

        if encoding:
            paramsCopy[paramName] = encoding(xsschecker)
        else:
            paramsCopy[paramName] = xsschecker

        response = requester(url, paramsCopy, headers, GET, delay, timeout)
        occurences = htmlParser(response, encoding)
        positions = occurences.keys()

        logger.debug('Occurences yang ditemukan: {}'.format(occurences))

        if not occurences:
            logger.error('Tidak ada refleksi yang ditemukan')
            continue
        else:
            logger.info('Refleksi yang ditemukan: %i' % len(occurences))

        logger.run('Menganalisis refleksi')
        efficiencies = filterChecker(
            url, paramsCopy, headers, GET, delay, occurences, timeout, encoding)
        logger.debug('Efisiensi pemindaian: {}'.format(efficiencies))
        logger.run('Menghasilkan payload')
        vectors = generator(occurences, response.text)
        total = 0

        for v in vectors.values():
            total += len(v)

        if total == 0:
            logger.error('Tidak ada vektor yang dibuat.')
            continue

        logger.info('Payload yang dihasilkan: %i' % total)
        progress = 0

        for confidence, vects in vectors.items():
            for vect in vects:
                if config['globalVariables']['path']:
                    vect = vect.replace('/', '%2F')

                loggerVector = vect
                progress += 1
                logger.run('Progress: %i/%i\r' % (progress, total))

                if not GET:
                    vect = unquote(vect)

                efficiencies = checker(
                    url, paramsCopy, headers, GET, delay, vect, positions, timeout, encoding)

                if not efficiencies:
                    for i in range(len(occurences)):
                        efficiencies.append(0)

                bestEfficiency = max(efficiencies)

                if bestEfficiency == 100 or (vect[0] == '\\' and bestEfficiency >= 95):
                    logger.red_line()
                    logger.good('Payload: %s' % loggerVector)
                    logger.info('Efisiensi: %i' % bestEfficiency)
                    logger.info('Keyakinan: %i' % confidence)

                    if not skip:
                        choice = input(
                            '%s Apakah Anda ingin melanjutkan pemindaian? [y/N] ' % que).lower()

                        if choice != 'y':
                            quit()
                elif bestEfficiency > minEfficiency:
                    logger.red_line()
                    logger.good('Payload: %s' % loggerVector)
                    logger.info('Efisiensi: %i' % bestEfficiency)
                    logger.info('Keyakinan: %i' % confidence)

        logger.no_format('')
        
def getParams(args, paramData, method):
    if paramData is None:
        return {}

    if not isinstance(paramData, str):
        paramData = str(paramData)

    parts = paramData.split('&')
    params = {}

    for part in parts:
        if '=' not in part:
            logger.error(f"Data parameter tidak valid: {part}")
            continue
        try:
            key, value = part.split('=')
            params[key] = value
        except ValueError:
            logger.error(f"Data parameter tidak valid: {part}")

    return params

scan(args, args.paramData, args.encode, args.add_headers, args.delay, args.timeout, args.skipDOM, args.skip)
