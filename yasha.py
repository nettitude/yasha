import xml.etree.ElementTree as ET
import argparse
import base64 as b64
import re
import json
from pathlib import Path
from urllib.parse import urlparse
from typing import List
import random

# Warning: don't use this with untrusted data. See https://docs.python.org/3/library/xml.html#xml-vulnerabilities.

def head_filter(req, filter):
    return [x for x in req if (x.lower()).startswith(filter.lower())]

def hsts_check(req: List[str]) -> List[str]:
    hst_lines = head_filter(req, 'Strict-Transport-Security')
    if hst_lines:
        # Remove Strict-Transport-Security from beginning
        hst_lines[0] = ''.join(hst_lines[0].split(':')[1:])
        
        good_max_age: bool = False
        for line in hst_lines:
            values = list(map(lambda f: f.strip(), line.split(';')))
            for value in values:
                value = value.strip()
                if value.lower().startswith('max-age'):
                    age = int(value.split('=')[1])
                    # max-age has to be set to this value. See https://hstspreload.org/
                    if age < 31536000:
                        return ['fail', f'max-age set to {age}']
                    else:
                        good_max_age: bool = True
        if good_max_age:
            return ['pass']
        else:
            return ['fail', 'HSTS does not contain max age']
    else:
        return ['fail', 'No HSTS header found']
    
def xframeoptions_check(req: List[str]) -> List[str]:
    # This is obsoleted for supporting browsers, but not everywhere yet.
    # https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
    xfo_lines = head_filter(req, 'X-Frame-Options')
    if xfo_lines:
        return ['fail', 'Deprecated X-Frame-Options headers found']
    else:
        return ['pass', 'No X-Frame-Options header found; check CSP']
    
def xcontenttypeoptions_check(req):
    xcto_lines = head_filter(req, 'X-Content-Type-Options')
    if xcto_lines:
        for line in xcto_lines:
            value = (line.split(':')[1]).strip()
            if 'nosniff' not in value:
                return ['fail', f'X-Content-Type-Options set to {value}']
        return ['pass']
    else:
        return ['fail', 'No X-Content-Type-Options header found']

def xxssprotection_check(req):
    xxp_lines = head_filter(req, 'X-XSS-Protection')
    if xxp_lines:
        # You oughtn't have it unless your client has really outdated browsers. See https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection
        return ['fail', 'Outdated X-XSS-Protection headers found']
    else:
        return ['pass', 'No X-XSS-Protection headers found']
    
def permissionspolicy_check(req):
    pp_lines = head_filter(req, 'Permissions-Policy')
    if pp_lines:
        pp_contrast = set()
        pp_contrast = {'accelerometer=()', 'ambient-light-sensor=()', 'autoplay=()',\
                       'battery=()', 'camera=()', 'cross-origin-isolated=()',\
                        'display-capture=()', 'document-domain=()', 'encrypted-media=()',\
                        'execution-while-not-rendered=()',\
                        'execution-while-out-of-viewport=()', 'fullscreen=()',\
                        'geolocation=()', 'gyroscope=()', 'keyboard-map=()',\
                        'magnetometer=()', 'microphone=()', 'midi=()',\
                        'navigation-override=()', 'payment=()', 'picture-in-picture=()',\
                        'publickey-credentials-get=()', 'screen-wake-lock=()', 'sync-xhr=()',\
                        'usb=()', 'web-share=()', 'xr-spatial-tracking=()'}
        for line in pp_lines:
            values = (line.split(':')[1]).strip()
            ind = set(map(lambda x: x.strip(), values.split(',')))
            diff = pp_contrast.difference(ind)
            if diff:
                return ['fail', f'Permissions-Policy missing {" ".join(list(diff))}']
        return ['pass']
    else:
        return ['fail', 'No Permissions Policy headers found']

def cachecontrol_check(req):
    cc_lines = head_filter(req, 'Cache-Control')
    if cc_lines:
        for line in cc_lines:
            values = (line.split(':')[1]).strip()
            # Has to be both 'no-cache' and 'private'. See https://developer.mozilla.org/en-US/docs/Web/HTTP/Caching#dealing_with_outdated_implementations
            if not 'no-cache' in values.lower() and not 'private' in values.lower():
                return ['fail', f'Cache headers set to {values}']
        return ['pass']    
    else:
        return ['uncertain', 'No Cache-Control headers found']

def referrerpolicy_check(req):
    rp_lines = head_filter(req, 'Referrer-Policy')
    if rp_lines:
        for line in rp_lines:
            if 'unsafe' in (line.strip()).lower():
                return ['fail', f'Referrer-Policy set to {(line.split(":")[1]).strip()}']
        return ['pass', f'Referrer-Policy set to {(line.split(":")[1]).strip()}']
    else:
        # Omitting the header defaults to a secure option: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy
        return ['pass', "Headers omitted"]

def contentsecuritypolicy_check(req):
    # Currently allows for Content-Security-Report-Only too. The tester has to check this when viewing the report.
    csp_lines = head_filter(req, 'Content-Security-Policy')
    if csp_lines:
        values = '\n'.join(csp_lines)
        return ['uncertain', f'Content security policy set to {values}']
    else:
        return ['fail', 'No Content Security Policy found']

def parse(f):
    tree = ET.parse(f)
    root = tree.getroot()
    finale = {}
    for item in root:
        url = item.find('url').text
        response = item.find('response').text
        method = item.find('method').text
        if not response or method == "OPTIONS":
            continue
        raw_req = b64.b64decode(response)
        req = (raw_req.decode(errors="ignore")).split('\r\n')

        headers = []
        for line in req:
            if not line:
                break
            else:
                headers.append(line)

        results = {}

        results['hsts'] = hsts_check(headers)
        results['x-frame-options'] = xframeoptions_check(headers)
        results['x-content-type-options'] = xcontenttypeoptions_check(headers)
        results['x-xss-protection'] = xxssprotection_check(headers)
        results['permissions-policy'] = permissionspolicy_check(headers)
        results['cache-control'] = cachecontrol_check(headers)
        results['referrer-policy'] = referrerpolicy_check(headers)
        results['content-security-policy'] = contentsecuritypolicy_check(headers)

        # OPTIONS doesn't need the other headers
        if method == "OPTIONS":
            for key in results.keys():
                if key == 'hsts':
                    pass
                else:
                    results[key] = ['pass']

        # This will overwrite duplicate entries. Sounds logical right now, but
        # keep it in mind.
        url = url.split('?')[0]
        finale[url] = results
    return finale

def parse_md():
    vkb = {}
    with open(Path(__file__).with_name("vkb.md"), 'r') as f:
        header = ""
        content = []
        for line in f:
            line = line.strip()
            if not line:
                continue
            elif line.startswith("# "):
                if header and content:
                    vkb[header] = content
                    header = line[2:]
                    content = []
                else:
                    header = line[2:]
            elif line.startswith("## "):
                if header and content:
                    vkb[header] = content
                    header = line[3:]
                    content = []
                else:
                    header = line[3:]
            else:
                content.append(line)
        vkb[header] = content
    return vkb

def to_html(vkb, table):
    code_blocks = re.compile(r"`(.*)`", flags=re.MULTILINE)
    li = re.compile(r"^\s?- (.+)$", flags=re.MULTILINE)
    href = re.compile(r"(https://\S*)", flags=re.MULTILINE)
    results = {}
    sections = ["Summary", "Background", "Recommendations", "Further Reading"]

    for key in vkb.keys():
        if key in sections:
            header = key
            lines = []
            for line in vkb[key]:
                line = code_blocks.sub(r"&lt;code&gt;\1&lt;/code&gt;", line)
                line = li.sub(r"&lt;li&gt;\1&lt;/li&gt;", line)
                line = href.sub(r'&lt;a href="\1"&gt;\1&lt;/a&gt;', line)
                lines.append(line)
            results[header] = lines
        else:
            lines = [f"&lt;b&gt;{key}&lt;/b&gt;"]
            for line in vkb[key]:
                line = code_blocks.sub(r"&lt;code&gt;\1&lt;/code&gt;", line)
                line = li.sub(r"&lt;li&gt;\1&lt;/li&gt;", line)
                line = href.sub(r'&lt;a href="\1"&gt;\1&lt;/a&gt;', line)
                lines.append(line)
            results["Background"].extend(lines)
    
    for key in results.keys():
        for i in range(len(results[key])):
            line = results[key][i]
            if line.startswith("<h1>") or line.startswith("&lt;li&gt;"):
                continue
            else:
                results[key][i] = f"&lt;p&gt;{line}&lt;/p&gt;"

    results["Further Reading"][0] = f"&lt;ul&gt;{results['Further Reading'][0]}"
    results["Further Reading"][1] = f"{results['Further Reading'][1]}"
    results["Background"].append(table)

    finale = {}

    for key in results.keys():
        finale[key] = '\n'.join(results[key])
    
    return finale

def report(results, component_table):
    report = {
        'hsts': True, 'x-frame-options': True, 'x-content-type-options': True, 'x-xss-protection': True,\
        'permissions-policy': True, 'referrer-policy': True, 'cache-control': True, 'content-security-policy': True
    }

    translation = {
        'hsts': 'HTTP Strict Transport Security (HSTS)', 'x-frame-options': 'Clickjacking', 'x-content-type-options': 'Content Sniffing', 'x-xss-protection': 'X-XSS-Protection',\
        'permissions-policy': 'Permissions Policy', 'referrer-policy': 'Referrer Policy', 'cache-control': 'Cacheable HTTPS Response', 'content-security-policy': 'Content Security Policy (CSP)'
    }

    rec_translation = {
        'hsts': ['Strict', 'HSTS'], 'x-frame-options': ['X-Frame-Options'], 'x-content-type-options': ['X-Content-Type-Options'], 'x-xss-protection': ['X-XSS-Protection'],\
        'permissions-policy': ['Permissions'], 'referrer-policy': ['Referrer'], 'cache-control': ['Cache'], 'content-security-policy': ['Content']
    }

    for key in results.keys():
        temp = results[key]
        for key2 in temp.keys():
            if temp[key2][0] == "fail" or temp[key2][0] == "uncertain":
                report[key2] = False
    
    if all(report.values()):
        return {}

    vkb = parse_md()
    reading = vkb['Further Reading']
    for key in report.keys():
        if report[key]:
            vkb.pop(translation[key])
            for v in rec_translation[key]:
                reading = list(filter(lambda x: not x.startswith(f"- {v}"), reading))
    vkb['Further Reading'] = reading

    return to_html(vkb, component_table)

def cache_report(report):
    passed = []
    failed = []

    for k in report.keys():
        # We don't need to worry about JavaScript and Cascading Style Sheets.
        stripped_url = k.split('?')[0]
        file_endings = ['js', 'gif', 'jpg', 'png', 'css', 'woff2', 'woff']
        if any([stripped_url.endswith(x) for x in file_endings]):
            continue
        elif report[k]['cache-control'][0] == 'pass':
            passed.append(k)
        else:
            failed.append(k)
    
    results = {
        'passed': passed,
        'failed': failed
    }

    return results

def csp_report(report):
    result = {}
    for k in report.keys():
        if report[k]['content-security-policy'][0] == "uncertain":
            values = report[k]['content-security-policy'][1][31:]
            result[values] = result.get(values, []) + [k]
    return result

def print_results(output, client=""):
    ok = (' ' * 12) + '\u001b[32mOK\x1b[0m'
    nok = (' ' * 8) + '\u001b[31mNOT OK\x1b[0m'
    mok = '\u001b[33mPOTENTIALLY NOT OK\x1b[0m'

    if client:
        print(f"\u001b[33mSecurity header analysis for {client}:\x1b[0m")
    else:
        print("\u001b[33mSecurity header analysis:\x1b[0m")

    for key in output.keys():
        print(f"\n\u001b[33m--> {key}:\x1b[0m")
        secure = output[key]
        if secure['hsts']:
            print(f"{'Secure Transport Security':<30}: {ok}")
        else:
            print(f"{'Secure Transport Security':<30}: {nok}")
        if secure['x-frame-options']:
            print(f"{'X-Frame-Options':<30}: {ok}")
        else:
            print(f"{'X-Frame-Options':<30}: {nok}")
        if secure['x-content-type-options']:
            print(f"{'X-Content-Type-Options':<30}: {ok}")
        else:
            print(f"{'X-Content-Type-Options':<30}: {nok}")
        if secure['content-security-policy']:
            print(f"{'Content-Security-Policy':<30}: {ok}")
        else:
            print(f"{'Content-Security-Policy':<30}: {nok}")
        if secure['x-xss-protection']:
            print(f"{'X-XSS-Protection':<30}: {ok}")
        else:
            print(f"{'X-XSS-Protection':<30}: {nok}")
        if secure['permissions-policy']:
            print(f"{'Permissions-Policy':<30}: {ok}")
        else:
            print(f"{'Permissions-Policy':<30}: {nok}")
        if secure['referrer-policy']:
            print(f"{'Referrer-Policy':<30}: {ok}")
        else:
            print(f"{'Referrer-Policy':<30}: {nok}")
        if secure['cache-control']:
            print(f"{'Cache-Control':<30}: {ok}")
        else:
            print(f"{'Cache-Control':<30}: {nok}")

def restructure_domains(results):
    urls = sorted(list(results.keys()))
    domains = {}
    for url in urls:
        root = urlparse(url).netloc
        
        if domains.get(root, False):
            domains[root][url] = results[url]
        else:
            domains[root] = {url: results[url]}
    return domains

def component_table(output):
    table_data = {}
    for domain in output:
        table_data[domain] = []
        secure = output[domain]
        if not secure['hsts']:
            table_data[domain].append('Secure Transport Security')
        
        if not secure['x-frame-options']:
            table_data[domain].append('X-Frame-Options')
        
        if not secure['x-content-type-options']:
            table_data[domain].append('X-Content-Type-Options')
        
        if not secure['content-security-policy']:
            table_data[domain].append('Content-Security-Policy')
        
        if not secure['x-xss-protection']:
            table_data[domain].append('X-XSS-Protection')
        
        if not secure['permissions-policy']:
            table_data[domain].append('Permissions-Policy')
        
        if not secure['referrer-policy']:
            table_data[domain].append('Referrer-Policy')
        
        if not secure['cache-control']:
            table_data[domain].append('Cache-Control')
    
    result = ["&lt;p&gt;&lt;b&gt;Affected Components&lt;/p&gt;&lt;/b&gt;&lt;ul&gt;"]
    for key in table_data.keys():
        result.append(f"&lt;li&gt;{key}&lt;/li&gt;&lt;ul&gt;")
        for item in table_data[key]:
            result.append(f"&lt;li&gt;{item}&lt;/li&gt;")
        result.append("&lt;/ul&gt;")
    result.append("&lt;/ul&gt;")
    return '\n'.join(result)
        
def print_samurai(bow=True):
    samurai = """\u001b[32m
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
░░░░░░░░░░░░░░░░░▓▓▓▓▒░░░░░░░░░░░░░░░░░░░░▒▓▓▓▓▒░░░░░░░░░░░░░░░░
░░░░░░░░░░░░░░░░░░▓▓▓▓▓▒░░░░░░░░░░░░░░░░▒▓▓▓▓▓▒░░░░░░░░░░░░░░░░░
░░░░░░░░░░░░░░░░░░▒▓▓▓▓▓▓▓░░░░░░░░░░░░▒▓▒▓▓▓▓▒░░░░░░░░░░░░░░░░░░
░░░░░░░░░░░░░░░░░░░▓▓▓▓▓▓▓▓▓░░░░░░░▒▓▓▓▓▓▓▓▓▓░░░░░░░░░░░░░░░░░░░
░░░░░░░░░░░░░░░░░░░▓▓▓▓▓▓▓▒▒▒░░░░░░▒▓▓▓▓▓▓▓▓▓░░░░░░░░░░░░░░░░░░░
░░░░░░░░░░░░░░░░░░░▓▓▓▓▓▒░░░░░░░░░░░░░░▓▓▓▓▓▓░░░░░░░░░░░░░░░░░░░
░░░░░░░░░░░░░░░░░░░▓▓▓▓▒░░░░░░░░░░░░░░░░▓▓▓▓▒░░░░░░░░░░░░░░░░░░░
░░░░░░░░░░░░░░░░░░░▓▓▓▓░░░░░░░░░░░░░░░░░▓▓▓▓▒░░░░░░░░░░░░░░░░░░░
░░░░░░░░░░░░░░░░░░░▒▓▓▓░░░▒▒▒▒▓█▓█▓▒▒▒░░▒▓▓▓░░░░░░░░░░░░░░░░░░░░
░░░░░░░░░░░░░░░░░░░▒▓▓▓▒▓████▓▓▓▓▓▓█████▓▓▓▓░░░░░░░░░░░░░░░░░░░░
░░░░░░░░░░░░░░░░░░░░▓▓▓▓███▓▓▓▓▓▓▓▓▓▓██▓▓▓▓▒░░░░░░░░░░░░░░░░░░░░
░░░░░░░░░░░░░░░░░░░░▓▓▓▓█▓▓▓▓▓▓▓▓▓▓▓▓▓█▓▓▓▓▒░░░░░░░░░░░░░░░░░░░░
░░░░░░░░░░░░░░░░░░░░▓▓▓▓▓█▓▓▓▓▓▒▓▓▓▓▓▓▓▓▓▓▓▓░░░░░░░░░░░░░░░░░░░░
░░░░░░░░░░░░░▓▓▓▓▓▓▓█▓▓▓▓▓▓▓▓▓▓▒▓▓▓▓▓▓▓▓▓▓██▓▒▒░░░░░░░░░░░░░░░░░
░░░░░░░░░░░░░▒▓▓▒▓▓▓█▓▓▓▓▓▓▓▓▓▓▒▓▓▓▓▓▓▓▓▓▓██▓▓▓▓▓▓▓▒░░░░░░░░░░░░
░░░░░░░░░░░░░░▒▒▒▒▒▒▓█▓▓▓▓▒▒▒▒▒▒▒▒▒▒▓▒▓▓▓███▓▓▒▒▓▓▒░░░░░░░░░░░░░
░░░░░░░░░░░░░░░▒▒▒▒▓█▓██▓▓▓▓▒▒▒▒▒▒▒▒▓▓▓██▓▓▓▓▓▒▒▒▒░░░░░░░░░░░░░░
░░░░░░░░░░░░░░▒█▓▓██▓▓▓▓▓▓▓▓▓▓▒▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▓▒░░░░░░░░░░░░░░
░░░░░░░░░░░░░▓▓██████▓▓▓▓▓▓▓▓▒▒▒▒▒▒▓▓▓▓▓▓▓▓█████▓▓▒░░░░░░░░░░░░░
░░░░░░░░░░░░▓▓██████████████▓▓▓▓▓▓▓▓▓████████████▓▓▓░░░░░░░░░░░░
░░░░░░░░░░▒▓▓█████████████████▓▓▓█████████████████▓▓▓░░░░░░░░░░░
░░░░░░░░░▒▓▓████▓▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▓▓▓▓██████▓▓▓▒░░░░░░░░░
░░░░░░░░░▒▒▒░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▒▒▓▓▓░░░░░░░░░
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
    """
    names = ["夜叉", "YASHA", "やしゃ"]
    version = "0.b"
    print(f"{samurai:^45}")
    print(f"{random.choice(names)+' '+version:^64s}\x1b[0m\n")

def yasha(burp_file, log=False):
    parcel = {}

    with open(burp_file, 'r') as f:
        original_results = parse(f)

    domains = restructure_domains(original_results)

    if log:
        parcel['log']= json.dumps(original_results)

    output = {}

    for domain in domains.keys():
        secure = {
            'hsts': True, 'x-frame-options': True, 'x-content-type-options': True, 'x-xss-protection': True,\
            'permissions-policy': True, 'referrer-policy': True, 'cache-control': True, 'content-security-policy': True
        }

        entry = domains[domain]
        for key in entry.keys():
            temp = entry[key]
            for key2 in temp.keys():
                if temp[key2][0] != "pass":
                    secure[key2] = False
        
        results = domains[domain]
        print(f"Analysing \u001b[34m{domain}\x1b[0m")
            
        cache_results = cache_report(results)
        if cache_results['failed'] or cache_results['passed']:
            print("\t\u001b[33mDo the right URL endpoints have caching headers according to the following?\x1b[0m")
            if len(cache_results['passed']) + len(cache_results['failed']) > 10:
                page = ["<h1 style='color:green'>Cache Headers OK:</h1><ul>"]
                for entry in cache_results['passed']:
                    page.append(f"<li>{entry}</li>")
                page.append('</ul><h1 style="color:red">Cache Headers NOT OK</h1>')
                for entry in cache_results['failed']:
                    page.append(f"<li>{entry}</li>")
                page.append("</ul>")
                with open("cache_report.htm", 'w') as f:
                    f.write(''.join(page))
                print("\tA large number of URLs noted. Check cache_report.htm.")
            else:
                print("\u001b[32mCache Headers OK:\x1b[0m")
                for item in cache_results['passed']:
                    print(f"\t{item}")       
                print("\u001b[31mCache Headers NOT OK:\x1b[0m")
                for item in cache_results['failed']:
                    print(f"\t{item}")
            while True:
                try:
                    answer = input("\t[y/n] > ")[0].lower()
                except IndexError:
                    continue
                
                if answer == 'y':
                    secure['cache-control'] = True
                    break
                elif answer == 'n':
                    secure['cache-control'] = False
                    break
                else:
                    continue
    
        # It's a direct fail if some pages don't have it. Will be 'fail' in this case,
        # and 'uncertain' otherwise.
        if not all([results[key]['content-security-policy'][0] != 'fail' for key in results.keys()]):
            pass
        else:
            csp_results = csp_report(results)
            if csp_results:
                page = []
                for (i, k) in enumerate(csp_results.keys()):
                    page.append("<head><style>a, a:visited { color: red}</style></head>")
                    page.append(f"<h1>CSP Value #{i}</h1><h2>CSP Value</h2>")
                    page.append(f"<h2>{k.split(':')[0]}</h2><ul>")
                    values = list(map(lambda x: x.strip(), (k.split(':')[1]).split(';')))
                    for v in values:
                        page.append(f"<li>{v}</li>")
                    page.append(f'</ul><a href="https://csp-evaluator.withgoogle.com/?csp={";".join(values)}" target="_blank">Check in Google\'s CSP Evaluator (Warning: external site)</a>')
                    page.append("<h2>URLs</h2><ul>")
                    urls = csp_results[k]
                    for u in urls:
                        page.append(f"<li>{u}</li>")
                    page.append('</ul><script>window.matchMedia&&window.matchMedia("(prefers-color-scheme: dark)").matches&&(document.body.style.color="#ddd",document.body.style.background="#011"),window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change",d=>{let e=d.matches?"dark":"light";"dark"==e?(document.body.style.color="#ddd",document.body.style.background="#011"):(document.body.style.color="#000",document.body.style.background="#fff")});</script>')
                with open("csp_report.htm", 'w') as f:
                            f.write(''.join(page))
                print("\t\u001b[33mAre the CSP headers secure in csp_report.htm?\x1b[0m")
                while True:
                        try:
                            answer = input("\t[y/n] > ")[0].lower()
                        except IndexError:
                            continue
                        
                        if answer == 'y':
                            secure['content-security-policy'] = True
                            break
                        elif answer == 'n':
                            secure['content-security-policy'] = False
                            break
                        else:
                            continue

        output[domain] = secure
    
    parcel['output'] = output
    parcel['report'] = ''.join([f'\n\n<h1>{x[0]}</h1>\n\n{x[1]}' for x in (report(original_results, component_table=component_table(output))).items()])
    js = '<script>window.matchMedia&&window.matchMedia("(prefers-color-scheme: dark)").matches&&(document.body.style.color="#ddd",document.body.style.background="#011"),window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change",d=>{let e=d.matches?"dark":"light";"dark"==e?(document.body.style.color="#ddd",document.body.style.background="#011"):(document.body.style.color="#000",document.body.style.background="#fff")});</script>'
    parcel['report'] = parcel['report'] + js

    return(parcel)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="Yasha",
        description="Yet Another Security Header Analyser"
    )
    parser.add_argument('-f', '--file', action='store', required=True, help="Burp exported requests/responses.")
    parser.add_argument('-c', '--client', action='store', help="Optional client name for display for screenshot.")
    parser.add_argument('-l', '--log', action="store_true", help="Write a JSON log.")
    args = parser.parse_args()

    print_samurai(bow=True)

    parcel = yasha(args.file, log=args.log)

    with open('reporting.htm', 'w') as f:
        f.write(parcel['report'])
        print("\n\n\u001b[33mReporting output written to reporting.htm\x1b[0m\n")

    if 'log' in parcel:
        with open('yasha_log.json', 'w') as f:
            f.write(parcel['log'])
            print("\u001b[33mLogs written to yasha_log.json\x1b[0m")
    print_results(parcel['output'], client=args.client)