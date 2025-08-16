import os
import asyncio
from flask import Flask, request, jsonify, g, Response, send_file, session
from supabase import create_client, Client
from dotenv import load_dotenv
import vt
import County_Codes
from functools import wraps
import secrets
import string
import requests
from datetime import datetime, timezone, timedelta
from flask_cors import CORS
from pathlib import Path
import subprocess
import re
import platform
import threading
import time
import geoip2.database
import tarfile
import csv
import dns.resolver
import dns.reversename
import io
import feedparser

# .env 파일의 절대 경로를 명시적으로 지정
env_path = Path(__file__).resolve().parent / '.env'
load_dotenv(dotenv_path=env_path)

# Flask 앱 생성
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

# CORS 설정
CORS(
    app,
    origins=["https://vt.openpesto.com", "http://localhost:3000"],
    supports_credentials=True,
    expose_headers=['Content-Disposition']
)

# Supabase 클라이언트 초기화
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
supabase_admin = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)

# MaxMind 라이선스 키 및 MMDB 파일 경로 설정
MAXMIND_LICENSE_KEY = os.getenv("MAXMIND_LICENSE_KEY")
MMDB_PATH = Path(__file__).resolve().parent / 'GeoLite2-Country.mmdb'
mmdb_ready_event = threading.Event()

# ===================================================================
# Helper Functions & Decorators
# ===================================================================
def get_supabase_client_from_token(access_token):
    """토큰으로 Supabase 클라이언트를 생성하고 사용자 정보를 반환합니다."""
    if not access_token:
        return None, None
    try:
        auth_supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
        user_response = auth_supabase.auth.get_user(access_token)
        if user_response.user:
            return auth_supabase, user_response.user.id
        return None, None
    except Exception as e:
        print(f"Supabase client authentication error: {e}")
        return None, None

def login_required(f):
    """
    요청 쿠키의 access_token을 확인하고, 유효하면 Flask의 g 객체에
    인증된 supabase 클라이언트와 user_id를 저장합니다.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        access_token = request.cookies.get('access_token')
        if not access_token:
            return jsonify({"error": "No access token provided"}), 401
        
        auth_supabase, user_id = get_supabase_client_from_token(access_token)
        if not auth_supabase or not user_id:
            return jsonify({"error": "Invalid or expired token"}), 401
        
        auth_supabase.postgrest.auth(access_token)
        
        g.auth_supabase = auth_supabase
        g.user_id = user_id
        
        return f(*args, **kwargs)
    return decorated_function

def login_required_session(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # 쿠키 대신 Flask 세션에 'user'가 있는지 직접 확인합니다.
        if 'user' not in session:
            return jsonify(success=False, message="로그인이 필요합니다."), 401
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """login_required가 먼저 실행된 후, g.user_id를 사용하여 관리자 권한을 확인합니다."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = getattr(g, 'user_id', None)
        if not user_id:
             return jsonify(success=False, message="인증 정보가 없습니다."), 401

        try:
            profile = supabase_admin.table('profiles').select('is_admin').eq('id', user_id).single().execute().data
            if not profile or not profile.get('is_admin'):
                return jsonify(success=False, message="관리자 권한이 필요합니다."), 403
        except Exception as e:
            return jsonify(success=False, message=f"권한 확인 중 오류 발생: {e}"), 500
            
        return f(*args, **kwargs)
    return decorated_function


def generate_temp_password(length=12):
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(secrets.choice(alphabet) for i in range(length))

async def get_ip_info(client, ip):
    result = {'country': '', 'as_owner': '', 'malicious': ''}
    try:
        ip_info = await client.get_object_async(f"/ip_addresses/{ip}")
        attributes = ip_info.to_dict().get('attributes', {})
        country_code = attributes.get('country')
        if country_code:
            result['country'] = County_Codes.country_code_to_korean.get(country_code, country_code)
        result['malicious'] = str(attributes.get('last_analysis_stats', {}).get('malicious', 0))
        result['as_owner'] = attributes.get('as_owner', 'N/A')
    except Exception as e:
        print(f"Error fetching data for IP {ip}: {e}")
        result = {key: 'Error' for key in result}
    return result

# ===================================================================
# 백그라운드 작업
# ===================================================================
def get_status_color(status_code):
    if 200 <= status_code < 300: return 'green'
    elif 300 <= status_code < 400 or 500 <= status_code < 600: return 'orange'
    else: return 'red'

def check_websites_status():
    try:
        websites = supabase_admin.table('health_check_websites').select('id, url').execute().data
        for site in websites:
            status_color, status_code = 'red', None
            try:
                headers = {'User-Agent': 'NEXTVT-Health-Checker/1.0'}
                response = requests.get(site['url'], timeout=5, allow_redirects=True, headers=headers)
                status_code, status_color = response.status_code, get_status_color(response.status_code)
            except requests.exceptions.RequestException:
                status_code = 500
            supabase_admin.table('health_check_websites').update({
                'status_color': status_color, 'status_code': status_code, 'last_checked': datetime.now(timezone.utc).isoformat()
            }).eq('id', site['id']).execute()
    except Exception as e:
        print(f"An error occurred in check_websites_status: {e}")

def run_health_checks():
    while True:
        print("Running website health checks...")
        check_websites_status()
        time.sleep(60)

def download_mmdb_file():
    if not MAXMIND_LICENSE_KEY:
        print("Warning: MAXMIND_LICENSE_KEY is not set.")
        mmdb_ready_event.set()
        return
    download_url = f"https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key={MAXMIND_LICENSE_KEY}&suffix=tar.gz"
    while True:
        try:
            print("Downloading GeoLite2-Country.mmdb file...")
            temp_tar_path = MMDB_PATH.with_suffix('.tar.gz')
            with requests.get(download_url, stream=True, timeout=60) as r:
                r.raise_for_status()
                with open(temp_tar_path, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=8192): f.write(chunk)
            with tarfile.open(temp_tar_path, "r:gz") as tar:
                for member in tar.getmembers():
                    if member.name.endswith('.mmdb'):
                        member.name = os.path.basename(member.name)
                        tar.extract(member, path=Path(__file__).resolve().parent)
                        extracted_path = Path(__file__).resolve().parent / member.name
                        if extracted_path.exists(): extracted_path.rename(MMDB_PATH)
                        break
            os.remove(temp_tar_path)
            print("MMDB file downloaded and extracted successfully.")
            mmdb_ready_event.set()
        except Exception as e:
            print(f"Failed to download MMDB file: {e}")
            mmdb_ready_event.set()
        time.sleep(86400)

def get_country_from_mmdb(ip, reader):
    if not reader: return None
    try:
        response = reader.country(ip)
        return County_Codes.country_code_to_korean.get(response.country.iso_code, response.country.iso_code)
    except geoip2.errors.AddressNotFoundError: return "N/A"
    except Exception: return None

def fetch_malicious_ips_from_github():
    mmdb_ready_event.wait()
    if not MMDB_PATH.exists(): return
    file_url = "https://raw.githubusercontent.com/romainmarcoux/malicious-ip/main/full-40k.txt"
    source_name = "Multiple Sources (romainmarcoux/malicious-ip)"
    reader = None
    try:
        reader = geoip2.database.Reader(MMDB_PATH)
        response = requests.get(file_url, timeout=20)
        response.raise_for_status()
        ip_list = response.text.strip().split('\n')
        all_indicators = []
        current_time = datetime.now(timezone.utc).isoformat()
        for ip in ip_list:
            if ip.strip() and not ip.startswith('#'):
                country = get_country_from_mmdb(ip.strip(), reader)
                if country:
                    all_indicators.append({'value': ip.strip(),'type': 'ipv4','source': source_name,'description': 'Malicious IP from public feed','country': country,'added_at': current_time})
        if all_indicators:
            supabase_admin.table('cti_indicators').upsert(all_indicators, on_conflict='value', ignore_duplicates=True).execute()
            print(f"Successfully processed {len(all_indicators)} indicators from GitHub.")
    except Exception as e:
        print(f"An error occurred in fetch_malicious_ips_from_github: {e}")
    finally:
        if reader: reader.close()

def run_cti_updates():
    print("Performing initial CTI data fetch...")
    fetch_malicious_ips_from_github()
    while True:
        time.sleep(3600)
        print("Running CTI data updates...")
        fetch_malicious_ips_from_github()

# ===================================================================
# API Routes
# ===================================================================

@app.route('/api/dashboard/ip', methods=['GET'])
def get_user_ip():
    ip = request.headers.getlist("X-Forwarded-For")[0] if request.headers.getlist("X-Forwarded-For") else request.remote_addr
    return jsonify(ip=ip)

@app.route('/api/dashboard/memo', methods=['GET', 'POST'])
@login_required
def handle_memo():
    auth_supabase, user_id = g.auth_supabase, g.user_id
    
    if request.method == 'GET':
        response = auth_supabase.table('dashboard_memos').select('content').eq('user_id', user_id).maybe_single().execute()
        content = response.data.get('content', '') if response and response.data else ''
        return jsonify(content=content)

    if request.method == 'POST':
        content = request.json.get('content', '')
        auth_supabase.table('dashboard_memos').upsert(
            {'user_id': user_id, 'content': content}, 
            on_conflict='user_id'
        ).execute()
        return jsonify(success=True)

@app.route('/api/dashboard/bookmarks', methods=['GET', 'POST'])
@login_required
def handle_bookmarks():
    auth_supabase, user_id = g.auth_supabase, g.user_id
    if request.method == 'GET':
        data = auth_supabase.table('dashboard_bookmarks').select('*').eq('user_id', user_id).order('id').execute()
        return jsonify(data.data)
    if request.method == 'POST':
        data = request.json
        new_bookmark = auth_supabase.table('dashboard_bookmarks').insert({'user_id': user_id, 'name': data['name'], 'url': data['url']}).execute()
        return jsonify(new_bookmark.data[0])

@app.route('/api/dashboard/bookmarks/<int:bookmark_id>', methods=['PUT', 'DELETE'])
@login_required
def handle_single_bookmark(bookmark_id):
    auth_supabase, user_id = g.auth_supabase, g.user_id
    if request.method == 'PUT':
        data = request.get_json()
        if not data or 'name' not in data or 'url' not in data:
            return jsonify({"error": "Missing name or url"}), 400
        
        update_response = auth_supabase.table('dashboard_bookmarks').update({
            'name': data['name'], 'url': data['url']
        }).eq('id', bookmark_id).eq('user_id', user_id).execute()

        if update_response.data:
            return jsonify(update_response.data[0])
        return jsonify({"error": "Bookmark not found or permission denied"}), 404

    if request.method == 'DELETE':
        auth_supabase.table('dashboard_bookmarks').delete().eq('id', bookmark_id).eq('user_id', user_id).execute()
        return jsonify(success=True)

@app.route('/api/dashboard/kisa-rss', methods=['GET'])
@login_required
def get_kisa_rss():
    feed_url = "https://www.boho.or.kr/kr/rss.do?bbsId=B0000133"
    try:
        feed = feedparser.parse(feed_url)
        entries = [{'title': e.title, 'link': e.link, 'published': e.published} for e in feed.entries[:10]]
        return jsonify(entries)
    except Exception as e:
        return jsonify({"error": f"RSS 피드를 가져오는 중 오류 발생: {e}"}), 500

@app.route('/api/yara', methods=['POST'])
@login_required
def generate_yara_rule():
    data = request.get_json()
    rule_name = data.get('ruleName') or 'MyRule'
    author = data.get('author') or 'N/A'
    description = data.get('description') or 'No description provided.'
    reference = data.get('reference') or 'N/A'
    strings = data.get('strings', [])
    condition = data.get('condition')

    if not strings:
        return jsonify(success=False, message="하나 이상의 문자열을 추가해야 합니다."), 400

    meta_section = f"""
    meta:
        author = "{author}"
        description = "{description}"
        reference = "{reference}"
        date = "{datetime.now().strftime('%Y-%m-%d')}"
    """
    strings_section_lines = []
    for i, s in enumerate(strings):
        str_id = f"$s{i+1}"
        if s.get('type') == 'hex':
            hex_value = ''.join(s.get('value', '').split())
            strings_section_lines.append(f'        {str_id} = {{ {hex_value} }}')
        else:
            escaped_value = s.get('value', '').replace('\\', '\\\\').replace('"', '\\"')
            strings_section_lines.append(f'        {str_id} = "{escaped_value}" ascii wide')
    strings_section = "    strings:\n" + "\n".join(strings_section_lines)
    condition_expression = "all of them" if condition == 'all' else "any of them"
    condition_section = f"    condition:\n        {condition_expression}"
    full_rule = f"""rule {rule_name}
{{{meta_section}
{strings_section}

{condition_section}
}}"""
    return jsonify(success=True, rule=full_rule)

@app.route('/api/cti/report', methods=['GET'])
@login_required
def get_cti_report():
    try:
        ips = supabase_admin.table('cti_indicators').select('value, country').eq('type', 'ipv4').order('added_at', desc=True).limit(198).execute().data
        domains = supabase_admin.table('cti_indicators').select('value, country').eq('type', 'domain').order('added_at', desc=True).limit(2).execute().data
        report_data = [['URL', '공격 IP', '공격국가']]
        for ip in ips: report_data.append(['', ip['value'], ip['country']])
        for domain in domains: report_data.append([domain['value'], '', domain.get('country') or '미국'])
        si = io.StringIO()
        cw = csv.writer(si)
        cw.writerows(report_data)
        output = si.getvalue().encode('utf-8-sig')
        mem = io.BytesIO(output)
        mem.seek(0)
        filename = f"{datetime.now().strftime('%y%m%d')}_악성IP&URL.csv"
        return send_file(mem, as_attachment=True, download_name=filename, mimetype='text/csv')
    except Exception as e:
        return jsonify(success=False, message=f"보고서 생성 중 오류 발생: {e}"), 500

@app.route('/api/dnslookup', methods=['POST'])
@login_required
def dns_lookup():
    domain = request.get_json().get('domain')
    if not domain: return jsonify(success=False, message="도메인을 입력해주세요."), 400
    results, reader = {}, None
    if MMDB_PATH.exists(): reader = geoip2.database.Reader(MMDB_PATH)
    for r_type in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']:
        try:
            answers = dns.resolver.resolve(domain, r_type)
            records = []
            for rdata in answers:
                if r_type == 'A': records.append({'ip': rdata.to_text(), 'country': get_country_from_mmdb(rdata.to_text(), reader)})
                elif r_type == 'MX': records.append(f"{rdata.preference} {rdata.exchange}")
                else: records.append(rdata.to_text())
            results[r_type] = records
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN): results[r_type] = []
        except Exception as e: results[r_type] = [f"오류: {e}"]
    if reader: reader.close()
    return jsonify(success=True, data=results)

@app.route('/api/reversedns', methods=['POST'])
@login_required
def reverse_dns_lookup():
    ip = request.get_json().get('ip')
    if not ip: return jsonify(success=False, message="IP 주소를 입력해주세요."), 400
    try:
        addr = dns.reversename.from_address(ip)
        domain = str(dns.resolver.resolve(addr, "PTR")[0]).rstrip('.')
        return jsonify(success=True, data=domain)
    except Exception as e:
        return jsonify(success=False, message=f"조회 중 오류 발생: {e}")

@app.route('/api/cti', methods=['GET'])
@login_required
def get_cti_data():
    try:
        page, limit = int(request.args.get('page', 1)), int(request.args.get('limit', 100))
        offset = (page - 1) * limit
        query = supabase.table('cti_indicators').select('*', count='exact').order('added_at', desc=True)
        if request.args.get('type', 'all') != 'all':
            query = query.eq('type', request.args.get('type'))
        result = query.range(offset, offset + limit - 1).execute()
        return jsonify(success=True, data=result.data, total=result.count)
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500

@app.route('/api/healthcheck', methods=['GET'])
@login_required
def get_health_check_data():
    try:
        categories = supabase.table('health_check_categories').select('*').order('id').execute().data
        websites = supabase.table('health_check_websites').select('*').order('id').execute().data
        last_checked_time = None
        if websites:
            last_checked_times = [datetime.fromisoformat(w['last_checked']) for w in websites if w['last_checked']]
            if last_checked_times: last_checked_time = max(last_checked_times).astimezone(timezone(timedelta(hours=9))).strftime('%Y. %m. %d. %p %I:%M:%S')
        result = []
        for category in categories:
            category['websites'] = [site for site in websites if site['category_id'] == category['id']]
            result.append(category)
        return jsonify(success=True, data=result, last_checked=last_checked_time)
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500

@app.route('/api/admin/healthcheck/categories', methods=['POST'])
@login_required
@admin_required
def add_category():
    name = request.get_json().get('name')
    if not name: return jsonify(success=False, message="카테고리 이름을 입력해주세요."), 400
    new_category = supabase_admin.table('health_check_categories').insert({'name': name}).execute().data
    return jsonify(success=True, data=new_category)

@app.route('/api/admin/healthcheck/websites', methods=['POST'])
@login_required
@admin_required
def add_website():
    data = request.get_json()
    if not all([data.get('name'), data.get('url'), data.get('category_id')]):
        return jsonify(success=False, message="모든 필드를 입력해주세요."), 400
    new_website = supabase_admin.table('health_check_websites').insert(data).execute().data
    return jsonify(success=True, data=new_website)

@app.route('/api/admin/healthcheck/websites/<int:site_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_website(site_id):
    supabase_admin.table('health_check_websites').delete().eq('id', site_id).execute()
    return jsonify(success=True, message="웹사이트가 삭제되었습니다.")
    
@app.route('/api/admin/healthcheck/categories/<int:category_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_category(category_id):
    supabase_admin.table('health_check_categories').delete().eq('id', category_id).execute()
    return jsonify(success=True, message="카테고리가 삭제되었습니다.")

@app.route('/api/ping', methods=['POST'])
@login_required_session # ✨ Ping 기능에만 특별히 세션 기반 데코레이터를 사용합니다.
def api_ping():
    # ✨ 정상 동작하던 기존 코드로 완전히 복원합니다.
    data = request.get_json()
    target = data.get('target')
    count = data.get('count')
    if not target or not isinstance(target, str):
        return jsonify(success=False, message="대상을 입력해주세요."), 400
    if not re.match(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)+([A-Za-z]|[A-Za-z][A-Za-z0-9\-]*[A-Za-z0-9])$", target):
        return jsonify(success=False, message="유효하지 않은 IP 주소 또는 도메인입니다."), 400
    try:
        count = int(count)
        if not (0 <= count <= 500):
            raise ValueError()
    except (ValueError, TypeError):
        return jsonify(success=False, message="Ping 횟수는 0에서 500 사이의 숫자여야 합니다."), 400

    def generate_ping():
        system = platform.system().lower()
        command = []

        if system != "windows":
            command.extend(['stdbuf', '-oL', 'ping'])
        else:
            command.append('ping')
        
        command.append(target)

        if count > 0:
            if system == "windows":
                command.extend(['-n', str(count)])
            else:
                command.extend(['-c', str(count)])
        elif system == "windows":
            command.append('-t')
        
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='utf-8', errors='replace', bufsize=1)
        
        for line in iter(process.stdout.readline, ''):
            yield line
        process.wait()

    return Response(generate_ping(), mimetype='text/plain')

# --- 인증 API ---
@app.route('/api/auth/signup', methods=['POST'])
def api_signup():
    data = request.get_json()
    email, password = data.get('email'), data.get('password')
    if not email or not password: return jsonify(success=False, message="이메일과 비밀번호를 모두 입력해주세요."), 400
    try:
        supabase.auth.sign_up({"email": email, "password": password})
        return jsonify(success=True, message="회원가입이 완료되었습니다. 이메일을 확인하여 계정을 활성화해주세요.")
    except Exception as e:
        return jsonify(success=False, message=str(e)), 400

@app.route('/api/auth/login', methods=['POST'])
def api_login():
    data = request.get_json()
    email, password = data.get('email'), data.get('password')
    if not email or not password:
        return jsonify(success=False, message="이메일과 비밀번호를 모두 입력해주세요."), 400
    try:
        res = supabase.auth.sign_in_with_password({"email": email, "password": password})
        profile = supabase_admin.table('profiles').select('is_admin, vt_api_key').eq('id', res.user.id).single().execute().data
        user_info = {
            'email': res.user.email, 'id': res.user.id,
            'is_admin': profile.get('is_admin', False),
            'apiKeySet': bool(profile.get('vt_api_key'))
        }

        session['user'] = user_info

        response = jsonify(success=True, message="로그인 성공", user=user_info)
        response.set_cookie('access_token', res.session.access_token, httponly=True, secure=True, samesite='Lax', max_age=3600*24*7) # 7일
        return response
    except Exception:
        return jsonify(success=False, message="로그인에 실패했습니다. 이메일 또는 비밀번호를 확인해주세요."), 401

@app.route('/api/auth/logout', methods=['POST'])
def api_logout():
    session.clear()
    response = jsonify(success=True, message="로그아웃되었습니다.")
    response.delete_cookie('access_token')
    return response

@app.route('/api/auth/session', methods=['GET'])
def api_check_session():
    access_token = request.cookies.get('access_token')
    if not access_token:
        return jsonify(isLoggedIn=False)
    try:
        user = supabase.auth.get_user(access_token).user
        profile = supabase_admin.table('profiles').select('is_admin, vt_api_key').eq('id', user.id).single().execute().data
        user_info = {
            'email': user.email, 'id': user.id,
            'is_admin': profile.get('is_admin', False),
            'apiKeySet': bool(profile.get('vt_api_key'))
        }
        return jsonify(isLoggedIn=True, user=user_info)
    except Exception as e:
        print(f"Session check error: {e}")
        return jsonify(isLoggedIn=False)

@app.route('/api/auth/forgot_password', methods=['POST'])
def api_forgot_password():
    email = request.get_json().get('email')
    if not email: return jsonify(success=False, message="이메일을 입력해주세요."), 400
    # 실제 비밀번호 재설정 로직 대신 관리자에게 알림을 보내는 기능만 유지
    webhook_url = os.getenv("SLACK_WEBHOOK_URL")
    if webhook_url:
        kst = timezone(timedelta(hours=9))
        slack_message = { "text": f"🔑 비밀번호 재설정 요청\n*요청자 이메일:* {email}\n*요청 시간:* {datetime.now(kst).strftime('%Y-%m-%d %H:%M:%S')}"}
        requests.post(webhook_url, json=slack_message, timeout=5)
    return jsonify(success=True, message="관리자에게 비밀번호 재설정 요청을 보냈습니다.")

@app.route('/api/scan', methods=['POST'])
@login_required
def api_scan():
    ips = request.get_json().get('ips', [])
    if not ips: return jsonify(success=False, message="조회할 IP를 입력해주세요."), 400
    try:
        profile = g.auth_supabase.table('profiles').select('vt_api_key').eq('id', g.user_id).single().execute().data
        if not profile or not profile.get('vt_api_key'):
            return jsonify(success=False, message="VirusTotal API 키가 설정되지 않았습니다."), 403
        vt_api_key = profile['vt_api_key']
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        with vt.Client(vt_api_key) as client:
            tasks = [get_ip_info(client, ip) for ip in ips]
            results_list = loop.run_until_complete(asyncio.gather(*tasks))
        scan_results = [{'ip': ip, **res} for ip, res in zip(ips, results_list)]
        return jsonify(success=True, results=scan_results)
    except Exception as e:
        return jsonify(success=False, message=f"IP 조회 중 오류 발생: {e}"), 500

@app.route('/api/profile/api_key', methods=['POST'])
@login_required
def api_profile_api_key():
    api_key = request.get_json().get('api_key')
    g.auth_supabase.table('profiles').update({'vt_api_key': api_key}).eq('id', g.user_id).execute()
    return jsonify(success=True, message="API 키가 성공적으로 저장되었습니다.")

@app.route('/api/profile/password', methods=['POST'])
@login_required
def api_profile_password():
    new_password = request.get_json().get('new_password')
    if not new_password or len(new_password) < 6:
        return jsonify(success=False, message="비밀번호는 6자리 이상이어야 합니다."), 400
    access_token = request.cookies.get('access_token')
    supabase.auth.update_user({"password": new_password}, jwt=access_token)
    return jsonify(success=True, message="비밀번호가 성공적으로 변경되었습니다.")

@app.route('/api/profile/delete', methods=['POST'])
@login_required
def api_delete_account():
    try:
        supabase_admin.auth.admin.delete_user(g.user_id)
        response = jsonify(success=True, message="계정이 성공적으로 삭제되었습니다.")
        response.delete_cookie('access_token')
        return response
    except Exception as e:
        return jsonify(success=False, message=f"계정 삭제 중 오류 발생: {e}"), 500

@app.route('/api/admin/users', methods=['GET'])
@login_required
@admin_required
def api_admin_get_users():
    users = supabase_admin.auth.admin.list_users().users
    user_list = [{'id': u.id, 'email': u.email, 'last_sign_in_at': u.last_sign_in_at} for u in users]
    return jsonify(success=True, users=user_list)

@app.route('/api/admin/users/<target_user_id>/reset_password', methods=['POST'])
@login_required
@admin_required
def api_admin_reset_password(target_user_id):
    try:
        temp_password = generate_temp_password()
        supabase_admin.auth.admin.update_user_by_id(target_user_id, {'password': temp_password})
        user_info = supabase_admin.auth.admin.get_user_by_id(target_user_id).user
        return jsonify(success=True, message=f"'{user_info.email}' 사용자의 임시 비밀번호는 '{temp_password}' 입니다.")
    except Exception as e:
        return jsonify(success=False, message=f"비밀번호 재설정 중 오류 발생: {e}"), 500

@app.route('/api/admin/users/<target_user_id>', methods=['DELETE'])
@login_required
@admin_required
def api_admin_delete_user(target_user_id):
    if target_user_id == g.user_id:
        return jsonify(success=False, message="자기 자신을 삭제할 수 없습니다."), 403
    try:
        supabase_admin.auth.admin.delete_user(target_user_id)
        return jsonify(success=True, message=f"사용자(ID: {target_user_id})가 성공적으로 삭제되었습니다.")
    except Exception as e:
        return jsonify(success=False, message=f"사용자 삭제 중 오류 발생: {e}"), 500

# ===================================================================
# 개발 서버 실행
# ===================================================================
if __name__ == '__main__':
    threading.Thread(target=download_mmdb_file, daemon=True).start()
    threading.Thread(target=run_cti_updates, daemon=True).start()
    threading.Thread(target=run_health_checks, daemon=True).start()
    app.run(host='0.0.0.0', port=5000, debug=False)

