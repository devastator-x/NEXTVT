import os
import asyncio
from flask import Flask, request, jsonify, session, Response
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
import hashlib
from pathlib import Path
import subprocess
import re
import platform
import threading
import time
from urllib.parse import urlparse
import geoip2.database # ✨ geoip2 대신 maxminddb를 직접 사용
import tarfile
import csv

# .env 파일의 절대 경로를 명시적으로 지정하여 실행 위치에 상관없이 파일을 찾도록 합니다.
env_path = Path(__file__).resolve().parent / '.env'
load_dotenv(dotenv_path=env_path)

# Flask 앱 생성
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

# CORS 설정
CORS(
    app,
    origins=["https://vt.openpesto.com", "http://localhost:3000"],
    supports_credentials=True
)

# Supabase 클라이언트 초기화
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
supabase_admin = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)

# ✨ MaxMind 라이선스 키 및 MMDB 파일 경로 설정
MAXMIND_LICENSE_KEY = os.getenv("MAXMIND_LICENSE_KEY")
MMDB_PATH = Path(__file__).resolve().parent / 'GeoLite2-Country.mmdb'
mmdb_ready_event = threading.Event()

# ===================================================================
# Helper Functions & Decorators
# ===================================================================
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return jsonify(success=False, message="로그인이 필요합니다."), 401
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'):
            return jsonify(success=False, message="관리자 권한이 필요합니다."), 403
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
# 웹사이트 헬스체크 백그라운드 작업
# ===================================================================
def get_status_color(status_code):
    if 200 <= status_code < 300:
        return 'green'
    elif 300 <= status_code < 400 or 500 <= status_code < 600:
        return 'orange'
    else:
        return 'red'

def check_websites_status():
    try:
        websites = supabase_admin.table('health_check_websites').select('id, url').execute().data
        for site in websites:
            status_color = 'red'
            status_code = None
            try:
                headers = {'User-Agent': 'NEXTVT-Health-Checker/1.0'}
                response = requests.get(site['url'], timeout=5, allow_redirects=True, headers=headers)
                status_code = response.status_code
                status_color = get_status_color(status_code)
            except requests.exceptions.Timeout:
                status_code = 408
                status_color = 'red'
            except requests.exceptions.ConnectionError:
                status_code = 503
                status_color = 'red'
            except requests.exceptions.RequestException as e:
                print(f"Error checking {site['url']}: {e}")
                status_code = 500
                status_color = 'red'
            
            supabase_admin.table('health_check_websites').update({
                'status_color': status_color,
                'status_code': status_code,
                'last_checked': datetime.now(timezone.utc).isoformat()
            }).eq('id', site['id']).execute()

    except Exception as e:
        print(f"An error occurred in check_websites_status: {e}")


def run_health_checks():
    while True:
        print("Running website health checks...")
        check_websites_status()
        time.sleep(60)

# ===================================================================
# CTI 데이터 수집 작업
# ===================================================================

def download_mmdb_file():
    """하루에 한 번 MaxMind GeoLite2 Country DB를 다운로드"""
    if not MAXMIND_LICENSE_KEY:
        print("Warning: MAXMIND_LICENSE_KEY is not set. Cannot download GeoLite2 database.")
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
                    for chunk in r.iter_content(chunk_size=8192):
                        f.write(chunk)
            
            with tarfile.open(temp_tar_path, "r:gz") as tar:
                for member in tar.getmembers():
                    if member.name.endswith('.mmdb'):
                        # 압축 파일 안의 디렉토리 구조를 무시하고 파일만 추출
                        member.name = os.path.basename(member.name) 
                        tar.extract(member, path=Path(__file__).resolve().parent)
                        # 추출된 파일의 이름을 최종 경로로 변경
                        extracted_path = Path(__file__).resolve().parent / member.name
                        if extracted_path.exists() and extracted_path != MMDB_PATH:
                             os.rename(extracted_path, MMDB_PATH)
                        break

            os.remove(temp_tar_path)
            print("MMDB file downloaded and extracted successfully.")
            mmdb_ready_event.set()

        except Exception as e:
            print(f"Failed to download MMDB file: {e}")
            mmdb_ready_event.set()
        
        time.sleep(86400)

def get_country_from_mmdb(ip, reader):
    """로컬 MMDB 파일에서 IP의 국가 정보 조회"""
    if not reader:
        return None
    try:
        # ✨ geoip2의 .country() 메소드 사용
        response = reader.country(ip)
        country_code = response.country.iso_code
        return County_Codes.country_code_to_korean.get(country_code, country_code)
    except geoip2.errors.AddressNotFoundError:
        return "N/A"
    except Exception as e:
        return None

def fetch_malicious_ips_from_github():
    """GitHub 저장소에서 악성 IP 목록을 가져와 DB에 저장"""
    mmdb_ready_event.wait()
    if not MMDB_PATH.exists():
        print("MMDB file not found. Skipping CTI update.")
        return

    file_url = "https://raw.githubusercontent.com/romainmarcoux/malicious-ip/main/full-40k.txt"
    source_name = "Multiple Sources (romainmarcoux/malicious-ip)"
    
    reader = None
    try:
        reader = geoip2.database.Reader(MMDB_PATH)
        
        file_response = requests.get(file_url, timeout=20)
        file_response.raise_for_status()
        
        ip_list = file_response.text.strip().split('\n')
        
        all_indicators = []
        current_time = datetime.now(timezone.utc).isoformat()
        for ip in ip_list:
            if ip.strip() and not ip.startswith('#'):
                country = get_country_from_mmdb(ip.strip(), reader)
                if country:
                    all_indicators.append({
                        'value': ip.strip(),
                        'type': 'ipv4',
                        'source': source_name,
                        'description': 'Malicious IP from public feed',
                        'country': country,
                        'added_at': current_time # ✨ 추가된 시간 기록
                    })

        if all_indicators:
            # ✨ 중복된 value는 무시하고 새로운 데이터만 추가
            supabase_admin.table('cti_indicators').upsert(
                all_indicators, 
                on_conflict='value',
                ignore_duplicates=True
            ).execute()
            
            print(f"Successfully processed {len(all_indicators)} indicators from GitHub.")

    except Exception as e:
        print(f"An error occurred in fetch_malicious_ips_from_github: {e}")
    finally:
        if reader:
            reader.close()


def fetch_malicious_domains_from_github():
    """GitHub 저장소에서 악성 도메인 목록을 가져와 DB에 저장"""
    repo_api_url = "https://api.github.com/repos/romainmarcoux/malicious-domains/contents/sources"
    
    try:
        repo_response = requests.get(repo_api_url, timeout=10)
        repo_response.raise_for_status()
        files = repo_response.json()

        all_indicators = []
        current_time = datetime.now(timezone.utc).isoformat()
        for file_info in files:
            if file_info['type'] == 'file':
                file_url = file_info['download_url']
                source_name = os.path.splitext(file_info['name'])[0]

                file_response = requests.get(file_url, timeout=10)
                if file_response.status_code == 200:
                    domain_list = file_response.text.strip().split('\n')
                    for domain in domain_list:
                        if domain.strip() and not domain.startswith('#'):
                            all_indicators.append({
                                'value': domain.strip(),
                                'type': 'domain',
                                'source': source_name,
                                'description': f'Malicious domain from {source_name}',
                                'country': None,
                                'added_at': current_time
                            })
        
        if all_indicators:
            chunk_size = 1000
            for i in range(0, len(all_indicators), chunk_size):
                chunk = all_indicators[i:i + chunk_size]
                supabase_admin.table('cti_indicators').upsert(
                    chunk, 
                    on_conflict='value',
                    ignore_duplicates=True
                ).execute()
            print(f"Successfully processed {len(all_indicators)} domain indicators from GitHub.")

    except Exception as e:
        print(f"An error occurred in fetch_malicious_domains_from_github: {e}")

def load_spam_emails_from_csv():
    """spam_mail.csv 파일에서 데이터를 읽어 DB에 저장"""
    csv_path = Path(__file__).resolve().parent / 'spam_mail.csv'
    if not csv_path.exists():
        print("spam_mail.csv file not found. Skipping email CTI load.")
        return

    try:
        with open(csv_path, mode='r', encoding='utf-8') as infile:
            reader = csv.reader(infile)
            next(reader) # 헤더 행 건너뛰기
            
            all_indicators = []
            for row in reader:
                # ✨ 빈 행이나 데이터가 부족한 행을 건너뛰도록 수정
                if len(row) >= 3 and row[0].strip():
                    date_str, subject, sender = row[0], row[1], row[2]
                    all_indicators.append({
                        'value': sender.strip(),
                        'type': 'email',
                        'source': 'spam_mail.csv',
                        'description': subject.strip(),
                        'added_at': date_str.strip()
                    })

        if all_indicators:
            supabase_admin.table('cti_indicators').upsert(
                all_indicators, 
                on_conflict='value',
                ignore_duplicates=True
            ).execute()
            print(f"Successfully processed {len(all_indicators)} email indicators from spam_mail.csv.")

    except Exception as e:
        print(f"An error occurred in load_spam_emails_from_csv: {e}")

def run_cti_updates():
    """1시간마다 CTI 데이터 수집을 실행하는 루프"""
    print("Performing initial CTI data fetch inside thread...")
    fetch_malicious_ips_from_github()
    fetch_malicious_domains_from_github() # ✨ 도메인 수집 추가
    load_spam_emails_from_csv()
    while True:
        time.sleep(360)
        print("Running CTI data updates...")
        fetch_malicious_ips_from_github()
        fetch_malicious_domains_from_github() # ✨ 도메인 수집 추가
        load_spam_emails_from_csv()

# ===================================================================
# API Routes
# ===================================================================

# --- CTI API ---
@app.route('/api/cti', methods=['GET'])
@login_required
def get_cti_data():
    try:
        indicator_type = request.args.get('type', 'all')
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 100))
        offset = (page - 1) * limit

        # ✨ 정렬 기준을 'added_at'으로 변경하여 순서 고정
        query = supabase.table('cti_indicators').select('*', count='exact').order('added_at', desc=True)
        
        if indicator_type != 'all':
            query = query.eq('type', indicator_type)
        
        query = query.range(offset, offset + limit - 1)
        
        result = query.execute()
        indicators = result.data
        total_count = result.count

        return jsonify(success=True, data=indicators, total=total_count)
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500


# --- 헬스체크 API ---
@app.route('/api/healthcheck', methods=['GET'])
@login_required
def get_health_check_data():
    try:
        categories = supabase.table('health_check_categories').select('*').order('id').execute().data
        websites = supabase.table('health_check_websites').select('*').order('id').execute().data
        
        last_checked_time = None
        if websites:
            last_checked_times = [datetime.fromisoformat(w['last_checked']) for w in websites if w['last_checked']]
            if last_checked_times:
                last_checked_time = max(last_checked_times).astimezone(timezone(timedelta(hours=9))).strftime('%Y. %m. %d. %p %I:%M:%S')

        result = []
        for category in categories:
            category['websites'] = [site for site in websites if site['category_id'] == category['id']]
            result.append(category)

        return jsonify(success=True, data=result, last_checked=last_checked_time)
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500

# --- 헬스체크 관리자 API ---
@app.route('/api/admin/healthcheck/categories', methods=['POST'])
@login_required
@admin_required
def add_category():
    data = request.get_json()
    name = data.get('name')
    if not name:
        return jsonify(success=False, message="카테고리 이름을 입력해주세요."), 400
    new_category = supabase_admin.table('health_check_categories').insert({'name': name}).execute().data
    return jsonify(success=True, data=new_category)

@app.route('/api/admin/healthcheck/websites', methods=['POST'])
@login_required
@admin_required
def add_website():
    data = request.get_json()
    name = data.get('name')
    url = data.get('url')
    category_id = data.get('category_id')
    if not all([name, url, category_id]):
        return jsonify(success=False, message="모든 필드를 입력해주세요."), 400
    new_website = supabase_admin.table('health_check_websites').insert({
        'name': name, 'url': url, 'category_id': category_id
    }).execute().data
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

# --- Ping 체크 API ---
@app.route('/api/ping', methods=['POST'])
@login_required
def api_ping():
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
        if system == "windows":
            command = ['ping', target]
            if count > 0:
                command.extend(['-n', str(count)])
            else:
                command.append('-t')
        else:
            command = ['ping', target]
            if count > 0:
                command.extend(['-c', str(count)])
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='utf-8', errors='replace')
        while True:
            line = process.stdout.readline()
            if not line:
                break
            yield line
        process.wait()
    return Response(generate_ping(), mimetype='text/plain')
    
# --- 인증 API ---
@app.route('/api/auth/signup', methods=['POST'])
def api_signup():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    if not email or not password:
        return jsonify(success=False, message="이메일과 비밀번호를 모두 입력해주세요."), 400
    try:
        supabase.auth.sign_up({"email": email, "password": password})
        return jsonify(success=True, message="회원가입이 완료되었습니다. 이메일을 확인하여 계정을 활성화해주세요.")
    except Exception as e:
        return jsonify(success=False, message=str(e)), 400

@app.route('/api/auth/login', methods=['POST'])
def api_login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    if not email or not password:
        return jsonify(success=False, message="이메일과 비밀번호를 모두 입력해주세요."), 400
    try:
        res = supabase.auth.sign_in_with_password({"email": email, "password": password})
        
        session['user'] = res.user.model_dump()
        session['access_token'] = res.session.access_token

        user_id = res.user.id
        
        profile = supabase_admin.table('profiles').select('is_admin, vt_api_key').eq('id', user_id).maybe_single().execute().data
        
        session['is_admin'] = profile.get('is_admin', False) if profile else False
        api_key_set = bool(profile and profile.get('vt_api_key'))

        user_info = {
            'email': res.user.email, 
            'id': res.user.id, 
            'is_admin': session['is_admin'],
            'apiKeySet': api_key_set
        }
        return jsonify(success=True, message="로그인 성공", user=user_info)
    except Exception as e:
        return jsonify(success=False, message="로그인에 실패했습니다. 이메일 또는 비밀번호를 확인해주세요."), 401

@app.route('/api/auth/logout', methods=['POST'])
def api_logout():
    session.clear()
    return jsonify(success=True, message="로그아웃되었습니다.")

@app.route('/api/auth/session', methods=['GET'])
def api_check_session():
    if 'user' in session:
        user_id = session['user']['id']
        try:
            profile = supabase_admin.table('profiles').select('is_admin, vt_api_key').eq('id', user_id).maybe_single().execute().data
            
            is_admin = profile.get('is_admin', False) if profile else False
            api_key_set = bool(profile and profile.get('vt_api_key'))

            user_info = {
                'email': session['user']['email'],
                'id': user_id,
                'is_admin': is_admin,
                'apiKeySet': api_key_set
            }
            return jsonify(isLoggedIn=True, user=user_info)
        except Exception as e:
            print(f"Error fetching profile for user {user_id}: {e}")
            session.clear()
            return jsonify(isLoggedIn=False)
    return jsonify(isLoggedIn=False)

@app.route('/api/auth/forgot_password', methods=['POST'])
def api_forgot_password():
    data = request.get_json()
    email = data.get('email')
    if not email:
        return jsonify(success=False, message="이메일을 입력해주세요."), 400
    try:
        user_check = supabase_admin.from_("users").select("id", count='exact').eq("email", email).execute()
        if user_check.count > 0:
            webhook_url = os.getenv("SLACK_WEBHOOK_URL")
            if webhook_url:
                kst = timezone(timedelta(hours=9))
                current_time = datetime.now(kst).strftime('%Y-%m-%d %H:%M:%S')
                slack_message = { "text": f"🔑 비밀번호 재설정 요청\n*요청자 이메일:* {email}\n*요청 시간:* {current_time}"}
                requests.post(webhook_url, json=slack_message, timeout=5)
            else:
                print("Warning: SLACK_WEBHOOK_URL is not set. Cannot send notification.")
    except Exception as e:
        print(f"ERROR in forgot_password for email '{email}': {e}")
    return jsonify(success=True, message="관리자에게 비밀번호 재설정 요청을 보냈습니다.")

# --- IP 스캔 API ---
@app.route('/api/scan', methods=['POST'])
@login_required
def api_scan():
    data = request.get_json()
    ips = data.get('ips', [])
    if not ips:
        return jsonify(success=False, message="조회할 IP를 입력해주세요."), 400
    try:
        auth_supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
        auth_supabase.auth.set_session(access_token=session['access_token'], refresh_token="dummy")
        user_id = session['user']['id']
        profile = auth_supabase.table('profiles').select('vt_api_key').eq('id', user_id).maybe_single().execute().data
        if not profile or not profile.get('vt_api_key'):
            return jsonify(success=False, message="VirusTotal API 키가 설정되지 않았습니다. MY 페이지에서 먼저 키를 설정해주세요."), 403
        vt_api_key = profile['vt_api_key']
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        client = vt.Client(vt_api_key)
        tasks = [get_ip_info(client, ip) for ip in ips]
        results_list = loop.run_until_complete(asyncio.gather(*tasks))
        client.close()
        scan_results = []
        for i, ip_address in enumerate(ips):
            result_item = results_list[i]
            result_item['ip'] = ip_address
            scan_results.append(result_item)
        return jsonify(success=True, results=scan_results)
    except Exception as e:
        return jsonify(success=False, message=f"IP 조회 중 오류 발생: {e}"), 500

# --- MY 페이지 (프로필) API ---
@app.route('/api/profile/api_key', methods=['POST'])
@login_required
def api_profile_api_key():
    auth_supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
    auth_supabase.auth.set_session(access_token=session['access_token'], refresh_token="dummy")
    user_id = session['user']['id']
    data = request.get_json()
    api_key = data.get('api_key')
    auth_supabase.table('profiles').update({'vt_api_key': api_key}).eq('id', user_id).execute()
    return jsonify(success=True, message="API 키가 성공적으로 저장되었습니다.")

@app.route('/api/profile/password', methods=['POST'])
@login_required
def api_profile_password():
    data = request.get_json()
    new_password = data.get('new_password')
    if not new_password or len(new_password) < 6:
        return jsonify(success=False, message="비밀번호는 6자리 이상이어야 합니다."), 400
    auth_supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
    auth_supabase.auth.set_session(access_token=session['access_token'], refresh_token="dummy")
    auth_supabase.auth.update_user({'password': new_password})
    return jsonify(success=True, message="비밀번호가 성공적으로 변경되었습니다.")

@app.route('/api/profile/delete', methods=['POST'])
@login_required
def api_delete_account():
    user_id = session['user']['id']
    try:
        supabase_admin.auth.admin.delete_user(user_id)
        session.clear()
        return jsonify(success=True, message="계정이 성공적으로 삭제되었습니다.")
    except Exception as e:
        return jsonify(success=False, message=f"계정 삭제 중 오류 발생: {e}"), 500

# --- 관리자 API ---
@app.route('/api/admin/users', methods=['GET'])
@login_required
@admin_required
def api_admin_get_users():
    users = supabase_admin.auth.admin.list_users()
    user_list = [{'id': u.id, 'email': u.email, 'last_sign_in_at': u.last_sign_in_at} for u in users]
    return jsonify(success=True, users=user_list)

@app.route('/api/admin/users/<user_id>/reset_password', methods=['POST'])
@login_required
@admin_required
def api_admin_reset_password(user_id):
    try:
        temp_password = generate_temp_password()
        supabase_admin.auth.admin.update_user_by_id(user_id, {'password': temp_password})
        user_info = supabase_admin.auth.admin.get_user_by_id(user_id).user
        return jsonify(success=True, message=f"'{user_info.email}' 사용자의 임시 비밀번호는 '{temp_password}' 입니다.")
    except Exception as e:
        return jsonify(success=False, message=f"비밀번호 재설정 중 오류 발생: {e}"), 500

@app.route('/api/admin/users/<user_id>', methods=['DELETE'])
@login_required
@admin_required
def api_admin_delete_user(user_id):
    if user_id == session['user']['id']:
        return jsonify(success=False, message="자기 자신을 삭제할 수 없습니다."), 403
    try:
        supabase_admin.auth.admin.delete_user(user_id)
        return jsonify(success=True, message=f"사용자(ID: {user_id})가 성공적으로 삭제되었습니다.")
    except Exception as e:
        return jsonify(success=False, message=f"사용자 삭제 중 오류 발생: {e}"), 500

# ===================================================================
# 개발 서버 실행
# ===================================================================
if __name__ == '__main__':
    mmdb_thread = threading.Thread(target=download_mmdb_file, daemon=True)
    mmdb_thread.start()
    
    cti_update_thread = threading.Thread(target=run_cti_updates, daemon=True)
    cti_update_thread.start()
    
    app.run(host='0.0.0.0', port=5000, debug=False)
