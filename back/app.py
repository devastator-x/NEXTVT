import os
import asyncio
from flask import Flask, request, jsonify, session
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

# .env 파일의 절대 경로를 명시적으로 지정하여 실행 위치에 상관없이 파일을 찾도록 합니다.
env_path = Path(__file__).resolve().parent / '.env'
load_dotenv(dotenv_path=env_path)

# Flask 앱 생성
app = Flask(__name__)

# Secret Key 설정 (Flask 세션에 필수)
app.secret_key = os.getenv("SECRET_KEY")
if not app.secret_key:
    raise ValueError("SECRET_KEY is not set in the .env file")

# CORS 설정: 프론트엔드 개발 서버 및 실제 서비스 주소에서의 요청을 허용합니다.
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

# ===================================================================
# Helper Functions & Decorators
# ===================================================================

def login_required(f):
    """로그인한 사용자만 접근할 수 있도록 하는 데코레이터"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return jsonify(success=False, message="로그인이 필요합니다."), 401
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """관리자만 접근할 수 있도록 하는 데코레이터"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'):
            return jsonify(success=False, message="관리자 권한이 필요합니다."), 403
        return f(*args, **kwargs)
    return decorated_function

def generate_temp_password(length=12):
    """안전한 임시 비밀번호 생성"""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(secrets.choice(alphabet) for i in range(length))

async def get_ip_info(client, ip):
    """VirusTotal에서 IP 정보 비동기 조회"""
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
# API Routes
# ===================================================================

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
        
        session['user'] = res.user.dict()
        session['access_token'] = res.session.access_token

        user_id = res.user.id
        
        auth_supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
        auth_supabase.auth.set_session(access_token=res.session.access_token, refresh_token="dummy")
        
        profile = auth_supabase.table('profiles').select('is_admin, vt_api_key').eq('id', user_id).maybe_single().execute().data
        
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
        
        auth_supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
        auth_supabase.auth.set_session(access_token=session['access_token'], refresh_token="dummy")
        
        profile = auth_supabase.table('profiles').select('is_admin, vt_api_key').eq('id', user_id).maybe_single().execute().data
        
        is_admin = profile.get('is_admin', False) if profile else False
        api_key_set = bool(profile and profile.get('vt_api_key'))

        user_info = {
            'email': session['user']['email'],
            'id': user_id,
            'is_admin': is_admin,
            'apiKeySet': api_key_set
        }
        return jsonify(isLoggedIn=True, user=user_info)
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
            result_item['ip'] = ip_address # 각 결과 객체에 'ip' 키를 추가합니다.
            scan_results.append(result_item)

        return jsonify(success=True, results=scan_results)
    except Exception as e:
        return jsonify(success=False, message=f"IP 조회 중 오류 발생: {e}"), 500

# --- MY 페이지 (프로필) API ---

@app.route('/api/profile/api_key', methods=['GET', 'POST'])
@login_required
def api_profile_api_key():
    auth_supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
    auth_supabase.auth.set_session(access_token=session['access_token'], refresh_token="dummy")
    user_id = session['user']['id']
    if request.method == 'GET':
        profile = auth_supabase.table('profiles').select('vt_api_key').eq('id', user_id).maybe_single().execute().data
        api_key_exists = bool(profile and profile.get('vt_api_key'))
        return jsonify(success=True, api_key_exists=api_key_exists)
    if request.method == 'POST':
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
    app.run(host='0.0.0.0', port=5000, debug=True)

