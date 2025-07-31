import os
import asyncio
from flask import Flask, request, render_template, session, redirect, url_for, flash
from supabase import create_client, Client
from dotenv import load_dotenv
import vt
import County_Codes
from functools import wraps
import secrets
import string
import requests
from datetime import datetime, timezone, timedelta

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session or not session.get('is_admin'):
            flash('관리자 권한이 필요합니다.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def generate_temp_password(length=12):
    """안전한 임시 비밀번호를 생성합니다."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(secrets.choice(alphabet) for i in range(length))

# .env 파일 로드
load_dotenv()

# Flask 앱 설정
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
if not app.secret_key:
    raise ValueError("SECRET_KEY is not set in the .env file")

# Supabase 클라이언트 초기화
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
# 계정 삭제를 위해 Service Role Key를 사용한 관리자 클라이언트 추가
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
supabase_admin = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)


# VirusTotal IP 정보 비동기 조회 함수 (이전과 동일)
async def get_ip_info(client, ip):
    result = {'country': '', 'as_owner': '', 'malicious': ''}
    try:
        ip_info = await client.get_object_async(f"/ip_addresses/{ip}")
        ip_info_dict = ip_info.to_dict()

        if 'attributes' in ip_info_dict:
            attributes = ip_info_dict['attributes']
            if 'country' in attributes:
                country_code = attributes['country']
                result['country'] = County_Codes.country_code_to_korean.get(country_code, country_code)
            result['malicious'] = str(attributes.get('last_analysis_stats', {}).get('malicious', 0))
            result['as_owner'] = attributes.get('as_owner', 'N/A')
    except Exception as e:
        print(f"Error fetching data for IP {ip}: {e}")
        result = {key: 'Error' for key in result}
    return result

# --- 인증 관련 라우트 (signup, login, logout은 이전과 동일) ---

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        try:
            res = supabase.auth.sign_up({"email": email, "password": password})
            flash('회원가입이 완료되었습니다. 이메일을 확인하여 계정을 활성화해주세요.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f'회원가입 중 오류가 발생했습니다: {e}', 'danger')
    return render_template('signup.html')

@app.route('/admin')
@admin_required
def admin_page():
    # 관리자 클라이언트로 모든 사용자 목록을 가져옵니다.
    users = supabase_admin.auth.admin.list_users()
    return render_template('admin.html', users=users)

@app.route('/admin/reset_password/<user_id>', methods=['POST'])
@admin_required
def admin_reset_password(user_id):
    try:
        temp_password = generate_temp_password()
        # 관리자 권한으로 특정 사용자의 비밀번호를 업데이트합니다.
        supabase_admin.auth.admin.update_user_by_id(user_id, {'password': temp_password})
        
        # 재설정된 사용자의 이메일을 찾아서 메시지에 포함합니다.
        user_info = supabase_admin.auth.admin.get_user_by_id(user_id).user
        flash(f"'{user_info.email}' 사용자의 임시 비밀번호는 '{temp_password}' 입니다.", "success")
    except Exception as e:
        flash(f"비밀번호 재설정 중 오류 발생: {e}", "danger")
    
    return redirect(url_for('admin_page'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        try:
            res = supabase.auth.sign_in_with_password({"email": email, "password": password})
            session['user'] = res.user.dict()
            session['access_token'] = res.session.access_token

            # ✨ [추가] 로그인 시 관리자 여부를 확인하여 세션에 저장
            user_id = res.user.id
            profile = supabase.table('profiles').select('is_admin').eq('id', user_id).single().execute().data
            session['is_admin'] = profile.get('is_admin', False)

            return redirect(url_for('index'))
        except Exception as e:
            flash(f'로그인에 실패했습니다. 이메일 또는 비밀번호를 확인해주세요. ({e})', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    supabase.auth.sign_out()
    flash('성공적으로 로그아웃되었습니다.', 'info')
    return redirect(url_for('login'))

# --- 서비스 핵심 라우트 (index는 이전과 동일) ---

@app.route('/', methods=['GET', 'POST'])
def index():
    if 'user' not in session:
        return redirect(url_for('login'))

    try:
        # ✨ [수정] access_token으로 인증된 Supabase 클라이언트 생성
        auth_supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
        auth_supabase.auth.set_session(access_token=session['access_token'], refresh_token="dummy") # refresh_token은 필요 없으나 형식상 추가

        user_id = session['user']['id']
        # 인증된 클라이언트로 데이터 조회
        profile = auth_supabase.table('profiles').select('vt_api_key').eq('id', user_id).execute().data

        if not profile or not profile[0]['vt_api_key']:
            flash('VirusTotal API 키가 설정되지 않았습니다. 먼저 키를 설정해주세요.', 'warning')
            return redirect(url_for('settings'))

    except Exception as e:
        # 토큰 만료 등의 에러 발생 시 로그아웃 처리
        flash(f'세션 오류가 발생했습니다. 다시 로그인해주세요. ({e})', 'danger')
        return redirect(url_for('logout'))


    vt_api_key = profile[0]['vt_api_key']
    results = {}
    selected_columns = ['country', 'as_owner', 'malicious']

    if request.method == 'POST':
        # ... (이하 POST 로직은 기존과 동일)
        ips = request.form.get('ips', '').split()
        selected_columns = request.form.getlist('columns')
        
        if not ips:
            flash('조회할 IP를 입력해주세요.', 'warning')
        elif not selected_columns:
            flash('표시할 컬럼을 하나 이상 선택해주세요.', 'warning')
        else:
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                client = vt.Client(vt_api_key)
                tasks = [get_ip_info(client, ip) for ip in ips]
                results_list = loop.run_until_complete(asyncio.gather(*tasks))
                client.close()
                
                for ip, info in zip(ips, results_list):
                    results[ip] = info
            except Exception as e:
                flash(f'IP 조회 중 오류가 발생했습니다: {e}', 'danger')

    return render_template('index.html', results=results, selected_columns=selected_columns)

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if 'user' not in session:
        return redirect(url_for('login'))

    try:
        # ✨ [수정] access_token으로 인증된 Supabase 클라이언트 생성
        auth_supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
        auth_supabase.auth.set_session(access_token=session['access_token'], refresh_token="dummy")

        user_id = session['user']['id']

        if request.method == 'POST':
            api_key = request.form.get('api_key')
            # 인증된 클라이언트로 업데이트
            result = auth_supabase.table('profiles').update({'vt_api_key': api_key}).eq('id', user_id).execute()
            
            if result.data:
                flash('API 키가 성공적으로 저장되었습니다.', 'success')
            else:
                flash('API 키 저장에 실패했습니다. RLS 정책을 확인해주세요.', 'danger')
            
            return redirect(url_for('settings'))

        # 인증된 클라이언트로 조회
        profile = auth_supabase.table('profiles').select('vt_api_key').eq('id', user_id).execute().data
        current_key = profile[0]['vt_api_key'] if profile and profile[0]['vt_api_key'] else ''
        
        return render_template('settings.html', current_key=current_key)

    except Exception as e:
        flash(f'세션 오류가 발생했습니다. 다시 로그인해주세요. ({e})', 'danger')
        return redirect(url_for('logout'))

# --- ✨ [신규] 계정 탈퇴 라우트 ---
@app.route('/delete_account', methods=['POST'])
def delete_account():
    if 'user' not in session:
        return redirect(url_for('login'))

    user_id = session['user']['id']
    try:
        # Supabase Admin 클라이언트를 사용하여 사용자 삭제
        supabase_admin.auth.admin.delete_user(user_id)
        session.pop('user', None) # 세션 정리
        flash('계정이 성공적으로 삭제되었습니다.', 'success')
    except Exception as e:
        flash(f'계정 삭제 중 오류가 발생했습니다: {e}', 'danger')
        return redirect(url_for('settings'))

    return redirect(url_for('login'))

@app.route('/change_password', methods=['POST'])
def change_password():
    # 1. 로그인 상태인지 확인
    if 'user' not in session:
        return redirect(url_for('login'))

    try:
        # 2. 폼에서 새 비밀번호 가져오기
        new_password = request.form.get('new_password')

        # 3. 비밀번호 유효성 검사 (Supabase는 최소 6자리를 요구)
        if not new_password or len(new_password) < 6:
            flash('비밀번호는 6자리 이상이어야 합니다.', 'warning')
            return redirect(url_for('settings'))

        # 4. access_token으로 인증된 클라이언트 생성
        auth_supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
        auth_supabase.auth.set_session(access_token=session['access_token'], refresh_token="dummy")

        # 5. Supabase에 사용자 비밀번호 업데이트 요청
        auth_supabase.auth.update_user({'password': new_password})

        flash('비밀번호가 성공적으로 변경되었습니다.', 'success')

    except Exception as e:
        flash(f'비밀번호 변경 중 오류가 발생했습니다: {e}', 'danger')

    return redirect(url_for('settings'))

@app.route('/admin/delete_user/<user_id>', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    # 관리자가 자기 자신을 삭제하는 것을 방지
    if user_id == session['user']['id']:
        flash('자기 자신을 삭제할 수 없습니다.', 'danger')
        return redirect(url_for('admin_page'))

    try:
        # 관리자 권한으로 특정 사용자 삭제
        # Supabase에서 auth.users의 사용자를 삭제하면 profiles 테이블의 데이터도
        # ON DELETE CASCADE 제약 조건에 의해 자동으로 삭제됩니다.
        supabase_admin.auth.admin.delete_user(user_id)
        flash(f"사용자(ID: {user_id})가 성공적으로 삭제되었습니다.", 'success')
    except Exception as e:
        flash(f"사용자 삭제 중 오류 발생: {e}", 'danger')

    return redirect(url_for('admin_page'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        
        # .env 파일에서 Slack Webhook URL을 가져옵니다.
        webhook_url = os.getenv("SLACK_WEBHOOK_URL")
        if not webhook_url:
            flash('관리자에게 문의하세요: Slack Webhook URL이 설정되지 않았습니다.', 'danger')
            return redirect(url_for('login'))

        try:
            # 한국 시간(KST)으로 현재 시간 계산
            kst = timezone(timedelta(hours=9))
            current_time = datetime.now(kst).strftime('%Y-%m-%d %H:%M:%S')

            # Slack에 보낼 메시지 (Block Kit 형식)
            slack_message = {
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": "🔑 비밀번호 재설정 요청",
                            "emoji": True
                        }
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*요청자 이메일:*\n{email}"},
                            {"type": "mrkdwn", "text": f"*요청 시간:*\n{current_time}"}
                        ]
                    },
                    {
                        "type": "actions",
                        "elements": [
                            {
                                "type": "button",
                                "text": {
                                    "type": "plain_text",
                                    "text": "관리자 페이지로 이동",
                                    "emoji": True
                                },
                                "url": url_for('admin_page', _external=True),
                                "style": "primary"
                            }
                        ]
                    }
                ]
            }
            
            # Slack으로 POST 요청을 보냅니다.
            response = requests.post(webhook_url, json=slack_message)
            response.raise_for_status() # 요청 실패 시 에러를 발생시킵니다.

            flash('관리자에게 비밀번호 재설정 요청을 보냈습니다. 곧 연락이 갈 것입니다.', 'info')

        except Exception as e:
            flash(f'요청을 보내는 중 오류가 발생했습니다: {e}', 'danger')
        
        return redirect(url_for('login'))

    # GET 요청일 경우, 비밀번호 찾기 폼을 보여줍니다.
    return render_template('forgot_password.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
