"use client";

import { useAuth } from '../../contexts/AuthContext';
import { useRouter } from 'next/navigation';
import { useEffect, useState, FormEvent } from 'react';
import axios from 'axios';

export default function MyPage() {
  // ✨ [수정] updateApiKeyStatus 함수를 AuthContext에서 가져옵니다.
  const { user, isLoading, updateApiKeyStatus } = useAuth();
  const router = useRouter();
  
  const [apiKey, setApiKey] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [message, setMessage] = useState<{type: 'success' | 'danger', text: string} | null>(null);

  useEffect(() => {
    if (!isLoading && !user) {
      router.push('/login');
    }
  }, [user, isLoading, router]);

  const handleApiKeySubmit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setMessage(null);
    try {
      const response = await axios.post('/api/profile/api_key', { api_key: apiKey }, { withCredentials: true });
      setMessage({ type: 'success', text: response.data.message });
      
      // ✨ [추가] API 키가 성공적으로 저장되면, 프론트엔드의 상태를 갱신합니다.
      updateApiKeyStatus(true);
      
      // ✨ [추가] 키 저장 후, 사용자를 IP 스캔 페이지로 보내줍니다.
      setTimeout(() => {
        router.push('/');
      }, 1500); // 1.5초 후 이동

    } catch (err: any) {
      setMessage({ type: 'danger', text: err.response?.data?.message || 'API 키 저장 실패' });
    }
  };

  const handlePasswordChange = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (newPassword !== confirmPassword) {
      setMessage({ type: 'danger', text: '새 비밀번호와 확인이 일치하지 않습니다.' });
      return;
    }
    setMessage(null);
    try {
      const response = await axios.post('/api/profile/password', { new_password: newPassword }, { withCredentials: true });
      setMessage({ type: 'success', text: response.data.message });
      setNewPassword('');
      setConfirmPassword('');
    } catch (err: any) {
      setMessage({ type: 'danger', text: err.response?.data?.message || '비밀번호 변경 실패' });
    }
  };
  
  const handleDeleteAccount = async () => {
    if (confirm('정말로 계정을 탈퇴하시겠습니까? 이 작업은 되돌릴 수 없습니다.')) {
      try {
        await axios.post('/api/profile/delete', {}, { withCredentials: true });
        router.push('/login');
      } catch (err: any) {
        setMessage({ type: 'danger', text: err.response?.data?.message || '계정 삭제 실패' });
      }
    }
  };

  if (isLoading || !user) {
    return (
        <div className="d-flex justify-content-center align-items-center" style={{ height: '100vh' }}>
            <div className="spinner-border" role="status">
                <span className="visually-hidden">Loading...</span>
            </div>
        </div>
    );
  }

  return (
    <>
      {message && <div className={`alert alert-${message.type}`}>{message.text}</div>}
      
      <div className="card mb-4">
        <div className="card-body">
          <h1 className="card-title">API 키 설정</h1>
          <p>VirusTotal API 키를 입력해주세요. 키는 <a href="https://www.virustotal.com/gui/my-apikey" target="_blank" rel="noopener noreferrer">여기</a>에서 확인하실 수 있습니다.</p>
          <form onSubmit={handleApiKeySubmit}>
            <div className="mb-3">
              <label htmlFor="api_key" className="form-label">VirusTotal API Key</label>
              <input type="password" id="api_key" className="form-control" value={apiKey} onChange={(e) => setApiKey(e.target.value)} placeholder="새 키를 입력하여 덮어쓰세요." />
            </div>
            <button type="submit" className="btn btn-primary">저장/업데이트</button>
          </form>
        </div>
      </div>

      <div className="card mb-4">
        <div className="card-body">
          <h1 className="card-title">비밀번호 변경</h1>
          <form onSubmit={handlePasswordChange}>
            <div className="mb-3">
              <label htmlFor="new_password" className="form-label">새 비밀번호 (6자리 이상)</label>
              <input type="password" id="new_password" className="form-control" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} required minLength={6} />
            </div>
            <div className="mb-3">
              <label htmlFor="confirm_password" className="form-label">새 비밀번호 확인</label>
              <input type="password" id="confirm_password" className="form-control" value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} required minLength={6} />
            </div>
            <button type="submit" className="btn btn-info">비밀번호 변경하기</button>
          </form>
        </div>
      </div>

      <div className="card border-danger">
        <div className="card-header bg-danger text-white">계정 관리</div>
        <div className="card-body">
          <h5 className="card-title text-danger">계정 탈퇴</h5>
          <p className="card-text">계정을 탈퇴하면 모든 정보가 영구적으로 삭제됩니다.</p>
          <button onClick={handleDeleteAccount} className="btn btn-danger">계정 탈퇴하기</button>
        </div>
      </div>
    </>
  );
}

