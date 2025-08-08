"use client";

import { useState, FormEvent } from 'react';
import Link from 'next/link';
import axios from 'axios';

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleRequest = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setMessage('');
    try {
      // ✨ [수정] 상대 경로로 API 호출
      const response = await axios.post('/api/auth/forgot_password', 
        { email },
        { withCredentials: true }
      );
      if (response.data.success) {
        setMessage(response.data.message);
      }
    } catch (err: any) {
      setError(err.response?.data?.message || '요청 중 오류가 발생했습니다.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="d-flex align-items-center justify-content-center" style={{ minHeight: '80vh' }}>
      <div className="card" style={{ width: '100%', maxWidth: '400px' }}>
        <div className="card-body">
          <h1 className="card-title text-center">비밀번호 찾기</h1>
          <p className="text-center text-muted">가입 시 사용한 이메일 주소를 입력하면 관리자에게 비밀번호 재설정 요청이 전달됩니다.</p>
          <form onSubmit={handleRequest}>
            <div className="mb-3">
              <label htmlFor="email" className="form-label">이메일 주소</label>
              <input
                type="email"
                id="email"
                className="form-control"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
              />
            </div>
            {message && <div className="alert alert-info">{message}</div>}
            {error && <div className="alert alert-danger">{error}</div>}
            <div className="d-grid">
              <button type="submit" className="btn btn-primary" disabled={loading}>
                {loading ? '요청 중...' : '관리자에게 요청하기'}
              </button>
            </div>
          </form>
          <p className="mt-3 text-center">
            <Link href="/login">로그인으로 돌아가기</Link>
          </p>
        </div>
      </div>
    </div>
  );
}

