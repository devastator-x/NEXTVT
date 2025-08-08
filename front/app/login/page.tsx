"use client";

import { useState, FormEvent } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import axios from 'axios';

export default function LoginPage() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const router = useRouter();
  const { login } = useAuth();

  const handleLogin = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      // ✨ [수정] 상대 경로로 API 호출
      const response = await axios.post('/api/auth/login', 
        { email, password },
        { withCredentials: true }
      );
      if (response.data.success) {
        login(response.data.user);
        router.push('/');
      }
    } catch (err: any) {
      setError(err.response?.data?.message || '로그인 중 오류가 발생했습니다.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="d-flex align-items-center justify-content-center" style={{ minHeight: '80vh' }}>
      <div className="card" style={{ width: '100%', maxWidth: '400px' }}>
        <div className="card-body">
          <h1 className="card-title text-center">로그인</h1>
          <form onSubmit={handleLogin}>
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
            <div className="mb-3">
              <label htmlFor="password" className="form-label">비밀번호</label>
              <input
                type="password"
                id="password"
                className="form-control"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </div>
            {error && <div className="alert alert-danger">{error}</div>}
            <div className="d-grid">
              <button type="submit" className="btn btn-primary" disabled={loading}>
                {loading ? '로그인 중...' : '로그인'}
              </button>
            </div>
          </form>
          <div className="text-center mt-3">
            <Link href="/forgot-password">비밀번호를 잊으셨나요?</Link>
          </div>
          <p className="mt-3 text-center">
            계정이 없으신가요? <Link href="/signup">회원가입</Link>
          </p>
        </div>
      </div>
    </div>
  );
}

