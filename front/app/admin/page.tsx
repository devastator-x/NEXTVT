"use client";

import { useAuth } from '../../contexts/AuthContext';
import { useRouter } from 'next/navigation';
import { useEffect, useState } from 'react';
import axios from 'axios';

interface User {
  id: string;
  email: string;
  last_sign_in_at: string | null;
}

export default function AdminPage() {
  const { user, isLoading } = useAuth();
  const router = useRouter();
  const [users, setUsers] = useState<User[]>([]);
  const [message, setMessage] = useState<{type: 'success' | 'danger', text: string} | null>(null);

  useEffect(() => {
    if (!isLoading && (!user || !user.is_admin)) {
      router.push('/'); // 관리자가 아니면 메인 페이지로
    }
    if (user?.is_admin) {
      fetchUsers();
    }
  }, [user, isLoading, router]);

  const fetchUsers = async () => {
    try {
      // ✨ [수정] 상대 경로로 API 호출
      const response = await axios.get('/api/admin/users', { withCredentials: true });
      setUsers(response.data.users);
    } catch (err) {
      setMessage({ type: 'danger', text: '사용자 목록을 불러오는데 실패했습니다.' });
    }
  };

  const handleResetPassword = async (userId: string) => {
    if (confirm('정말로 이 사용자의 비밀번호를 재설정하시겠습니까?')) {
      try {
        // ✨ [수정] 상대 경로로 API 호출
        const response = await axios.post(`/api/admin/users/${userId}/reset_password`, {}, { withCredentials: true });
        setMessage({ type: 'success', text: response.data.message });
      } catch (err: any) {
        setMessage({ type: 'danger', text: err.response?.data?.message || '비밀번호 재설정 실패' });
      }
    }
  };

  const handleDeleteUser = async (userId: string) => {
    if (confirm('경고: 이 사용자를 영구적으로 삭제합니다. 정말로 진행하시겠습니까?')) {
      try {
        // ✨ [수정] 상대 경로로 API 호출
        const response = await axios.delete(`/api/admin/users/${userId}`, { withCredentials: true });
        setMessage({ type: 'success', text: response.data.message });
        fetchUsers(); // 사용자 목록 새로고침
      } catch (err: any) {
        setMessage({ type: 'danger', text: err.response?.data?.message || '사용자 삭제 실패' });
      }
    }
  };

  if (isLoading || !user || !user.is_admin) {
    return <p>Loading or Access Denied...</p>;
  }

  return (
    <div className="card">
      <div className="card-header"><h1 className="card-title mb-0">관리자 페이지</h1></div>
      <div className="card-body">
        <h2 className="card-subtitle mb-3 text-muted">사용자 목록</h2>
        {message && <div className={`alert alert-${message.type}`}>{message.text}</div>}
        <div className="table-responsive">
          <table className="table table-striped">
            <thead className="table-dark">
              <tr>
                <th>Email</th>
                <th>User ID</th>
                <th>마지막 로그인</th>
                <th style={{ minWidth: '220px' }}>작업</th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.id}>
                  <td>{u.email}</td>
                  <td>{u.id}</td>
                  <td>{u.last_sign_in_at ? new Date(u.last_sign_in_at).toLocaleString('ko-KR') : 'N/A'}</td>
                  <td>
                    <button onClick={() => handleResetPassword(u.id)} className="btn btn-warning btn-sm">임시 비밀번호 발급</button>
                    <button onClick={() => handleDeleteUser(u.id)} className="btn btn-danger btn-sm ms-2">사용자 삭제</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

