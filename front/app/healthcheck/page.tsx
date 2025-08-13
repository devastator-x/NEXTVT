"use client";

import { useAuth } from '../../contexts/AuthContext';
import { useRouter } from 'next/navigation';
import { useEffect, useState } from 'react';
import axios from 'axios';
import Link from 'next/link';

type StatusColor = 'green' | 'orange' | 'red' | 'pending';

interface Website {
  id: number;
  name: string;
  url: string;
  status_color: StatusColor;
  status_code: number | null;
}

interface Category {
  id: number;
  name:string;
  websites: Website[];
}

// 응답 코드 뱃지 컴포넌트
const StatusBadge = ({ status_color, status_code }: { status_color: StatusColor, status_code: number | null }) => {
  // ✨ colorMap의 key 타입도 명시적으로 StatusColor로 지정
  const colorMap: Record<StatusColor, string> = {
    green: 'bg-success',
    orange: 'bg-warning text-dark',
    red: 'bg-danger',
    pending: 'bg-secondary'
  };  

  const badgeClass = colorMap[status_color] || colorMap.pending;

  return (
    <span className={`badge ${badgeClass} ms-2`}>
      {status_code || 'N/A'}
    </span>
  );
};

// ✨ 디자인이 개선된 응답 코드 치트 시트 컴포넌트
const CheatSheet = () => {
  const statusCodes = [
    { color: 'success', range: '2xx', title: '성공', description: '요청이 성공적으로 처리됨 (예: 200 OK)' },
    { color: 'warning', range: '3xx', title: '리디렉션', description: '페이지 주소가 변경됨 (예: 301, 302)' },
    { color: 'danger', range: '400', title: 'Bad Request', description: '잘못된 요청' },
    { color: 'danger', range: '401', title: 'Unauthorized', description: '인증 실패' },
    { color: 'danger', range: '403', title: 'Forbidden', description: '접근 권한 없음' },
    { color: 'danger', range: '404', title: 'Not Found', description: '페이지를 찾을 수 없음' },
    { color: 'danger', range: '408', title: 'Timeout', description: '요청 시간 초과' },
    { color: 'warning', range: '5xx', title: '서버 오류', description: '서버 내부 문제 발생 (예: 500, 502)' },
    { color: 'danger', range: '기타', title: '연결 불가', description: 'DNS 조회 실패, 연결 거부 등' },
  ];

  return (
    <div className="card">
      <div className="card-header">
        <strong>응답 코드 가이드</strong>
      </div>
      <div className="card-body" style={{fontSize: '0.875rem'}}>
        {statusCodes.map((code, index) => (
          <div key={index} className="d-flex align-items-center mb-3">
            {/* ✨ 스타일 수정: d-flex, align-items-center, justify-content-center 추가 및 폰트 크기 조정 */}
            <span 
              className={`badge bg-${code.color} me-3 d-flex align-items-center justify-content-center`} 
              style={{width: '65px', height: '30px', fontSize: '1rem'}}
            >
              {code.range}
            </span>
            <div>
              <strong>{code.title}</strong>
              <div className="text-muted">{code.description}</div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};


export default function HealthCheckPage() {
  const { user, isLoading: authLoading } = useAuth();
  const router = useRouter();
  const [categories, setCategories] = useState<Category[]>([]);
  const [lastChecked, setLastChecked] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchData = async () => {
    try {
      const response = await axios.get('/api/healthcheck', { withCredentials: true });
      if (response.data.success) {
        setCategories(response.data.data);
        setLastChecked(response.data.last_checked);
      }
    } catch (error) {
      console.error("Error fetching health check data:", error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (!authLoading && !user) {
      router.push('/login');
    }
    if (user) {
      fetchData();
      const interval = setInterval(fetchData, 20000);
      return () => clearInterval(interval);
    }
  }, [user, authLoading, router]);

  if (authLoading || loading) {
    return (
        <div className="d-flex justify-content-center align-items-center" style={{ height: '100vh' }}>
            <div className="spinner-border" role="status">
                <span className="visually-hidden">Loading...</span>
            </div>
        </div>
    );
  }

  return (
    <div>
      <div className="d-flex justify-content-between align-items-center mb-4">
        <h1>Health Check</h1>
        {user?.is_admin && (
          <Link href="/admin/healthcheck" className="btn btn-primary">
            관리자 모드
          </Link>
        )}
      </div>
      
      <div className="row">
        <div className="col-lg-9">
          {categories.map(category => (
            <div key={category.id} className="card mb-4">
              <div className="card-header">
                <h4>{category.name}</h4>
              </div>
              <div className="card-body">
                <div className="d-flex flex-wrap gap-2">
                  {category.websites.map(site => (
                    <a 
                      key={site.id} 
                      href={site.url} 
                      target="_blank" 
                      rel="noopener noreferrer" 
                      className="btn btn-light d-flex align-items-center text-decoration-none"
                    >
                      {site.name}
                      <StatusBadge status_color={site.status_color} status_code={site.status_code} />
                    </a>
                  ))}
                </div>
              </div>
            </div>
          ))}
        </div>
        
        <div className="col-lg-3">
          <CheatSheet />
        </div>
      </div>
      
      {lastChecked && (
        <p className="text-muted text-center mt-4">마지막 업데이트: {lastChecked}</p>
      )}
    </div>
  );
}

