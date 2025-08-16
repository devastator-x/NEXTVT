"use client";

import { useAuth } from '../../contexts/AuthContext';
import { useRouter } from 'next/navigation';
import { useEffect, useState, FormEvent, useRef } from 'react';
import axios from 'axios';

// ✨ 타입 정의를 파일 상단으로 이동
interface Bookmark { 
    id: number; 
    name: string; 
    url: string; 
}

interface RssItem { 
    title: string; 
    link: string; 
    published: string; 
}

// ===================================================================
// 위젯 컴포넌트들
// ===================================================================

// 1. My IP 위젯 (변경 없음)
function MyIpWidget() {
    const [ip, setIp] = useState('Loading...');
    useEffect(() => {
        axios.get('/api/dashboard/ip').then(res => setIp(res.data.ip));
    }, []);
    return (
        <div className="card h-100">
            <div className="card-body d-flex flex-column justify-content-center">
                <h5 className="card-title">My IP</h5>
                {/* 폰트 크기를 fs-5로 줄여 공간을 덜 차지하도록 합니다. */}
                <p className="card-text fs-5 mb-0">{ip}</p>
            </div>
        </div>
    );
}

// 2. 메모장 위젯
function MemoWidget() {
    const [memo, setMemo] = useState('');
    const [saveStatus, setSaveStatus] = useState<'idle' | 'typing' | 'saving' | 'saved' | 'error'>('idle');
    const timeoutRef = useRef<NodeJS.Timeout | null>(null);

    useEffect(() => {
        axios.get('/api/dashboard/memo', { withCredentials: true })
            .then(res => setMemo(res.data.content || ''))
            .catch(() => setSaveStatus('error'));
    }, []);

    const handleMemoChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
        const newMemo = e.target.value;
        setMemo(newMemo);
        setSaveStatus('typing');

        if (timeoutRef.current) clearTimeout(timeoutRef.current);

        timeoutRef.current = setTimeout(() => {
            setSaveStatus('saving');
            axios.post('/api/dashboard/memo', { content: newMemo }, { withCredentials: true })
                .then(() => setSaveStatus('saved'))
                .catch(() => setSaveStatus('error'));
        }, 1500);
    };
    
    const getStatusIndicator = () => {
        switch(saveStatus) {
            case 'typing': return <span className="text-secondary">작성 중...</span>;
            case 'saving': return <span className="text-primary">저장 중...</span>;
            case 'saved': return <span className="text-success">저장 완료</span>;
            case 'error': return <span className="text-danger">저장 실패</span>;
            default: return null;
        }
    }

    return (
        <div className="card h-100">
            <div className="card-body d-flex flex-column">
                <div className="d-flex justify-content-between align-items-center mb-2">
                    <h5 className="card-title mb-0">Memo</h5>
                    <small>{getStatusIndicator()}</small>
                </div>
                <textarea 
                    className="form-control flex-grow-1" 
                    value={memo}
                    onChange={handleMemoChange}
                    placeholder="여기에 메모를 입력하세요..."
                ></textarea>
            </div>
        </div>
    );
}

// 3. 북마크 위젯
function BookmarksWidget() {
    const [bookmarks, setBookmarks] = useState<Bookmark[]>([]);
    const [newName, setNewName] = useState('');
    const [newUrl, setNewUrl] = useState('');
    const [editingId, setEditingId] = useState<number | null>(null);
    const [editingName, setEditingName] = useState('');
    const [editingUrl, setEditingUrl] = useState('');
    
    const fetchBookmarks = () => {
        axios.get('/api/dashboard/bookmarks', { withCredentials: true }).then(res => setBookmarks(res.data));
    };
    useEffect(fetchBookmarks, []);

    const handleAddBookmark = (e: FormEvent) => {
        e.preventDefault();
        axios.post('/api/dashboard/bookmarks', { name: newName, url: newUrl }, { withCredentials: true }).then(() => {
            setNewName(''); setNewUrl(''); fetchBookmarks();
        });
    };

    const handleDeleteBookmark = (id: number) => {
        if(confirm('정말 삭제하시겠습니까?')) {
            axios.delete(`/api/dashboard/bookmarks/${id}`, { withCredentials: true }).then(fetchBookmarks);
        }
    };

    const handleEditClick = (bm: Bookmark) => {
        setEditingId(bm.id);
        setEditingName(bm.name);
        setEditingUrl(bm.url);
    };

    const handleUpdateBookmark = (id: number) => {
        axios.put(`/api/dashboard/bookmarks/${id}`, { name: editingName, url: editingUrl }, { withCredentials: true }).then(() => {
            setEditingId(null); fetchBookmarks();
        });
    };

    return (
        <div className="card h-100">
            <div className="card-body d-flex flex-column">
                <h5 className="card-title">Bookmarks</h5>
                {/* maxHeight 스타일을 제거하고 flex-grow-1을 사용하여 공간을 채웁니다. */}
                <div className="flex-grow-1" style={{overflowY: 'auto'}}>
                    <ul className="list-group list-group-flush">
                        {bookmarks.map(bm => (
                            <li key={bm.id} className="list-group-item d-flex justify-content-between align-items-center">
                                {editingId === bm.id ? (
                                    <div className="input-group input-group-sm">
                                        <input type="text" className="form-control" value={editingName} onChange={e => setEditingName(e.target.value)} />
                                        <input type="url" className="form-control" value={editingUrl} onChange={e => setEditingUrl(e.target.value)} />
                                        <button className="btn btn-success" onClick={() => handleUpdateBookmark(bm.id)}>저장</button>
                                        <button className="btn btn-secondary" onClick={() => setEditingId(null)}>취소</button>
                                    </div>
                                ) : (
                                    <>
                                        <a href={bm.url} target="_blank" rel="noopener noreferrer">{bm.name}</a>
                                        <div>
                                            <button className="btn btn-sm btn-outline-secondary me-1" onClick={() => handleEditClick(bm)}>수정</button>
                                            <button className="btn btn-sm btn-outline-danger" onClick={() => handleDeleteBookmark(bm.id)}>삭제</button>
                                        </div>
                                    </>
                                )}
                            </li>
                        ))}
                    </ul>
                </div>
                <form onSubmit={handleAddBookmark} className="mt-auto">
                    <div className="input-group input-group-sm mt-2">
                        <input type="text" className="form-control" placeholder="이름" value={newName} onChange={e => setNewName(e.target.value)} required />
                        <input type="url" className="form-control" placeholder="URL" value={newUrl} onChange={e => setNewUrl(e.target.value)} required />
                        <button className="btn btn-primary" type="submit">+</button>
                    </div>
                </form>
            </div>
        </div>
    );
}


// 4. Nyan Cat 위젯
function NyanCatWidget() {
    const [seconds, setSeconds] = useState(0);

    useEffect(() => {
        const interval = setInterval(() => setSeconds(s => s + 1), 1000);
        return () => clearInterval(interval);
    }, []);

    return (
        <div className="card h-100 overflow-hidden">
            {/* SVG 배경과 유사한 어두운 색을 카드 배경으로 지정하여 자연스럽게 만듭니다. */}
            <div className="card-body text-center d-flex flex-column p-0 h-100" style={{ backgroundColor: '#030328' }}>
                <img
                    src="https://raw.githubusercontent.com/Gowee/nyancat-svg/main/nyancat.svg"
                    alt="Nyan Cat"
                    className="flex-grow-1"
                    style={{
                        width: '100%',
                        minHeight: 0,
                        // 'contain'에서 'cover'로 변경하여 좌우 여백을 제거하고 카드를 꽉 채웁니다.
                        objectFit: 'cover'
                    }}
                />
                {/* 텍스트가 잘 보이도록 배경색을 추가합니다. */}
                <p className="card-text py-2 mb-0 bg-dark text-white">You've NYANED for {seconds.toFixed(0)} seconds</p>
            </div>
        </div>
    );
}

// 5. KISA 보안공지 위젯
function KisaRssWidget() {
    const [items, setItems] = useState<RssItem[]>([]);
    const fetchRss = () => {
        axios.get('/api/dashboard/kisa-rss', { withCredentials: true }).then(res => setItems(res.data));
    };
    useEffect(() => {
        fetchRss();
        const interval = setInterval(fetchRss, 300000);
        return () => clearInterval(interval);
    }, []);

    const formatDate = (dateString: string) => {
        // 'YYYY. MM. DD.' 형식으로 날짜 포맷 변경
        return new Date(dateString).toLocaleDateString('ko-KR', {
            year: 'numeric',
            month: '2-digit',
            day: '2-digit'
        }).replace(/\.$/, ''); // 마지막 . 제거
    };

    return (
        <div className="card h-100">
            <div className="card-body d-flex flex-column">
                <h5 className="card-title">KISA 보안공지</h5>
                <div className="flex-grow-1" style={{overflowY: 'auto'}}>
                    <ul className="list-group list-group-flush">
                        {items.map((item, index) => (
                            <li key={index} className="list-group-item">
                                {/* flexbox를 사용하여 제목과 날짜를 양쪽으로 정렬 */}
                                <div className="d-flex justify-content-between align-items-start">
                                    <a href={item.link} target="_blank" rel="noopener noreferrer" className="text-decoration-none me-3">
                                        {item.title}
                                    </a>
                                    <span className="text-muted small text-nowrap">{formatDate(item.published)}</span>
                                </div>
                            </li>
                        ))}
                    </ul>
                </div>
            </div>
        </div>
    );
}

// ===================================================================
// 대시보드 메인 페이지
// ===================================================================
export default function DashboardPage() {
  const { user, isLoading } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (!isLoading && !user) {
      router.push('/login');
    }
  }, [user, isLoading, router]);

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
    <div className="container-fluid px-4 py-4">
        {/* 모든 위젯을 하나의 row 안에 배치하여 자연스러운 흐름을 만듭니다. */}
        <div className="row g-4">
            {/* 왼쪽 사이드바 위젯 그룹 */}
            <div className="col-lg-3">
                <div className="row g-4">
                    <div className="col-12" style={{ height: '120px' }}>
                        <MyIpWidget />
                    </div>
                    <div className="col-12" style={{ height: '156px' }}>
                        <NyanCatWidget />
                    </div>
                </div>
            </div>

            {/* 오른쪽 메인 컨텐츠 위젯 그룹 */}
            <div className="col-lg-9">
                <div className="row g-4">
                    <div className="col-12" style={{ minHeight: '300px' }}>
                        <MemoWidget />
                    </div>
                </div>
            </div>

            {/* 하단 위젯 그룹 (전체 너비 사용) */}
            <div className="col-lg-5" style={{ minHeight: '450px' }}>
                <BookmarksWidget />
            </div>
            <div className="col-lg-7" style={{ minHeight: '450px' }}>
                <KisaRssWidget />
            </div>
        </div>
    </div>
  );
}
