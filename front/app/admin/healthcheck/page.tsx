"use client";

import { useAuth } from '../../../contexts/AuthContext';
import { useRouter } from 'next/navigation';
import { useEffect, useState, FormEvent } from 'react';
import axios from 'axios';

interface Category {
  id: number;
  name: string;
}

interface Website {
    id: number;
    name: string;
    url: string;
    category_id: number;
}

interface CategoryWithWebsites extends Category {
    websites: Website[];
}

export default function HealthCheckAdminPage() {
  const { user, isLoading } = useAuth();
  const router = useRouter();

  const [categories, setCategories] = useState<CategoryWithWebsites[]>([]);
  const [newCategoryName, setNewCategoryName] = useState('');
  const [newSiteName, setNewSiteName] = useState('');
  const [newSiteUrl, setNewSiteUrl] = useState('');
  const [selectedCategoryId, setSelectedCategoryId] = useState('');
  const [message, setMessage] = useState('');

  const fetchData = async () => {
    try {
        const catResponse = await axios.get('/api/healthcheck', { withCredentials: true });
        if (catResponse.data.success) {
            setCategories(catResponse.data.data);
            if (catResponse.data.data.length > 0 && !selectedCategoryId) {
                setSelectedCategoryId(catResponse.data.data[0].id.toString());
            }
        }
    } catch (error) {
        console.error("Error fetching data:", error);
        setMessage('데이터를 불러오는 데 실패했습니다.');
    }
  };
  
  useEffect(() => {
    if (!isLoading) {
      if (!user || !user.is_admin) {
        router.push('/');
      } else {
        fetchData();
      }
    }
  }, [user, isLoading, router]);

  const handleAddCategory = async (e: FormEvent) => {
    e.preventDefault();
    try {
      await axios.post('/api/admin/healthcheck/categories', { name: newCategoryName }, { withCredentials: true });
      setMessage('카테고리가 추가되었습니다.');
      setNewCategoryName('');
      fetchData();
    } catch (err) {
      setMessage('카테고리 추가 실패.');
    }
  };

  const handleAddWebsite = async (e: FormEvent) => {
    e.preventDefault();
    try {
      await axios.post('/api/admin/healthcheck/websites', { 
        name: newSiteName, 
        url: newSiteUrl, 
        category_id: parseInt(selectedCategoryId) 
      }, { withCredentials: true });
      setMessage('웹사이트가 추가되었습니다.');
      setNewSiteName('');
      setNewSiteUrl('');
      fetchData();
    } catch (err) {
      setMessage('웹사이트 추가 실패.');
    }
  };

  const handleDeleteWebsite = async (siteId: number) => {
    if (confirm('정말로 이 웹사이트를 삭제하시겠습니까?')) {
        try {
            await axios.delete(`/api/admin/healthcheck/websites/${siteId}`, { withCredentials: true });
            setMessage('웹사이트가 삭제되었습니다.');
            fetchData();
        } catch (err) {
            setMessage('웹사이트 삭제 실패.');
        }
    }
  };
  
  const handleDeleteCategory = async (categoryId: number) => {
    if (confirm('정말로 이 카테고리를 삭제하시겠습니까? 모든 하위 웹사이트도 함께 삭제됩니다.')) {
        try {
            await axios.delete(`/api/admin/healthcheck/categories/${categoryId}`, { withCredentials: true });
            setMessage('카테고리가 삭제되었습니다.');
            setSelectedCategoryId(''); // 삭제 후 선택 초기화
            fetchData();
        } catch (err) {
            setMessage('카테고리 삭제 실패.');
        }
    }
  };

  if (isLoading || !user || !user.is_admin) {
    return <p>Loading or Access Denied...</p>;
  }

  return (
    <div className="container">
      <h1>헬스체크 관리</h1>
      {message && <div className="alert alert-info my-3">{message}</div>}

      <div className="row">
        <div className="col-md-6">
            <div className="card mb-4">
                <div className="card-body">
                <h2 className="card-title">카테고리 관리</h2>
                <form onSubmit={handleAddCategory} className="mb-3">
                    <div className="input-group">
                    <input 
                        type="text" 
                        className="form-control" 
                        value={newCategoryName} 
                        onChange={e => setNewCategoryName(e.target.value)} 
                        placeholder="새 카테고리 이름" 
                        required 
                    />
                    <button type="submit" className="btn btn-secondary">추가</button>
                    </div>
                </form>
                <ul className="list-group">
                    {categories.map(cat => (
                        <li key={cat.id} className="list-group-item d-flex justify-content-between align-items-center">
                            {cat.name}
                            <button className="btn btn-sm btn-outline-danger" onClick={() => handleDeleteCategory(cat.id)}>삭제</button>
                        </li>
                    ))}
                </ul>
                </div>
            </div>
        </div>

        <div className="col-md-6">
            <div className="card mb-4">
                <div className="card-body">
                <h2 className="card-title">웹사이트 추가</h2>
                <form onSubmit={handleAddWebsite}>
                    <div className="mb-3">
                    <label className="form-label">카테고리</label>
                    <select className="form-select" value={selectedCategoryId} onChange={e => setSelectedCategoryId(e.target.value)} required>
                        <option value="" disabled>카테고리를 선택하세요</option>
                        {categories.map(cat => <option key={cat.id} value={cat.id}>{cat.name}</option>)}
                    </select>
                    </div>
                    <div className="mb-3">
                    <label className="form-label">웹사이트 이름</label>
                    <input type="text" className="form-control" value={newSiteName} onChange={e => setNewSiteName(e.target.value)} placeholder="예: 서강대학교 SAINT" required />
                    </div>
                    <div className="mb-3">
                    <label className="form-label">URL</label>
                    <input type="url" className="form-control" value={newSiteUrl} onChange={e => setNewSiteUrl(e.target.value)} placeholder="https://saint.sogang.ac.kr" required />
                    </div>
                    <button type="submit" className="btn btn-primary">웹사이트 추가</button>
                </form>
                </div>
            </div>
        </div>
      </div>
      
      <hr className="my-4"/>

      <h2>등록된 웹사이트 목록</h2>
        {categories.map(cat => (
            <div key={`list-${cat.id}`} className="mb-3">
                <h5>{cat.name}</h5>
                <ul className="list-group">
                    {cat.websites.map(site => (
                        <li key={site.id} className="list-group-item d-flex justify-content-between align-items-center">
                            <div>
                                <strong>{site.name}</strong><br/>
                                <small className="text-muted">{site.url}</small>
                            </div>
                            <button className="btn btn-sm btn-outline-danger" onClick={() => handleDeleteWebsite(site.id)}>삭제</button>
                        </li>
                    ))}
                    {cat.websites.length === 0 && <li className="list-group-item">등록된 웹사이트가 없습니다.</li>}
                </ul>
            </div>
        ))}
    </div>
  );
}

