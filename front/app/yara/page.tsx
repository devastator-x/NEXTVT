"use client";

import { useAuth } from '../../contexts/AuthContext';
import { useRouter } from 'next/navigation';
import { useEffect, useState, FormEvent } from 'react';
import axios from 'axios';

interface YaraString {
    id: number;
    type: 'text' | 'hex';
    value: string;
}

export default function YaraGeneratorPage() {
    const { user, isLoading } = useAuth();
    const router = useRouter();

    const [ruleName, setRuleName] = useState('');
    const [author, setAuthor] = useState('');
    const [description, setDescription] = useState('');
    const [reference, setReference] = useState('');
    const [strings, setStrings] = useState<YaraString[]>([{ id: 1, type: 'text', value: '' }]);
    const [condition, setCondition] = useState('any');
    
    const [generatedRule, setGeneratedRule] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [isCopied, setIsCopied] = useState(false);

    useEffect(() => {
        if (!isLoading && !user) {
            router.push('/login');
        }
    }, [user, isLoading, router]);

    const handleAddString = () => {
        setStrings([...strings, { id: Date.now(), type: 'text', value: '' }]);
    };

    const handleRemoveString = (id: number) => {
        setStrings(strings.filter(s => s.id !== id));
    };

    const handleStringChange = (id: number, field: 'type' | 'value', value: string) => {
        const newStrings = strings.map(s => {
            if (s.id === id) {
                return { ...s, [field]: value };
            }
            return s;
        });
        setStrings(newStrings as YaraString[]);
    };

    const handleGenerate = async (e: FormEvent) => {
        e.preventDefault();
        setLoading(true);
        setError(null);
        setGeneratedRule('');
        try {
            const response = await axios.post('/api/yara', {
                ruleName, author, description, reference, strings, condition
            }, { withCredentials: true });

            if (response.data.success) {
                setGeneratedRule(response.data.rule);
            } else {
                setError(response.data.message);
            }
        } catch (err: any) {
            setError(err.response?.data?.message || '규칙 생성 중 오류가 발생했습니다.');
        } finally {
            setLoading(false);
        }
    };
    
    const handleCopy = () => {
        navigator.clipboard.writeText(generatedRule).then(() => {
            setIsCopied(true);
            setTimeout(() => setIsCopied(false), 2000);
        });
    };

    if (isLoading || !user) {
        return <div className="d-flex justify-content-center align-items-center" style={{ height: '100vh' }}><div className="spinner-border"></div></div>;
    }

    return (
        <div className="row g-4">
            {/* Left Column: Input Form */}
            <div className="col-lg-6">
                <div className="card">
                    <div className="card-body">
                        <h1 className="card-title">YARA 규칙 생성기</h1>
                        <form onSubmit={handleGenerate}>
                            {/* Meta Section */}
                            <h5 className="mt-4">메타 정보</h5>
                            <div className="mb-3">
                                <label htmlFor="ruleName" className="form-label">규칙 이름</label>
                                <input type="text" className="form-control" id="ruleName" value={ruleName} onChange={e => setRuleName(e.target.value)} placeholder="예: Detect_My_Malware" required />
                            </div>
                            <div className="mb-3">
                                <label htmlFor="author" className="form-label">작성자</label>
                                <input type="text" className="form-control" id="author" value={author} onChange={e => setAuthor(e.target.value)} placeholder="Your Name" />
                            </div>
                            <div className="mb-3">
                                <label htmlFor="description" className="form-label">설명</label>
                                <textarea className="form-control" id="description" rows={2} value={description} onChange={e => setDescription(e.target.value)} placeholder="이 규칙이 탐지하는 것에 대한 설명"></textarea>
                            </div>
                             <div className="mb-3">
                                <label htmlFor="reference" className="form-label">참조</label>
                                <input type="text" className="form-control" id="reference" value={reference} onChange={e => setReference(e.target.value)} placeholder="관련 정보 링크 (URL)" />
                            </div>

                            {/* Strings Section */}
                            <h5 className="mt-4">탐지 문자열</h5>
                            {strings.map((s, index) => (
                                <div key={s.id} className="input-group mb-2">
                                    <select className="form-select" style={{flex: '0 0 100px'}} value={s.type} onChange={e => handleStringChange(s.id, 'type', e.target.value)}>
                                        <option value="text">Text</option>
                                        <option value="hex">Hex</option>
                                    </select>
                                    <input type="text" className="form-control" value={s.value} onChange={e => handleStringChange(s.id, 'value', e.target.value)} placeholder={s.type === 'text' ? "탐지할 텍스트" : "예: 4D 5A 90 00"} required />
                                    <button type="button" className="btn btn-outline-danger" onClick={() => handleRemoveString(s.id)} disabled={strings.length <= 1}>삭제</button>
                                </div>
                            ))}
                            <button type="button" className="btn btn-outline-secondary btn-sm" onClick={handleAddString}>+ 문자열 추가</button>

                            {/* Condition Section */}
                            <h5 className="mt-4">조건</h5>
                            <div className="mb-3">
                                <select className="form-select" value={condition} onChange={e => setCondition(e.target.value)}>
                                    <option value="any">하나라도 일치</option>
                                    <option value="all">모두 일치</option>
                                </select>
                            </div>

                            <hr/>
                            <button type="submit" className="btn btn-primary w-100" disabled={loading}>
                                {loading ? '생성 중...' : '생성하기'}
                            </button>
                            {error && <div className="alert alert-danger mt-3">{error}</div>}
                        </form>
                    </div>
                </div>
            </div>

            {/* Right Column: Output */}
            <div className="col-lg-6">
                <div className="card">
                    <div className="card-body">
                        <div className="d-flex justify-content-between align-items-center">
                            <h1 className="card-title">생성된 규칙</h1>
                            <button className="btn btn-sm btn-outline-secondary" onClick={handleCopy} disabled={!generatedRule}>
                                {isCopied ? '복사 완료!' : '복사하기'}
                            </button>
                        </div>
                        <pre className="bg-light p-3 rounded mt-3" style={{minHeight: '400px', whiteSpace: 'pre-wrap'}}>
                            <code>
                                {generatedRule || '여기에 생성된 YARA 규칙이 표시됩니다.'}
                            </code>
                        </pre>
                    </div>
                </div>
            </div>
        </div>
    );
}

