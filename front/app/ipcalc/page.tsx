"use client";

import { useAuth } from '../../contexts/AuthContext';
import { useRouter } from 'next/navigation';
import { useEffect, useState, FormEvent } from 'react';

interface CalcResult {
    address: string;
    netmask: string;
    wildcard: string;
    network: string;
    hostMin: string;
    hostMax: string;
    broadcast: string;
    hostsCount: number;
    hostsInfo: string;
    addressBinary: string;
    netmaskBinary: string;
    wildcardBinary: string;
    networkBinary: string;
    hostMinBinary: string;
    hostMaxBinary: string;
    broadcastBinary: string;
    cidr: number;
}

// ✨ 이진수 값을 색상으로 구분하여 표시하는 컴포넌트
const BinaryWithColor = ({ binary, cidr }: { binary: string; cidr: number }) => {
    if (!binary) return null;

    const networkPart = binary.substring(0, cidr + Math.floor((cidr - 1) / 8));
    const hostPart = binary.substring(cidr + Math.floor((cidr - 1) / 8));

    return (
        <span className="font-monospace">
            <span style={{ color: '#00FFFF' }}>{networkPart}</span>
            <span style={{ color: '#FF0000' }}>{hostPart}</span>
        </span>
    );
};


const ResultRow = ({ label, value, binary, cidr }: { label: string; value: string | number; binary?: string; cidr?: number; }) => (
    <div className="row py-2">
        <div className="col-sm-3"><strong>{label}</strong></div>
        <div className="col-sm-4" style={{ color: '#00FFFF' }}>{value}</div>
        <div className="col-sm-5">
            {binary && cidr !== undefined ? <BinaryWithColor binary={binary} cidr={cidr} /> : <span className="font-monospace">{binary}</span>}
        </div>
    </div>
);

// Helper functions for IP calculation
const ipToLong = (ip: string) => {
    if (!/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(ip)) {
        throw new Error("Invalid IP address format");
    }
    return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
};

const longToIp = (long: number) => {
    return `${(long >>> 24)}.${(long >> 16) & 255}.${(long >> 8) & 255}.${long & 255}`;
};

const formatBinary = (ip: string) => {
    return ip.split('.').map(octet => parseInt(octet).toString(2).padStart(8, '0')).join('.');
};

const getIpInfo = (ip: string) => {
    const firstOctet = parseInt(ip.split('.')[0], 10);
    let ipClass = '';
    if (firstOctet >= 1 && firstOctet <= 126) ipClass = 'Class A';
    else if (firstOctet >= 128 && firstOctet <= 191) ipClass = 'Class B';
    else if (firstOctet >= 192 && firstOctet <= 223) ipClass = 'Class C';
    else if (firstOctet >= 224 && firstOctet <= 239) ipClass = 'Class D (Multicast)';
    else if (firstOctet >= 240 && firstOctet <= 255) ipClass = 'Class E (Experimental)';
    else if (firstOctet === 127) return 'Loopback';

    const ipLong = ipToLong(ip);
    const isPrivate =
        (ipToLong('10.0.0.0') <= ipLong && ipLong <= ipToLong('10.255.255.255')) ||
        (ipToLong('172.16.0.0') <= ipLong && ipLong <= ipToLong('172.31.255.255')) ||
        (ipToLong('192.168.0.0') <= ipLong && ipLong <= ipToLong('192.168.255.255'));

    return `${ipClass}, ${isPrivate ? 'Private Internet' : 'Public'}`;
};


export default function IpCalcPage() {
    const { user, isLoading } = useAuth();
    const router = useRouter();
    const [ipAddress, setIpAddress] = useState('');
    const [cidr, setCidr] = useState('');
    const [result, setResult] = useState<CalcResult | null>(null);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        if (!isLoading && !user) {
            router.push('/login');
        }
    }, [user, isLoading, router]);

    const handleCalculate = (e: FormEvent) => {
        e.preventDefault();
        setError(null);
        setResult(null);

        try {
            const cidrNum = parseInt(cidr, 10);
            if (isNaN(cidrNum) || cidrNum < 0 || cidrNum > 32) {
                throw new Error("Invalid CIDR value");
            }

            const ipLong = ipToLong(ipAddress);
            
            const maskLong = cidrNum === 0 ? 0 : ((0xFFFFFFFF << (32 - cidrNum)) >>> 0);
            const netmask = longToIp(maskLong);

            const networkLong = (ipLong & maskLong) >>> 0;
            const network = longToIp(networkLong);
            
            const broadcastLong = (networkLong | (~maskLong >>> 0)) >>> 0;
            const broadcast = longToIp(broadcastLong);

            const hostMinLong = networkLong + 1;
            const hostMaxLong = broadcastLong - 1;
            
            const hosts = Math.pow(2, 32 - cidrNum) - 2;
            const hostsCount = hosts >= 0 ? hosts : 0;
            const hostsInfo = getIpInfo(ipAddress);

            const hostMin = cidrNum < 31 ? longToIp(hostMinLong) : network;
            const hostMax = cidrNum < 31 ? longToIp(hostMaxLong) : network;

            setResult({
                address: ipAddress,
                netmask: `${netmask} = ${cidrNum}`,
                wildcard: longToIp(~maskLong >>> 0),
                network: `${network}/${cidrNum}`,
                hostMin: hostMin,
                hostMax: hostMax,
                broadcast: broadcast,
                hostsCount: hostsCount,
                hostsInfo: hostsInfo,
                addressBinary: formatBinary(ipAddress),
                netmaskBinary: formatBinary(netmask),
                wildcardBinary: formatBinary(longToIp(~maskLong >>> 0)),
                networkBinary: formatBinary(network),
                hostMinBinary: formatBinary(hostMin),
                hostMaxBinary: formatBinary(hostMax),
                broadcastBinary: formatBinary(broadcast),
                cidr: cidrNum,
            });
        } catch (err) {
            setError('유효하지 않은 IPv4 주소 또는 CIDR 형식입니다. (예: 192.168.0.1 / 24)');
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
        <div className="card bg-dark text-white">
            <div className="card-body">
                <h1 className="card-title">IP 계산기</h1>
                <p className="card-subtitle mb-3 text-muted">IPv4 주소와 CIDR을 입력하여 네트워크 정보를 계산합니다.</p>
                
                <form onSubmit={handleCalculate}>
                    <div className="row g-2 align-items-center mb-3">
                        <div className="col">
                            <input
                                type="text"
                                className="form-control"
                                value={ipAddress}
                                onChange={(e) => setIpAddress(e.target.value)}
                                placeholder="IP 주소 (예: 10.7.8.94)"
                                required
                            />
                        </div>
                        <div className="col-auto">
                            <span className="fs-4">/</span>
                        </div>
                        <div className="col-3 col-md-2">
                            <input
                                type="number"
                                className="form-control"
                                value={cidr}
                                onChange={(e) => setCidr(e.target.value)}
                                placeholder="CIDR (예: 18)"
                                min="0"
                                max="32"
                                required
                            />
                        </div>
                        <div className="col-auto">
                            <button className="btn btn-primary" type="submit">계산하기</button>
                        </div>
                    </div>
                </form>

                {error && <div className="alert alert-danger">{error}</div>}

                {result && (
                    <div className="mt-4 p-3 rounded" style={{backgroundColor: '#343a40'}}>
                        <div className="container-fluid p-0">
                            <ResultRow label="Address" value={result.address} binary={result.addressBinary} cidr={result.cidr} />
                            <ResultRow label="Netmask" value={result.netmask} binary={result.netmaskBinary} cidr={result.cidr} />
                            <ResultRow label="Wildcard" value={result.wildcard} binary={result.wildcardBinary} cidr={result.cidr} />
                            <div className="py-2">=&gt;</div>
                            <ResultRow label="Network" value={result.network} binary={result.networkBinary} cidr={result.cidr} />
                            <ResultRow label="HostMin" value={result.hostMin} binary={result.hostMinBinary} cidr={result.cidr} />
                            <ResultRow label="HostMax" value={result.hostMax} binary={result.hostMaxBinary} cidr={result.cidr} />
                            <ResultRow label="Broadcast" value={result.broadcast} binary={result.broadcastBinary} cidr={result.cidr} />
                            <ResultRow label="Hosts/Net" value={result.hostsCount.toLocaleString()} binary={result.hostsInfo} />
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
}

