import { createClient } from '@supabase/supabase-js';

// .env.local 파일에서 환경 변수를 가져옵니다.
const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL!;
const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!;

// Supabase 클라이언트를 생성하여 내보냅니다.
// '!'는 TypeScript에게 이 변수들이 null이나 undefined가 아님을 보장합니다.
export const supabase = createClient(supabaseUrl, supabaseAnonKey);

