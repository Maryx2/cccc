export default async () => {
  const url = process.env.SUPABASE_URL || '';
  const anonKey = process.env.SUPABASE_ANON_KEY || '';
  return new Response(JSON.stringify({ supabaseUrl: url, supabaseAnonKey: anonKey }), {
    status: url && anonKey ? 200 : 503,
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store' }
  });
};
