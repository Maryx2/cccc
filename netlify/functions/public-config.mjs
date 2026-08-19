
import {json} from './_admin-lib.mjs';
export default async()=>json({
  supabaseUrl:process.env.SUPABASE_URL||'',
  supabaseAnonKey:process.env.SUPABASE_ANON_KEY||''
});
