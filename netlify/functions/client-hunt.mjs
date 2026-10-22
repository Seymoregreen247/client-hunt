import { createHash, createHmac, timingSafeEqual, randomBytes } from 'node:crypto';
const FALLBACK_URL = 'https://script.google.com/macros/s/AKfycbyxH0ERXEYK6xQfPbN9WJ_1ZUhRzEhLw2iEMwODG7IOeCnLuewHeVallEZ5Fz9l2ghr/exec';
const COOKIE='__Host-ch_session';
const TTL=8*60*60;
const headers={'content-type':'application/json; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff'};
function reply(body,status=200,extra={}) {return new Response(JSON.stringify(body),{status,headers:{...headers,...extra}})}
function same(a,b){return timingSafeEqual(createHash('sha256').update(String(a)).digest(),createHash('sha256').update(String(b)).digest())}
function sign(v,secret){return createHmac('sha256',secret).update('client-hunt-session-v1:'+v).digest('base64url')}
function cookie(token,age=TTL){return `${COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${age}`}
function session(req,secret){const raw=(req.headers.get('cookie')||'').split(';').map(v=>v.trim()).find(v=>v.startsWith(COOKIE+'='))?.slice(COOKIE.length+1)||'';
 const [payload,sig,...rest]=raw.split('.');if(rest.length||!payload||!sig||!same(sig,sign(payload,secret)))return false;
 try{let p=JSON.parse(Buffer.from(payload,'base64url').toString());let now=Math.floor(Date.now()/1000);return p.v===1&&Number.isInteger(p.exp)&&p.exp>now&&p.exp<=now+TTL&&typeof p.n==='string'}catch{return false}}
function token(secret){let p=Buffer.from(JSON.stringify({v:1,exp:Math.floor(Date.now()/1000)+TTL,n:randomBytes(20).toString('hex')})).toString('base64url');return p+'.'+sign(p,secret)}
export default async function handler(req){
 if(req.method!=='POST')return reply({ok:false,code:'METHOD',message:'Use POST.'},405,{'allow':'POST'});
 let origin=req.headers.get('origin');if(!origin||origin!==new URL(req.url).origin)return reply({ok:false,code:'ORIGIN',message:'Use this API from the Client Hunt site.'},403);
 if(!req.headers.get('content-type')?.startsWith('application/json'))return reply({ok:false,code:'CONTENT_TYPE',message:'Send application/json.'},415);
 let password=process.env.CLIENT_HUNT_APP_PASSWORD,key=process.env.CLIENT_HUNT_API_KEY;
 if(!password||password.length<20||!key)return reply({ok:false,code:'NOT_CONFIGURED',message:'Add CLIENT_HUNT_API_KEY and a CLIENT_HUNT_APP_PASSWORD of at least 20 characters to Netlify environment variables (Functions scope), then redeploy.'},503);
 let body;try{let text=await req.text();if(Buffer.byteLength(text)>1100000)return reply({ok:false,code:'TOO_LARGE',message:'Workspace is too large.'},413);body=JSON.parse(text)}catch{return reply({ok:false,code:'BAD_JSON',message:'Invalid JSON.'},400)}
 if(!body||typeof body!=='object'||Array.isArray(body))return reply({ok:false,code:'BAD_REQUEST',message:'Expected a request object.'},400);
 if(body.action==='login'){
  if(typeof body.password!=='string'||!same(body.password,password)){await new Promise(r=>setTimeout(r,600));return reply({ok:false,code:'LOGIN',message:'Password did not match.'},401)}
  return reply({ok:true,authenticated:true},200,{'set-cookie':cookie(token(password))});
 }
 if(body.action==='logout')return reply({ok:true},200,{'set-cookie':cookie('',0)});
 let authenticated=session(req,password);
 if(body.action==='status')return reply({ok:true,authenticated});
 if(!authenticated)return reply({ok:false,code:'SIGN_IN',message:'Sign in to your Client Hunt cloud connection.'},401);
 if(!['load','save'].includes(body.action))return reply({ok:false,code:'ACTION',message:'Unsupported action.'},400);
 let payload={key,action:body.action};
 if(body.action==='save'){
  if(!Number.isInteger(body.expectedRevision)||body.expectedRevision<0||typeof body.requestId!=='string'||!body.state)return reply({ok:false,code:'BAD_REQUEST',message:'Save requires revision, request ID, and state.'},400);
  Object.assign(payload,{expectedRevision:body.expectedRevision,requestId:body.requestId,state:body.state});
 }
 let url=process.env.CLIENT_HUNT_SCRIPT_URL||FALLBACK_URL;
 if(!/^https:\/\/script\.google\.com\/macros\/s\/[a-zA-Z0-9_-]+\/exec$/.test(url))return reply({ok:false,code:'CONFIG_URL',message:'Check the Apps Script /exec deployment URL in Netlify.'},503);
 try{
  let upstream=await fetch(url,{method:'POST',headers:{'content-type':'text/plain;charset=utf-8'},body:JSON.stringify(payload),redirect:'follow',signal:AbortSignal.timeout(25000)});
  let text=await upstream.text(),result;
  try{result=JSON.parse(text)}catch{return reply({ok:false,code:'GOOGLE_ACCESS',message:'Google did not return the CRM API. Confirm this deployment uses the supplied script, Execute as Me, access Anyone, and the /exec URL.'},502)}
  if(!result||typeof result.ok!=='boolean')return reply({ok:false,code:'BAD_UPSTREAM',message:'The endpoint returned an unexpected response.'},502);
  if(result.code==='UNAUTHORIZED')return reply({ok:false,code:'SCRIPT_KEY',message:'The Netlify API key does not match this Apps Script deployment.'},502);
  return reply(result,result.ok?200:result.code==='CONFLICT'?409:400);
 }catch{return reply({ok:false,code:'CONNECTION',message:'Google could not be reached or timed out. Your local records are retained. Retry Save now; identical pending requests are safe to retry.'},502)}
}
