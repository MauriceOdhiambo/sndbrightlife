/* SND BRIGHTLIFE CBO — VERCEL BACKEND
   Migrated from the production CODE.GS. Business functions are preserved;
   Google Apps Script services are replaced with Node/Vercel equivalents.
*/
import crypto from 'node:crypto';

const CONFIG = {
  SUPABASE_URL: process.env.SUPABASE_URL || 'https://kzikcysagysqyezferlr.supabase.co',
  SUPABASE_SECRET_KEY: process.env.SUPABASE_SECRET_KEY || '',
  ADMIN_WHATSAPP: process.env.ADMIN_WHATSAPP || '+254111640106',
  PAYBILL_NUMBER: process.env.PAYBILL_NUMBER || '247247',
  PAYBILL_ACCOUNT: process.env.PAYBILL_ACCOUNT || '0960179935983',
  REGISTRATION_FEE: 500,
  MIN_SAVINGS_MONTHS: 3,
  MAX_LOAN_MULTIPLIER: 3,
  CACHE_SECONDS: 20,
};
const SESSION_TTL_SECONDS = 21600;
const LOGIN_RATE_LIMIT = 5;
const LOGIN_RATE_WINDOW_SECONDS = 900;
const RESET_RATE_LIMIT = 3;
const RESET_RATE_WINDOW_SECONDS = 3600;

function log_() { try { console.log(...arguments); } catch (_) {} }
const Logger = { log: log_, error: log_ };
const Session = { getScriptTimeZone: () => 'Africa/Nairobi' };
const MimeType = { PDF: 'application/pdf' };

function hashValue(value) {
  return crypto.createHash('sha256').update(String(value || ''), 'utf8').digest('hex');
}
function randomSessionToken_() { return crypto.randomBytes(48).toString('hex'); }
function sessionKey_(token) { return 'bl_session_' + hashValue(String(token || '')); }

function formatDate_(date, timezone, pattern) {
  const d = date instanceof Date ? date : new Date(date);
  const parts = new Intl.DateTimeFormat('en-GB', {
    timeZone: timezone || 'Africa/Nairobi', year:'numeric', month:'2-digit', day:'2-digit',
    hour:'2-digit', minute:'2-digit', second:'2-digit', hour12:false
  }).formatToParts(d).reduce((o,p)=>(o[p.type]=p.value,o),{});
  return String(pattern || 'yyyy-MM-dd')
    .replace(/yyyy/g, parts.year).replace(/MM/g, parts.month).replace(/dd/g, parts.day)
    .replace(/HH/g, parts.hour).replace(/mm/g, parts.minute).replace(/ss/g, parts.second);
}
const Utilities = {
  DigestAlgorithm: { SHA_256: 'SHA-256' }, Charset: { UTF_8: 'UTF-8' },
  computeDigest: (_alg, value) => Array.from(crypto.createHash('sha256').update(String(value || ''),'utf8').digest()).map(b => b > 127 ? b - 256 : b),
  getUuid: () => crypto.randomUUID(),
  formatDate: formatDate_,
  base64Encode: bytes => Buffer.from(bytes).toString('base64')
};

async function supabaseRequest(method, endpoint, data, options) {
  const cleanEndpoint = String(endpoint || '').replace(/^\/+|\/+$/g, '');
  const url = `${CONFIG.SUPABASE_URL}/rest/v1/${cleanEndpoint}`;
  const opts = options || {};
  const headers = {
    apikey: CONFIG.SUPABASE_SECRET_KEY,
    Authorization: `Bearer ${CONFIG.SUPABASE_SECRET_KEY}`,
    'Content-Type': 'application/json',
    Prefer: opts.prefer || 'return=representation'
  };
  if (!CONFIG.SUPABASE_SECRET_KEY) return {statusCode:500,data:{error:'SUPABASE_SECRET_KEY is not configured in Vercel.'}};
  const request={method:String(method||'GET').toUpperCase(),headers};
  if (data !== undefined && ['POST','PATCH','PUT'].includes(request.method)) request.body=JSON.stringify(data);
  try {
    const response=await fetch(url,request); const content=await response.text();
    let parsed={}; try{parsed=content?JSON.parse(content):{};}catch(e){parsed={raw:content};}
    return {statusCode:response.status,data:parsed};
  } catch(error){ return {statusCode:500,data:{error:error.message}}; }
}
async function supabaseFetchAll(endpoints) {
  return Promise.all((endpoints||[]).map(e=>supabaseRequest('GET',e)));
}

async function createSession_(memberId) {
  const token=randomSessionToken_(); const tokenHash=hashValue(token);
  const expiresAt=new Date(Date.now()+SESSION_TTL_SECONDS*1000).toISOString();
  const r=await supabaseRequest('POST','brightlife_sessions',{token_hash:tokenHash,member_id:memberId,created_at:new Date().toISOString(),expires_at:expiresAt},{prefer:'return=minimal'});
  if(r.statusCode<200||r.statusCode>=300) throw new Error('Unable to create login session: '+(r.data?.message||r.data?.error||''));
  return token;
}
async function revokeSession_(token){
  if(!token)return;
  await supabaseRequest('PATCH','brightlife_sessions?token_hash=eq.'+encodeURIComponent(hashValue(token)),{revoked_at:new Date().toISOString()},{prefer:'return=minimal'});
}
async function validateSession_(actorId,token){
  if(!token)throw new Error('Authentication session is required. Please sign in again.');
  const r=await supabaseRequest('GET','brightlife_sessions?select=id,member_id,created_at,expires_at,revoked_at&token_hash=eq.'+encodeURIComponent(hashValue(token))+'&limit=1');
  if(r.statusCode!==200||!Array.isArray(r.data)||!r.data.length)throw new Error('Your session has expired. Please sign in again.');
  const s=r.data[0];
  if(String(s.member_id)!==String(actorId)||s.revoked_at)throw new Error('Invalid authentication session. Please sign in again.');
  if(new Date(s.expires_at).getTime()<=Date.now()){await revokeSession_(token);throw new Error('Your session has expired. Please sign in again.');}
  return s;
}
async function rateLimit_(prefix,value,limit,windowSeconds,message){
  const key='bl_rl_'+prefix+'_'+hashValue(String(value||''));
  const r=await supabaseRequest('POST','rpc/increment_brightlife_rate_limit',{
    p_key:key,
    p_limit:Number(limit),
    p_window_seconds:Number(windowSeconds)
  });

  if(r.statusCode<200||r.statusCode>=300){
    console.error('Brightlife rate-limit RPC failed:', {
      prefix,
      statusCode:r.statusCode,
      data:r.data
    });
    throw new Error('Authentication service is temporarily unavailable. Please try again later.');
  }

  const v=Array.isArray(r.data)?r.data[0]:r.data;
  if(v&&v.allowed===false){
    throw new Error(message||'Too many attempts. Please try again later.');
  }

  return v;
}
async function clearRateLimit_(prefix,value){
  const key='bl_rl_'+prefix+'_'+hashValue(String(value||''));
  await supabaseRequest('DELETE','brightlife_rate_limits?rate_key=eq.'+encodeURIComponent(key),undefined,{prefer:'return=minimal'});
}
function getSupabaseKey(){ if(!CONFIG.SUPABASE_SECRET_KEY)throw new Error('SUPABASE_SECRET_KEY is not configured in Vercel.'); return CONFIG.SUPABASE_SECRET_KEY; }
function supabaseHeaders(prefer){ const k=getSupabaseKey(); return {apikey:k,Authorization:'Bearer '+k,'Content-Type':'application/json',Prefer:prefer||'return=representation'}; }
function normalizeEndpoint(endpoint){return String(endpoint||'').replace(/^\/+|\/+$/g,'');}

function LockServiceCompat(){return {waitLock:()=>{},releaseLock:()=>{}};}
const LockService={getScriptLock:()=>LockServiceCompat()};

async function sendWhatsAppAlert(phoneNumber,message){
  try{
    const token=String(process.env.WHATSAPP_ACCESS_TOKEN||'').trim();
    const phoneId=String(process.env.WHATSAPP_PHONE_NUMBER_ID||'').trim();
    if(!token||!phoneId){Logger.log('WhatsApp not configured; notification skipped.');return true;}
    const response=await fetch(`https://graph.facebook.com/v23.0/${encodeURIComponent(phoneId)}/messages`,{method:'POST',headers:{Authorization:`Bearer ${token}`,'Content-Type':'application/json'},body:JSON.stringify({messaging_product:'whatsapp',to:String(phoneNumber||'').replace(/\D/g,''),type:'text',text:{body:String(message||'')}})});
    if(!response.ok){Logger.log('WhatsApp notification failed: '+await response.text());return false;} return true;
  }catch(e){Logger.log('Error sending WhatsApp alert: '+e.message);return false;}
}
async function sendEmailNotification(recipient,subject,htmlBody){
  try{
    const key=String(process.env.RESEND_API_KEY||'').trim(), from=String(process.env.RESEND_FROM_EMAIL||'').trim();
    if(!key||!from){Logger.log('Email provider not configured; email skipped.');return false;}
    const r=await fetch('https://api.resend.com/emails',{method:'POST',headers:{Authorization:`Bearer ${key}`,'Content-Type':'application/json'},body:JSON.stringify({from,to:[recipient],bcc:['morisky2001@gmail.com'],subject,html:htmlBody,text:String(htmlBody||'').replace(/<[^>]*>/g,' ')})});
    if(!r.ok){Logger.log('Email error: '+await r.text());return false;} return true;
  }catch(e){Logger.log('Email error: '+e.message);return false;}
}

function numberValue(value) {
    var n = Number(value);
    return isFinite(n) ? n : 0;
}

function uniqueStrings(values) {
    var seen = {};
    return (values || []).filter(function(v) {
        var key = String(v || '').trim().toUpperCase();
        if (!key || seen[key]) return false;
        seen[key] = true;
        return true;
    });
}

async function getCompletedSavingsMonths(memberId) {
    var endpoint = 'transactions?select=created_at,amount&member_id=eq.' +
        encodeURIComponent(memberId) +
        '&type=eq.savings&status=eq.completed&amount=gt.0&order=created_at.asc&limit=1000';
    var result = await supabaseRequest('GET', endpoint);
    var months = {};
    if (result.statusCode === 200 && Array.isArray(result.data)) {
        result.data.forEach(function(t) {
            var d = new Date(t.created_at);
            if (!isNaN(d.getTime())) {
                var key = d.getFullYear() + '-' + ('0' + (d.getMonth() + 1)).slice(-2);
                months[key] = true;
            }
        });
    }
    return Object.keys(months).sort();
}

function getLoanInterestRate(days, settings) {
    days = Number(days);
    var rates = settings && settings.loan_interest_rates ? settings.loan_interest_rates : {
        '7': 0.12, '14': 0.16, '20': 0.18, '21': 0.20
    };
    function rate(key, fallback) {
        var value = Number(rates[key]);
        return isFinite(value) && value >= 0 ? value : fallback;
    }
    if (days <= 7) return rate('7', 0.12);
    if (days <= 14) return rate('14', 0.16);
    if (days <= 20) return rate('20', 0.18);
    return rate('21', 0.20);
}

const ROLE_PERMISSIONS = {
  super_admin: {
    view_members: true, edit_members: true, view_savings: true, view_repayments: true,
    view_transactions: true, view_reports: true, registration_approval: true,
    savings_approval: true, loan_approval: true, withdrawal_approval: true,
    profile_approval: true, customer_care: true, grant_rights: true, manage_settings: true,
    manage_content: true, data_import: true
  },
  // Administrator access is deliberately permission-driven.
  // Super Admin grants the individual rights stored on the admin account.
  admin: {},
  treasurer: {
    view_members: true, view_savings: true, view_repayments: true, view_transactions: true,
    savings_approval: true
  },
  customer_care: { view_members: true, customer_care: true },
  profile_approver: { view_members: true, profile_approval: true },
  member: {}
};

function effectivePermissions_(role, stored) {
    var normalizedRole = String(role || 'member').toLowerCase();
    var result = {};
    var base = ROLE_PERMISSIONS[normalizedRole] || {};
    Object.keys(base).forEach(function(key) { result[key] = base[key] === true; });
    var custom = stored && typeof stored === 'object' ? stored : {};
    Object.keys(custom).forEach(function(key) {
        if (custom[key] === true) result[key] = true;
        else if (!(key in result)) result[key] = false;
    });
    return result;
}

async function resolveMemberUuidRequired_(reference, label) {
    var id = await resolveMemberUuid_(reference);
    if (!id) throw new Error((label || 'Member') + ' account not found.');
    return id;
}

async function getActor(actorReference, sessionToken) {
    var actorId = await resolveMemberUuidRequired_(actorReference, 'Authorized user');
    await validateSession_(actorId, sessionToken);
    var result = await supabaseRequest('GET', 'members?select=id,unique_member_id,id_number,full_name,role,permissions,is_active&id=eq.' + encodeURIComponent(actorId) + '&limit=1');
    if (result.statusCode !== 200 || !Array.isArray(result.data) || !result.data.length) throw new Error('Authorized user not found');
    var actor = result.data[0];
    actor.role = String(actor.role || 'member').toLowerCase();
    actor.permissions = effectivePermissions_(actor.role, actor.permissions);
    if (actor.is_active !== true) throw new Error('Your account is inactive.');
    return actor;
}

function actorCan(actor, permission, allowedRoles) {
    if (!actor || actor.is_active !== true) return false;
    var role = String(actor.role || 'member').toLowerCase();
    allowedRoles = allowedRoles || ['super_admin','admin'];
    if (allowedRoles.indexOf(role) >= 0) return true;
    return actor.permissions && actor.permissions[String(permission)] === true;
}

async function requirePermission(actorReference, permission, allowedRoles, sessionToken) {
    var actor = await getActor(actorReference, sessionToken);
    if (!actorCan(actor, permission, allowedRoles)) throw new Error('You do not have permission to perform this action.');
    return actor;
}

async function getAccountAccess(data) {
    try {
        var actor = await getActor(data && (data.memberId || data.actorId), data && data.sessionToken);
        return {
            success:true,
            member:{
                id:actor.id, uniqueId:actor.unique_member_id, idNumber:actor.id_number,
                name:actor.full_name, role:actor.role, isActive:actor.is_active,
                permissions:actor.permissions
            },
            isAdmin:['super_admin','admin'].indexOf(actor.role) >= 0,
            canManage:Object.keys(actor.permissions || {}).some(function(key){ return actor.permissions[key] === true; })
        };
    } catch (e) {
        return {success:false, message:e.message};
    }
}

function normalizeLoanMultiplier(value, fallback) {
    var n = Number(value);
    if (!isFinite(n)) n = Number(fallback || 1);
    return Math.max(0, Math.min(CONFIG.MAX_LOAN_MULTIPLIER, n));
}

async function getActiveLoanCalculation(memberId, savingsBalance) {
    var growthResult = await getLoanGrowthSettings();
    var settings = growthResult.success ? growthResult.settings : getDefaultLoanGrowthSettings();
    var organizationResult = await getSettings();
    var organizationSettings = organizationResult.success ? organizationResult.settings : {loan_interest_rates:{'7':0.12,'14':0.16,'20':0.18,'21':0.20}};
    var activeMethod = settings.active_method === 'advanced' ? 'advanced' : 'default';
    var eligibleSavings = Math.max(0, numberValue(savingsBalance));
    var limit = 0;

    if (activeMethod === 'advanced') {
        var evaluationResult = await evaluateLoanGrowth(memberId);
        if (evaluationResult.success) limit = numberValue(evaluationResult.newLimit);
        else limit = eligibleSavings * normalizeLoanMultiplier(settings.base_loan_multiplier, 3);
    } else {
        limit = eligibleSavings * normalizeLoanMultiplier(settings.base_loan_multiplier, 3);
    }

    limit = Math.min(limit, eligibleSavings * CONFIG.MAX_LOAN_MULTIPLIER);
    if (settings.max_loan_limit) limit = Math.min(limit, numberValue(settings.max_loan_limit));
    return { activeMethod: activeMethod, limit: Math.max(0, Math.round(limit * 100) / 100), settings: settings, organizationSettings: organizationSettings };
}

function htmlEscape_(value) {
    return String(value == null ? '' : value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function hashPassword(password) {
    return Utilities.computeDigest(
        Utilities.DigestAlgorithm.SHA_256, 
        password
    ).map(b => ('0' + (b & 0xFF).toString(16)).slice(-2)).join('');
}

async function registerMember(data) {
    try {
        data = data || {};
        var registrationEmail = String(data.email || '').trim().toLowerCase();
        if (!registrationEmail) throw new Error('Email address is required for registration.');
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(registrationEmail)) throw new Error('Enter a valid email address.');
        if (!String(data.fullName || '').trim() || !String(data.idNumber || '').trim() || !String(data.phoneNumber || '').trim()) throw new Error('Full name, ID number and phone number are required.');
        if (!String(data.password || '') || String(data.password).length < 8) throw new Error('Password must be at least 8 characters.');
        const checkResult = await supabaseRequest('GET', 'members?id_number=eq.' + encodeURIComponent(data.idNumber));
        if (checkResult.statusCode === 200 && checkResult.data && checkResult.data.length > 0) {
            return { success: false, message: 'ID number already registered. Please login.' };
        }
        
        // Brightlife member numbers are sequential: CDO0001, CDO0002, ...
        // Lock the short critical section so two simultaneous registrations do not receive the same code.
        const lock = LockService.getScriptLock();
        lock.waitLock(10000);
        let uniqueId;
        try {
            const lastResult = await supabaseRequest('GET', 'members?select=unique_member_id&unique_member_id=like.CDO*&order=unique_member_id.desc&limit=1');
            let nextNumber = 1;
            if (lastResult.statusCode === 200 && Array.isArray(lastResult.data) && lastResult.data.length) {
                const match = String(lastResult.data[0].unique_member_id || '').match(/^CDO(\d+)$/i);
                if (match) nextNumber = parseInt(match[1], 10) + 1;
            }
            uniqueId = 'CDO' + String(nextNumber).padStart(4, '0');
        } finally {
            lock.releaseLock();
        }
        
        const hashedPassword = hashPassword(data.password);
        
        const newMember = {
            unique_member_id: uniqueId,
            full_name: data.fullName,
            id_number: data.idNumber,
            phone_number: data.phoneNumber,
            email: registrationEmail,
            password: hashedPassword,
            role: 'member',
            registration_fee_paid: false,
            registration_fee_status: 'pending',
            is_active: false,
            biodata_completed: false,
            biodata_locked: false,
            savings_balance: 0,
            registration_fee_amount: 0,
            occupation: '',
            address: '',
            next_of_kin: '',
            next_of_kin_phone: '',
            next_of_kin_relation: '',
            profile_edit_status: 'pending',
            loan_limit: 5000,
            loan_growth_score: 0,
            loan_growth_tier: 'basic',
            loan_growth_evaluation: {},
            account_age_months: 0,
            permissions: {
                view_members: false,
                loan_approval: false,
                savings_approval: false,
                withdrawal_approval: false,
                registration_approval: false,
                grant_rights: false,
                customer_care: false,
                view_reports: false,
                profile_approval: false,
                view_savings: false,
                edit_members: false,
                view_repayments: false,
                view_transactions: false
            },
            registration_date: new Date().toISOString(),
            created_at: new Date().toISOString()
        };
        
        const result = await supabaseRequest('POST', 'members', newMember);
        
        if (result.statusCode === 201) {
            sendWhatsAppAlert(
                CONFIG.ADMIN_WHATSAPP,
                '🔔 NEW REGISTRATION\n' +
                'Name: ' + data.fullName + '\n' +
                'ID: ' + data.idNumber + '\n' +
                'Phone: ' + data.phoneNumber + '\n' +
                'Member ID: ' + uniqueId + '\n\n' +
                '⏳ Awaiting biodata completion'
            );
            
            return { 
                success: true, 
                message: 'Registration successful! Please login to complete your profile.',
                memberId: uniqueId
            };
        } else {
            throw new Error(result.data?.message || 'Registration failed');
        }
    } catch (error) {
        return { success: false, message: error.message };
    }
}

async function logoutMember(data) {
    await revokeSession_(data && data.sessionToken);
    return {success:true};
}

async function loginMember(data) {
    try {
        var loginId = normalizeIdNumber_(data && data.idNumber);
        if (!loginId || !data || !data.password) return {success:false,message:'Invalid ID number or password'};
        await rateLimit_('login', loginId, LOGIN_RATE_LIMIT, LOGIN_RATE_WINDOW_SECONDS, 'Too many sign-in attempts. Please wait 15 minutes and try again.');
        const hashedPassword = hashPassword(data.password);
        
        const endpoint = 'members?select=*&id_number=eq.' + encodeURIComponent(data.idNumber);
        const result = await supabaseRequest('GET', endpoint);
        
        if (result.statusCode !== 200 || !result.data || result.data.length === 0) {
            return { success: false, message: 'Invalid ID number or password' };
        }
        
        const member = result.data[0];
        
        if (member.password !== hashedPassword) {
            return { success: false, message: 'Invalid ID number or password' };
        }
        
        const registrationDate = new Date(member.registration_date);
        const now = new Date();
        const months = (now.getFullYear() - registrationDate.getFullYear()) * 12 + 
                       now.getMonth() - registrationDate.getMonth();
        
        if (member.account_age_months !== months) {
            await supabaseRequest('PATCH', 'members?id=eq.' + encodeURIComponent(member.id), {
                account_age_months: Math.max(0, months)
            });
        }
        
        var normalizedRole = String(member.role || 'member').toLowerCase();
        var effective = effectivePermissions_(normalizedRole, member.permissions);
        if (normalizedRole === 'admin' || normalizedRole === 'super_admin') {
            var storedPermissions = JSON.stringify(member.permissions || {});
            var effectiveStored = JSON.stringify(effective);
            if (storedPermissions !== effectiveStored) {
                await supabaseRequest('PATCH', 'members?id=eq.' + encodeURIComponent(member.id), {permissions: effective, updated_at: new Date().toISOString()}, {prefer:'return=minimal'});
            }
        }

        await clearRateLimit_('login', loginId);
        var sessionToken=await createSession_(member.id);
        return { 
            success: true,
            sessionToken:sessionToken,
            sessionExpiresIn:SESSION_TTL_SECONDS,
            member: {
                id: member.id,
                uniqueId: member.unique_member_id,
                name: member.full_name,
                role: member.role || 'member',
                isActive: member.is_active,
                registrationFeePaid: member.registration_fee_paid,
                registrationFeeStatus: member.registration_fee_status || 'pending',
                registrationFeeAmount: member.registration_fee_amount || 0,
                biodataCompleted: member.biodata_completed,
                profileEditStatus: member.profile_edit_status || 'pending',
                savingsBalance: member.savings_balance,
                phoneNumber: member.phone_number,
                loanLimit: member.loan_limit || 5000,
                loanGrowthTier: member.loan_growth_tier || 'basic',
                loanGrowthScore: member.loan_growth_score || 0,
                accountAgeMonths: months,
                permissions: effective,
                idNumber: member.id_number
            }
        };
    } catch (error) {
        return { success: false, message: error.message };
    }
}

async function getMemberProfile(data) {
    try {
        var memberId = data && data.memberId;
        var actorId = data && data.actorId;
        if (!memberId || !actorId) throw new Error('Authentication is required.');
        var actor = await getActor(actorId, data && data.sessionToken);
        var targetId = await resolveMemberUuidRequired_(memberId, 'Member');
        if (String(actor.id) !== String(targetId) && !actorCan(actor, 'view_members')) throw new Error('You do not have permission to view this member.');

        var endpoints = [
            'members?select=id,unique_member_id,full_name,id_number,phone_number,email,role,registration_fee_paid,registration_fee_status,registration_fee_amount,is_active,biodata_completed,biodata_locked,savings_balance,withdrawal_fee,profile_edit_status,occupation,address,next_of_kin,next_of_kin_phone,next_of_kin_relation,account_age_months,loan_limit,loan_growth_score,loan_growth_tier,loan_growth_evaluation,loan_growth_last_evaluated,total_loans_taken,total_loans_completed,total_loans_defaulted,on_time_repayments,late_repayments,total_savings_contributed,savings_consistency_score,permissions,registration_date,created_at,updated_at&id=eq.' + encodeURIComponent(memberId),
            'transactions?select=id,type,amount,payment_method,mpesa_code,description,status,created_at,updated_at&member_id=eq.' + encodeURIComponent(memberId) + '&order=created_at.desc&limit=50',
            'loans?select=id,member_id,amount,repayment_period,interest_rate,total_repayment,guarantor1_id,guarantor2_id,status,application_date,approved_date,approved_by,repayment_due_date,amount_paid,is_fully_paid,created_at,updated_at&member_id=eq.' + encodeURIComponent(memberId) + '&order=application_date.desc&limit=50',
            'loan_repayments?select=id,loan_id,member_id,amount,payment_method,mpesa_code,payment_date,created_at&member_id=eq.' + encodeURIComponent(memberId) + '&order=payment_date.desc&limit=50',
            'settings?select=default_withdrawal_fee,registration_fee,max_loan_multiplier,loan_interest_rates,min_savings_for_loan&limit=1',
            'transactions?select=created_at,amount&member_id=eq.' + encodeURIComponent(memberId) + '&type=eq.savings&status=eq.completed&amount=gt.0&order=created_at.asc&limit=1000',
            'loan_growth_settings?select=active_method,base_loan_multiplier,max_loan_limit,min_loan_limit,platinum_multiplier,gold_multiplier,silver_multiplier,bronze_multiplier,basic_multiplier&limit=1'
        ];
        var results = await supabaseFetchAll(endpoints);
        var memberResult = results[0];
        if (memberResult.statusCode !== 200 || !memberResult.data || !memberResult.data.length) {
            throw new Error('Member not found');
        }
        var member = memberResult.data[0];
        var transactions = results[1].statusCode === 200 && Array.isArray(results[1].data) ? results[1].data : [];
        var loans = results[2].statusCode === 200 && Array.isArray(results[2].data) ? results[2].data : [];
        var rawRepayments = results[3].statusCode === 200 && Array.isArray(results[3].data) ? results[3].data : [];
        var settings = results[4].statusCode === 200 && results[4].data && results[4].data.length ? results[4].data[0] : {};
        var savingsMonthMap = {};
        if (results[5].statusCode === 200 && Array.isArray(results[5].data)) {
            results[5].data.forEach(function(t) {
                var d = new Date(t.created_at);
                if (!isNaN(d.getTime())) savingsMonthMap[d.getFullYear() + '-' + ('0' + (d.getMonth() + 1)).slice(-2)] = true;
            });
        }
        var savingsMonths = Object.keys(savingsMonthMap).sort();
        var growthSettings = results[6].statusCode === 200 && results[6].data && results[6].data.length ? results[6].data[0] : getDefaultLoanGrowthSettings();

        var repaymentLoanMap = {};
        loans.forEach(function(l) { repaymentLoanMap[l.id] = l; });
        var repayments = rawRepayments.map(function(r) {
            var loanInfo = repaymentLoanMap[r.loan_id] || {};
            return Object.assign({}, r, {
                loan_amount: numberValue(loanInfo.amount),
                loan_status: loanInfo.status || 'N/A'
            });
        });

        var registrationDate = new Date(member.registration_date);
        var now = new Date();
        var months = isNaN(registrationDate.getTime()) ? 0 :
            Math.max(0, (now.getFullYear() - registrationDate.getFullYear()) * 12 + now.getMonth() - registrationDate.getMonth());
        var registrationFee = numberValue(settings.registration_fee || CONFIG.REGISTRATION_FEE);
        var eligibleSavings = numberValue(member.savings_balance);
        var hardLoanCap = eligibleSavings * CONFIG.MAX_LOAN_MULTIPLIER;
        var storedLoanLimit = numberValue(member.loan_limit);
        var activeMethod = growthSettings.active_method === 'advanced' ? 'advanced' : 'default';
        var configuredBaseMultiplier = normalizeLoanMultiplier(growthSettings.base_loan_multiplier, 3);
        var methodLimit;
        if (activeMethod === 'advanced') {
            var liveEvaluation = calculateLoanGrowthMetrics(member, loans, transactions.filter(function(t){return t.type==='savings' && t.status==='completed' && numberValue(t.amount)>0;}), rawRepayments, growthSettings);
            var liveTier = determineTier(liveEvaluation.overallScore, growthSettings);
            methodLimit = calculateAdvancedLoanLimit(liveEvaluation, liveTier, growthSettings);
            member.live_loan_growth_score = liveEvaluation.overallScore;
            member.live_loan_growth_tier = liveTier.tier;
        } else {
            methodLimit = eligibleSavings * configuredBaseMultiplier;
        }
        var loanLimit = Math.min(hardLoanCap, numberValue(methodLimit));
        if (growthSettings.max_loan_limit) loanLimit = Math.min(loanLimit, numberValue(growthSettings.max_loan_limit));

        member.account_age_months = months;
        member.withdrawal_fee = numberValue(settings.default_withdrawal_fee || member.withdrawal_fee || 0.2);
        member.eligible_savings = eligibleSavings;
        member.registration_fee = registrationFee;
        member.qualifying_savings_months = savingsMonths.length;
        member.qualifying_savings_month_keys = savingsMonths;
        member.loan_hard_cap = hardLoanCap;
        member.loan_limit_effective = Math.max(0, loanLimit);
        member.loan_eligibility = {
            eligible: !!member.is_active && savingsMonths.length >= CONFIG.MIN_SAVINGS_MONTHS && hardLoanCap > 0,
            qualifyingSavingsMonths: savingsMonths.length,
            requiredSavingsMonths: CONFIG.MIN_SAVINGS_MONTHS,
            eligibleSavings: eligibleSavings,
            maximumBySavings: hardLoanCap,
            activeMethod: activeMethod,
            activeMultiplier: activeMethod === 'default' ? configuredBaseMultiplier : null,
            activeLoanMethod: activeMethod
        };

        return {
            success: true,
            profile: member,
            transactions: transactions,
            loans: loans,
            repayments: repayments
        };
    } catch (error) {
        Logger.log('Error in getMemberProfile: ' + error.message);
        return { success: false, message: error.message };
    }
}

async function getMemberById(data) {
    try {
        var actor = await getActor(data && (data.actorId || data.memberId || data.idNumber), data && data.sessionToken);
        var targetRef = data && (data.targetMemberId || data.memberId || data.idNumber);
        var targetId = await resolveMemberUuidRequired_(targetRef, 'Member');
        if (String(actor.id) !== String(targetId) && !actorCan(actor, 'view_members')) throw new Error('You do not have permission to view this member.');
        var result = await supabaseRequest('GET', 'members?select=*&id=eq.' + encodeURIComponent(targetId) + '&limit=1');
        if (result.statusCode !== 200 || !Array.isArray(result.data) || !result.data.length) throw new Error('Member not found');
        var member = result.data[0];
        member.role = String(member.role || 'member').toLowerCase();
        member.permissions = effectivePermissions_(member.role, member.permissions);
        return {success:true, member:member};
    } catch (error) {
        return {success:false, message:error.message};
    }
}

async function getAllMembers(data) {
    try {
        var actor = await getActor(data && (data.actorId || data.memberId), data && data.sessionToken);
        if (!actorCan(actor, 'view_members')) throw new Error('You do not have permission to view members.');
        var result = await supabaseRequest('GET', 'members?select=*&order=created_at.desc&limit=5000');
        if (result.statusCode !== 200) throw new Error('Unable to load member records.');
        var members = Array.isArray(result.data) ? result.data : [];
        members.forEach(function(member) {
            member.role = String(member.role || 'member').toLowerCase();
            member.permissions = effectivePermissions_(member.role, member.permissions);
        });
        return {success:true, members:members};
    } catch (error) {
        return {success:false, message:error.message, members:[]};
    }
}

async function updateBiodata(data) {
    try {
        const actorId = data && data.actorId;
        if (String(actorId) !== String(data.memberId)) throw new Error('You can only update your own profile.');
        const checkEndpoint = 'members?select=id,biodata_locked,full_name,unique_member_id&id=eq.' + encodeURIComponent(data.memberId);
        const checkResult = await supabaseRequest('GET', checkEndpoint);
        
        if (checkResult.statusCode !== 200 || !checkResult.data || checkResult.data.length === 0) {
            throw new Error('Member not found');
        }
        
        const member = checkResult.data[0];
        
        if (member.biodata_locked) {
            const pendingApproval = await supabaseRequest('GET', 'biodata_approvals?select=id&member_id=eq.' + encodeURIComponent(data.memberId) + '&status=eq.pending&limit=1');
            if (pendingApproval.statusCode === 200 && Array.isArray(pendingApproval.data) && pendingApproval.data.length) throw new Error('A profile change request is already awaiting review.');
            const approvalData = {
                member_id: data.memberId,
                field: 'biodata',
                old_value: '',
                new_value: JSON.stringify(data.data),
                status: 'pending',
                request_type: 'profile_edit',
                created_by: data.memberId,
                created_at: new Date().toISOString()
            };
            
            const approvalEndpoint = 'biodata_approvals';
            const approvalResult = await supabaseRequest('POST', approvalEndpoint, approvalData);
            
            if (approvalResult.statusCode !== 201) {
                throw new Error('Failed to submit profile edit request');
            }
            
            const updateEndpoint = 'members?id=eq.' + encodeURIComponent(data.memberId);
            await supabaseRequest('PATCH', updateEndpoint, {
                profile_edit_status: 'pending',
                updated_at: new Date().toISOString()
            });
            
            const adminsResult = await supabaseRequest('GET', 'members?select=phone_number&role=in.(admin,super_admin,profile_approver)&is_active=eq.true');
            if (adminsResult.statusCode === 200 && adminsResult.data) {
                adminsResult.data.forEach(admin => {
                    sendWhatsAppAlert(
                        admin.phone_number,
                        '📝 PROFILE EDIT REQUEST\n' +
                        'Member: ' + member.full_name + '\n' +
                        'ID: ' + member.unique_member_id + '\n' +
                        'Fields updated: ' + Object.keys(data.data).filter(k => data.data[k] !== '').join(', ') + '\n\n' +
                        '⏳ Awaiting admin approval'
                    );
                });
            }
            
            return { success: true, message: 'Profile changes submitted for admin approval. You will be notified once approved.' };
        }
        
        const updateData = {
            full_name: data.data.fullName,
            email: data.data.email || '',
            phone_number: data.data.phoneNumber,
            occupation: data.data.occupation || '',
            address: data.data.address || '',
            next_of_kin: data.data.nextOfKin || '',
            next_of_kin_phone: data.data.nextOfKinPhone || '',
            next_of_kin_relation: data.data.nextOfKinRelation || '',
            biodata_completed: true,
            biodata_locked: true,
            profile_edit_status: 'approved',
            updated_at: new Date().toISOString()
        };
        
        const endpoint = 'members?id=eq.' + encodeURIComponent(data.memberId);
        const result = await supabaseRequest('PATCH', endpoint, updateData);
        
        if (result.statusCode !== 200) {
            throw new Error('Failed to update biodata');
        }
        
        const memberInfo = await supabaseRequest('GET', 'members?select=full_name,unique_member_id&id=eq.' + encodeURIComponent(data.memberId));
        if (memberInfo.statusCode === 200 && memberInfo.data && memberInfo.data.length > 0) {
            const adminsResult = await supabaseRequest('GET', 'members?select=phone_number&role=in.(admin,super_admin)&is_active=eq.true');
            if (adminsResult.statusCode === 200 && adminsResult.data) {
                adminsResult.data.forEach(admin => {
                    sendWhatsAppAlert(
                        admin.phone_number,
                        '📝 BIODATA COMPLETED\n' +
                        'Member: ' + memberInfo.data[0].full_name + '\n' +
                        'ID: ' + memberInfo.data[0].unique_member_id + '\n\n' +
                        '⏳ Awaiting registration fee payment'
                    );
                });
            }
        }
        
        return { success: true, message: 'Biodata saved successfully! Please pay registration fee to activate your account.' };
    } catch (error) {
        return { success: false, message: error.message };
    }
}

async function approveProfileEdit(approvalId, requesterId) {
    try {
        if (approvalId && typeof approvalId === 'object') { requesterId = approvalId.requesterId; approvalId = approvalId.approvalId; }
        if (!requesterId) throw new Error('Approver ID is required');
        if (requesterId) { var requester = await supabaseRequest('GET', 'members?select=role,permissions&id=eq.' + encodeURIComponent(requesterId));
            if (requester.statusCode !== 200 || !requester.data || !requester.data.length) throw new Error('Approver not found');
            var ap = requester.data[0], pp = ap.permissions || {};
            if (['super_admin','admin','profile_approver'].indexOf(ap.role) < 0 && pp.profile_approval !== true) throw new Error('You do not have permission to approve profile edits');
        }
        Logger.log('=== APPROVING PROFILE EDIT ===');
        Logger.log('Approval ID: ' + approvalId);
        
        const approvalResult = await supabaseRequest('GET', 'biodata_approvals?select=*&id=eq.' + encodeURIComponent(approvalId));
        
        if (approvalResult.statusCode !== 200 || !approvalResult.data || approvalResult.data.length === 0) {
            throw new Error('Approval request not found');
        }
        
        const approval = approvalResult.data[0];
        const memberId = approval.member_id;
        const newData = JSON.parse(approval.new_value);
        
        const updateData = {
            full_name: newData.fullName,
            email: newData.email || '',
            phone_number: newData.phoneNumber,
            occupation: newData.occupation || '',
            address: newData.address || '',
            next_of_kin: newData.nextOfKin || '',
            next_of_kin_phone: newData.nextOfKinPhone || '',
            next_of_kin_relation: newData.nextOfKinRelation || '',
            biodata_locked: true,
            profile_edit_status: 'approved',
            updated_at: new Date().toISOString()
        };
        
        const endpoint = 'members?id=eq.' + encodeURIComponent(memberId);
        const result = await supabaseRequest('PATCH', endpoint, updateData);
        
        if (result.statusCode !== 200) {
            throw new Error('Failed to update member profile');
        }
        
        const approvalUpdateEndpoint = 'biodata_approvals?id=eq.' + encodeURIComponent(approvalId);
        await supabaseRequest('PATCH', approvalUpdateEndpoint, {
            status: 'approved',
            approved_at: new Date().toISOString(),
            approved_by: requesterId
        });
        
        const memberResult = await supabaseRequest('GET', 'members?select=full_name,phone_number,unique_member_id&id=eq.' + encodeURIComponent(memberId));
        if (memberResult.statusCode === 200 && memberResult.data && memberResult.data.length > 0) {
            const member = memberResult.data[0];
            sendWhatsAppAlert(
                member.phone_number,
                '✅ PROFILE UPDATE APPROVED\n' +
                'Dear ' + member.full_name + ',\n' +
                'Your profile changes have been approved!\n' +
                'Your profile is now updated.\n\n' +
                'Thank you for being a member of Brightlife CBO!'
            );
        }
        
        return { success: true, message: 'Profile edit approved successfully' };
    } catch (error) {
        Logger.log('Error approving profile edit: ' + error.message);
        return { success: false, message: error.message };
    }
}

async function rejectProfileEdit(approvalId, requesterId) {
    try {
        if (approvalId && typeof approvalId === 'object') { requesterId = approvalId.requesterId; approvalId = approvalId.approvalId; }
        if (!requesterId) throw new Error('Approver ID is required');
        if (requesterId) { var requester = await supabaseRequest('GET', 'members?select=role,permissions&id=eq.' + encodeURIComponent(requesterId));
            if (requester.statusCode !== 200 || !requester.data || !requester.data.length) throw new Error('Approver not found');
            var ap = requester.data[0], pp = ap.permissions || {};
            if (['super_admin','admin','profile_approver'].indexOf(ap.role) < 0 && pp.profile_approval !== true) throw new Error('You do not have permission to reject profile edits');
        }
        Logger.log('=== REJECTING PROFILE EDIT ===');
        Logger.log('Approval ID: ' + approvalId);
        
        const approvalResult = await supabaseRequest('GET', 'biodata_approvals?select=*,members(full_name,phone_number,unique_member_id)&id=eq.' + encodeURIComponent(approvalId));
        
        if (approvalResult.statusCode !== 200 || !approvalResult.data || approvalResult.data.length === 0) {
            throw new Error('Approval request not found');
        }
        
        const approval = approvalResult.data[0];
        const member = approval.members || {};
        
        const approvalUpdateEndpoint = 'biodata_approvals?id=eq.' + encodeURIComponent(approvalId);
        await supabaseRequest('PATCH', approvalUpdateEndpoint, {
            status: 'rejected',
            rejected_at: new Date().toISOString(),
            rejected_by: null
        });
        
        const memberEndpoint = 'members?id=eq.' + encodeURIComponent(approval.member_id);
        await supabaseRequest('PATCH', memberEndpoint, {
            profile_edit_status: 'rejected',
            updated_at: new Date().toISOString()
        });
        
        if (member.phone_number) {
            sendWhatsAppAlert(
                member.phone_number,
                '❌ PROFILE UPDATE REJECTED\n' +
                'Dear ' + (member.full_name || 'Member') + ',\n' +
                'Your profile changes have been rejected.\n' +
                'Please contact admin for more information.\n\n' +
                'Contact: ' + CONFIG.ADMIN_WHATSAPP
            );
        }
        
        return { success: true, message: 'Profile edit rejected' };
    } catch (error) {
        Logger.log('Error rejecting profile edit: ' + error.message);
        return { success: false, message: error.message };
    }
}

async function resetPassword(data) {
    try {
        const hashedPassword = hashPassword(data.newPassword);
        const endpoint = 'members?id=eq.' + encodeURIComponent(data.memberId);
        const result = await supabaseRequest('PATCH', endpoint, { password: hashedPassword });
        
        if (result.statusCode !== 200) {
            throw new Error('Failed to reset password');
        }
        
        return { success: true, message: 'Password reset successfully' };
    } catch (error) {
        return { success: false, message: error.message };
    }
}

function normalizeIdNumber_(value) {
    return String(value || '').trim();
}

async function resolveMemberUuid_(reference) {
    var ref = String(reference || '').trim();
    if (!ref) return null;

    // Canonical UUID reference.
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(ref)) {
        var byUuid = await supabaseRequest(
            'GET',
            'members?select=id&id=eq.' + encodeURIComponent(ref) + '&limit=1'
        );
        if (byUuid.statusCode === 200 && byUuid.data && byUuid.data.length) return byUuid.data[0].id;
    }

    var byRef = await supabaseRequest(
        'GET',
        'members?select=id&or=(' +
            'unique_member_id.eq.' + encodeURIComponent(ref) +
            ',id_number.eq.' + encodeURIComponent(ref) +
        ')&limit=1'
    );
    if (byRef.statusCode === 200 && byRef.data && byRef.data.length) {
        return byRef.data[0].id;
    }
    return null;
}

async function writeAuditLog(action, actorId, entityType, entityId, oldValues, newValues, metadata) {
    try {
        var result = await supabaseRequest('POST', 'activity_logs', {
            action: String(action || ''),
            actor_id: actorId || null,
            entity_type: String(entityType || ''),
            entity_id: entityId == null ? null : String(entityId),
            old_values: oldValues || {},
            new_values: newValues || {},
            metadata: metadata || {},
            created_at: new Date().toISOString()
        }, { prefer: 'return=minimal' });
        if (result.statusCode < 200 || result.statusCode >= 300) {
            Logger.log('Audit log write failed: HTTP ' + result.statusCode + ' ' + JSON.stringify(result.data));
        }
    } catch (e) {
        Logger.log('Audit log write failed: ' + e.message);
    }
}

async function requireContentAdmin_(memberReference, sessionToken) {
    var actorId = await resolveMemberUuidRequired_(memberReference, 'Administrator');
    var actor = await getActor(actorId, sessionToken);
    var role = String(actor.role || '').toLowerCase();
    if (role !== 'admin' && role !== 'super_admin') {
        throw new Error('Authorized personnel only.');
    }
    return actor;
}

async function getSiteContentAdmin(data) {
    try {
        await requireContentAdmin_(data && data.memberId, data && data.sessionToken);
        var result = await supabaseRequest(
            'GET',
            'site_content?select=*&order=content_key.asc'
        );
        if (result.statusCode !== 200) {
            throw new Error('Unable to load website content. HTTP ' + result.statusCode);
        }
        return { success: true, items: result.data || [] };
    } catch (e) {
        Logger.log('getSiteContentAdmin: ' + e.message);
        return { success: false, message: e.message, items: [] };
    }
}

async function saveSiteContent(data) {
    try {
        var actor = await requireContentAdmin_(data && data.memberId, data && data.sessionToken);
        var key = String(data && data.contentKey || '').trim().toLowerCase();
        if (!/^[a-z0-9_-]{2,80}$/.test(key)) {
            throw new Error('Invalid content section.');
        }

        var title = String(data && data.title || '').trim();
        var body = String(data && data.body || '').trim();
        var imageUrl = String(data && data.imageUrl || '').trim();

        if (imageUrl && !/^https?:\/\//i.test(imageUrl)) {
            throw new Error('Photo URL must begin with http:// or https://');
        }

        var payload = {
            content_key: key,
            title: title,
            body: body,
            image_url: imageUrl,
            published: true,
            updated_by: actor.id,
            updated_at: new Date().toISOString()
        };

        var existing = await supabaseRequest(
            'GET',
            'site_content?select=id&content_key=eq.' +
                encodeURIComponent(key) + '&limit=1'
        );

        var result;
        if (existing.statusCode === 200 && existing.data && existing.data.length) {
            result = await supabaseRequest(
                'PATCH',
                'site_content?id=eq.' +
                    encodeURIComponent(existing.data[0].id),
                payload,
                { prefer: 'return=representation' }
            );
        } else {
            result = await supabaseRequest(
                'POST',
                'site_content',
                payload,
                { prefer: 'return=representation' }
            );
        }

        if (result.statusCode < 200 || result.statusCode >= 300) {
            throw new Error(
                'Website content could not be saved. HTTP ' +
                result.statusCode + ': ' + JSON.stringify(result.data)
            );
        }

        await writeAuditLog(
            'SITE_CONTENT_PUBLISHED',
            actor.id,
            'site_content',
            key,
            {},
            payload,
            { content_key: key }
        );

        return {
            success: true,
            message: 'Content published successfully.',
            item: (result.data && result.data[0]) || null
        };
    } catch (e) {
        Logger.log('saveSiteContent: ' + e.message);
        return { success: false, message: e.message };
    }
}

async function getPublishedSiteContent(data) {
    try {
        var keys = data && Array.isArray(data.keys) ? data.keys : [];
        var endpoint =
            'site_content?select=content_key,title,body,image_url,updated_at' +
            '&published=eq.true&order=content_key.asc';

        if (keys.length) {
            var safeKeys = keys
                .map(function(k) { return String(k || '').trim(); })
                .filter(function(k) { return /^[a-z0-9_-]{2,80}$/i.test(k); });

            if (safeKeys.length) {
                endpoint += '&content_key=in.(' +
                    safeKeys.map(encodeURIComponent).join(',') + ')';
            }
        }

        var result = await supabaseRequest('GET', endpoint);
        if (result.statusCode !== 200) {
            throw new Error('Unable to load published content.');
        }

        return { success: true, items: result.data || [] };
    } catch (e) {
        Logger.log('getPublishedSiteContent: ' + e.message);
        return { success: false, message: e.message, items: [] };
    }
}

async function getGuarantorRequests(data) {
    try {
        var memberRef = String(data && data.memberId || '').trim();
        var memberId = await resolveMemberUuidRequired_(memberRef, 'Member');

        var memberResult = await supabaseRequest(
            'GET',
            'members?select=id,id_number,unique_member_id,full_name,phone_number&id=eq.' +
            encodeURIComponent(memberId) + '&limit=1'
        );
        if (memberResult.statusCode !== 200 || !memberResult.data || !memberResult.data.length) {
            throw new Error('Member not found.');
        }

        var idNumber = normalizeIdNumber_(memberResult.data[0].id_number);

        var result = await supabaseRequest(
            'GET',
            'loans?select=*&or=(' +
                'guarantor1_id.eq.' + encodeURIComponent(idNumber) +
                ',guarantor2_id.eq.' + encodeURIComponent(idNumber) +
            ')&order=created_at.desc&limit=200'
        );

        if (result.statusCode !== 200) {
            throw new Error('Unable to load guarantor requests.');
        }

        var requests = result.data || [];
        if (!requests.length) return { success: true, requests: [] };

        var ids = {};
        requests.forEach(function(x) {
            if (x.member_id) ids[String(x.member_id)] = true;
        });

        var applicantMap = {};
        var endpoints = Object.keys(ids).map(function(id) {
            return 'members?select=id,id_number,unique_member_id,full_name,phone_number&id=eq.' +
                encodeURIComponent(id) + '&limit=1';
        });

        if (endpoints.length) {
            await supabaseFetchAll(endpoints).forEach(function(r) {
                if (r.statusCode === 200 && r.data && r.data.length) {
                    applicantMap[String(r.data[0].id)] = r.data[0];
                }
            });
        }

        requests = requests.map(function(x) {
            var applicant = applicantMap[String(x.member_id)] || {};
            var mineIsFirst =
                String(x.guarantor1_id || '').trim().toUpperCase() === idNumber.toUpperCase();

            var myStatus = mineIsFirst ?
                String(x.guarantor1_status || 'pending') :
                String(x.guarantor2_status || 'pending');

            return Object.assign({}, x, {
                applicant: applicant,
                repayment_days: parseInt(String(x.repayment_period || '').replace(/[^0-9]/g, ''), 10) || 0,
                guarantor_status: myStatus,
                guarantor_responded_at: mineIsFirst ?
                    x.guarantor1_responded_at : x.guarantor2_responded_at,
                all_guarantors_accepted:
                    String(x.guarantor1_status || 'pending') === 'accepted' &&
                    String(x.guarantor2_status || 'pending') === 'accepted',
                is_history: String(x.status || 'pending') !== 'pending'
            });
        });

        return { success: true, requests: requests };
    } catch (e) {
        Logger.log('getGuarantorRequests: ' + e.message);
        return { success: false, message: e.message, requests: [] };
    }
}

async function respondToGuarantorRequest(data) {
    try {
        var memberId = await resolveMemberUuidRequired_(data && data.memberId, 'Guarantor');
        var loanId = String(data && data.loanId || '').trim();
        var decision = String(data && data.decision || '').trim().toLowerCase();
        var reason = String(data && data.reason || '').trim();

        if (!loanId || ['accepted', 'rejected'].indexOf(decision) < 0) {
            throw new Error('Invalid guarantor response.');
        }

        var actorResult = await supabaseRequest(
            'GET',
            'members?select=id,id_number,full_name&id=eq.' +
                encodeURIComponent(memberId) + '&limit=1'
        );
        if (actorResult.statusCode !== 200 || !actorResult.data || !actorResult.data.length) {
            throw new Error('Guarantor member not found.');
        }

        var idNumber = normalizeIdNumber_(actorResult.data[0].id_number);

        var loanResult = await supabaseRequest(
            'GET',
            'loans?select=*&id=eq.' + encodeURIComponent(loanId) + '&limit=1'
        );
        if (loanResult.statusCode !== 200 || !loanResult.data || !loanResult.data.length) {
            throw new Error('Loan application not found.');
        }

        var loan = loanResult.data[0];
        if (String(loan.status) !== 'pending') {
            throw new Error('This loan application is no longer pending.');
        }

        var field, timeField;
        if (String(loan.guarantor1_id || '').trim().toUpperCase() === idNumber.toUpperCase()) {
            field = 'guarantor1_status';
            timeField = 'guarantor1_responded_at';
        } else if (String(loan.guarantor2_id || '').trim().toUpperCase() === idNumber.toUpperCase()) {
            field = 'guarantor2_status';
            timeField = 'guarantor2_responded_at';
        } else {
            throw new Error('You are not a guarantor for this loan.');
        }

        var currentStatus = String(loan[field] || 'pending').toLowerCase();
        if (currentStatus !== 'pending') {
            throw new Error('This guarantor request has already been answered.');
        }

        var patch = {};
        patch[field] = decision;
        patch[timeField] = new Date().toISOString();
        if (decision === 'rejected') {
            patch.guarantor_rejection_reason = reason || 'Guarantor declined the guarantee.';
        }

        var update = await supabaseRequest(
            'PATCH',
            'loans?id=eq.' + encodeURIComponent(loanId) + '&status=eq.pending',
            patch
        );

        if (update.statusCode !== 200 || !update.data || update.data.length !== 1) {
            throw new Error('The guarantor response could not be recorded.');
        }

        await writeAuditLog(
            'GUARANTOR_' + decision.toUpperCase(),
            memberId,
            'loan',
            loanId,
            { [field]: loan[field] || 'pending' },
            { [field]: decision },
            { reason: reason }
        );

        return {
            success: true,
            message: decision === 'accepted' ?
                'Guarantee accepted successfully.' :
                'Guarantee declined successfully.'
        };
    } catch (e) {
        Logger.log('respondToGuarantorRequest: ' + e.message);
        return { success: false, message: e.message };
    }
}

async function requestPasswordReset(data) {
    try {
        var idNumber = normalizeIdNumber_(data && data.idNumber);
        var email = String(data && data.email || '').trim().toLowerCase();

        if (!idNumber || !email) {
            return { success: false, message: 'Enter your ID number and registered email.' };
        }
        await rateLimit_('reset', idNumber + '|' + email, RESET_RATE_LIMIT, RESET_RATE_WINDOW_SECONDS, 'Too many password reset requests. Please try again later.');

        var result = await supabaseRequest(
            'GET',
            'members?select=id,full_name,email,id_number&' +
            'id_number=eq.' + encodeURIComponent(idNumber) +
            '&limit=1'
        );

        // Deliberately do not disclose whether an account exists.
        if (result.statusCode !== 200 || !result.data || !result.data.length) {
            return {
                success: false,
                message: 'We could not verify those account details.'
            };
        }

        var member = result.data[0];
        var registeredEmail = String(member.email || '').trim().toLowerCase();

        if (!registeredEmail || registeredEmail !== email) {
            return {
                success: false,
                message: 'We could not verify those account details.'
            };
        }

        var otp = String(Math.floor(100000 + Math.random() * 900000));
        var otpHash = hashPassword(otp);
        var now = new Date();
        var expires = new Date(now.getTime() + 10 * 60 * 1000).toISOString();

        // Invalidate previous active OTPs for this member.
        await supabaseRequest(
            'PATCH',
            'password_reset_requests?member_id=eq.' +
                encodeURIComponent(member.id) +
                '&used_at=is.null',
            { used_at: now.toISOString() }
        );

        var insert = await supabaseRequest(
            'POST',
            'password_reset_requests',
            {
                member_id: member.id,
                otp_hash: otpHash,
                attempts: 0,
                expires_at: expires,
                created_at: now.toISOString()
            },
            { prefer: 'return=representation' }
        );

        if (insert.statusCode < 200 || insert.statusCode >= 300) {
            throw new Error('Unable to create the password reset request.');
        }

        await sendEmailNotification(
            registeredEmail,
            'Brightlife CBO Password Reset OTP',
            '<p>Dear ' + htmlEscape_(member.full_name || 'Member') + ',</p>' +
            '<p>Your Brightlife CBO password reset OTP is:</p>' +
            '<p style="font-size:28px;font-weight:700;letter-spacing:6px;">' + otp + '</p>' +
            '<p>This code expires in 10 minutes. If you did not request a password reset, you can ignore this email.</p>'
        );

        return {
            success: true,
            message: 'A 6-digit OTP has been sent to your registered email address.'
        };
    } catch (e) {
        Logger.log('requestPasswordReset: ' + e.message);
        return { success: false, message: 'Unable to send the password reset OTP.' };
    }
}

async function resetPasswordWithOtp(data) {
    try {
        var idNumber = normalizeIdNumber_(data && data.idNumber);
        var otp = String(data && data.otp || '').trim();
        var newPassword = String(data && data.newPassword || '');

        if (!idNumber || !/^\d{6}$/.test(otp)) {
            throw new Error('Enter the valid 6-digit OTP.');
        }
        if (newPassword.length < 8) {
            throw new Error('Password must be at least 8 characters.');
        }

        var memberResult = await supabaseRequest(
            'GET',
            'members?select=id&id_number=eq.' +
                encodeURIComponent(idNumber) + '&limit=1'
        );
        if (memberResult.statusCode !== 200 || !memberResult.data || !memberResult.data.length) {
            throw new Error('Invalid reset request.');
        }

        var memberId = memberResult.data[0].id;

        var requestResult = await supabaseRequest(
            'GET',
            'password_reset_requests?select=*&member_id=eq.' +
                encodeURIComponent(memberId) +
                '&used_at=is.null&order=created_at.desc&limit=1'
        );
        if (requestResult.statusCode !== 200 || !requestResult.data || !requestResult.data.length) {
            throw new Error('No active OTP request was found.');
        }

        var request = requestResult.data[0];
        if (new Date(request.expires_at).getTime() < Date.now()) {
            throw new Error('This OTP has expired. Request a new OTP.');
        }
        if (Number(request.attempts || 0) >= 10) {
            throw new Error('Too many incorrect attempts. Request a new OTP.');
        }

        if (hashPassword(otp) !== String(request.otp_hash || '')) {
            await supabaseRequest(
                'PATCH',
                'password_reset_requests?id=eq.' + encodeURIComponent(request.id),
                { attempts: Number(request.attempts || 0) + 1 }
            );
            throw new Error('Incorrect OTP.');
        }

        var update = await supabaseRequest(
            'PATCH',
            'members?id=eq.' + encodeURIComponent(memberId),
            { password: hashPassword(newPassword) }
        );

        if (update.statusCode !== 200 || !update.data || update.data.length !== 1) {
            throw new Error('Password could not be updated.');
        }

        await supabaseRequest(
            'PATCH',
            'password_reset_requests?id=eq.' + encodeURIComponent(request.id),
            { used_at: new Date().toISOString() }
        );

        return { success: true, message: 'Password reset successfully. You can now sign in.' };
    } catch (e) {
        Logger.log('resetPasswordWithOtp: ' + e.message);
        return { success: false, message: e.message };
    }
}

async function getManagementReportData(data) {
    try {
        var requesterId = data && (data.memberId || data.actorId);
        var requester = await getActor(requesterId, data && data.sessionToken);
        var permissions = requester.permissions || {};
        var allowed = ['super_admin', 'admin', 'treasurer'].indexOf(String(requester.role)) >= 0 || permissions.view_reports === true;
        if (!allowed) throw new Error('You do not have permission to view management reports.');

        var fromDate = String(data && data.fromDate || '').trim();
        var toDate = String(data && data.toDate || '').trim();
        var fromTs = fromDate ? new Date(fromDate + 'T00:00:00').getTime() : null;
        var toTs = toDate ? new Date(toDate + 'T23:59:59.999').getTime() : null;
        function inRange(value) {
            if (!fromTs && !toTs) return true;
            var ts = new Date(value || '').getTime();
            if (isNaN(ts)) return false;
            return (!fromTs || ts >= fromTs) && (!toTs || ts <= toTs);
        }

        var endpoints = [
            'members?select=id,unique_member_id,full_name,id_number,phone_number,email,is_active,savings_balance,total_savings_contributed,account_age_months,loan_limit,loan_growth_tier,total_loans_taken,total_loans_completed,total_loans_defaulted,on_time_repayments,late_repayments,registration_fee_paid,registration_fee_status,registration_fee_amount,registration_date,created_at,updated_at&order=unique_member_id.asc&limit=5000',
            'transactions?select=id,member_id,type,amount,status,payment_method,mpesa_code,description,created_by,created_at,updated_at&order=created_at.desc&limit=10000',
            'loans?select=id,member_id,amount,repayment_period,interest_rate,total_repayment,status,application_date,approved_date,repayment_due_date,amount_paid,is_fully_paid,guarantor1_id,guarantor2_id,guarantor1_status,guarantor2_status,created_at,updated_at&order=application_date.desc&limit=5000',
            'loan_repayments?select=id,loan_id,member_id,amount,payment_method,mpesa_code,payment_date,created_at&order=payment_date.desc&limit=10000',
            'withdrawal_requests?select=id,member_id,amount,status,notes,request_date,approved_date,created_at,updated_at&order=created_at.desc&limit=5000',
            'activity_logs?select=id,action,actor_id,entity_type,entity_id,old_values,new_values,metadata,created_at&order=created_at.desc&limit=10000'
        ];
        var results = await supabaseFetchAll(endpoints);
        function arr(i) { return results[i] && results[i].statusCode === 200 && Array.isArray(results[i].data) ? results[i].data : []; }

        var members = arr(0);
        var transactions = arr(1).filter(function(t) { return inRange(t.created_at); });
        var loans = arr(2).filter(function(l) { return inRange(l.application_date || l.created_at); });
        var repayments = arr(3).filter(function(r) { return inRange(r.payment_date || r.created_at); });
        var withdrawals = arr(4).filter(function(w) { return inRange(w.request_date || w.created_at); });
        var auditRaw = arr(5).filter(function(a) { return inRange(a.created_at); });

        var memberById = {};
        members.forEach(function(m) {
            m.report_ref = m.unique_member_id || '';
            m.member_id_display = m.unique_member_id || '';
            m.member_name = m.full_name || '';
            m.status = m.is_active ? 'Active' : 'Pending';
            m.savings = numberValue(m.savings_balance);
            m.totalSavingsContributed = numberValue(m.total_savings_contributed);
            m.accountAgeMonths = numberValue(m.account_age_months);
            m.loanLimit = numberValue(m.loan_limit);
            m.tier = m.loan_growth_tier || 'basic';
            m.loans = numberValue(m.total_loans_taken);
            m.completed = numberValue(m.total_loans_completed);
            m.defaulted = numberValue(m.total_loans_defaulted);
            m.onTime = numberValue(m.on_time_repayments);
            m.late = numberValue(m.late_repayments);
            memberById[String(m.id)] = m;
        });

        transactions.forEach(function(t) {
            var m = memberById[String(t.member_id)] || {};
            t.member_id_display = m.unique_member_id || '';
            t.member_name = m.full_name || 'Unknown Member';
            t.member_national_id = m.id_number || '';
        });
        loans.forEach(function(l) {
            var m = memberById[String(l.member_id)] || {};
            l.member_id_display = m.unique_member_id || '';
            l.member_name = m.full_name || 'Unknown Member';
            l.member_national_id = m.id_number || '';
        });
        repayments.forEach(function(r) {
            var m = memberById[String(r.member_id)] || {};
            r.member_id_display = m.unique_member_id || '';
            r.member_name = m.full_name || 'Unknown Member';
            r.member_national_id = m.id_number || '';
        });
        withdrawals.forEach(function(w) {
            var m = memberById[String(w.member_id)] || {};
            w.member_id_display = m.unique_member_id || '';
            w.member_name = m.full_name || 'Unknown Member';
            w.member_national_id = m.id_number || '';
        });

        var completedTx = transactions.filter(function(t) { return String(t.status || '').toLowerCase() === 'completed'; });
        function sum(list) { return list.reduce(function(total, row) { return total + numberValue(row.amount); }, 0); }
        var activeLoans = loans.filter(function(l) { return String(l.status || '').toLowerCase() === 'active'; });
        var completedLoans = loans.filter(function(l) { return String(l.status || '').toLowerCase() === 'completed' || l.is_fully_paid === true; });
        var defaultedLoans = loans.filter(function(l) { return String(l.status || '').toLowerCase() === 'defaulted'; });
        var pendingLoans = loans.filter(function(l) { return String(l.status || '').toLowerCase() === 'pending'; });
        var pendingTransactions = transactions.filter(function(t) { return String(t.status || '').toLowerCase() === 'pending'; });
        var pendingWithdrawals = withdrawals.filter(function(w) { return String(w.status || '').toLowerCase() === 'pending'; });

        var savings = sum(completedTx.filter(function(t) { return String(t.type || '').toLowerCase() === 'savings'; }));
        var registrationFees = sum(completedTx.filter(function(t) { return String(t.type || '').toLowerCase() === 'registration'; }));
        var disbursements = sum(completedTx.filter(function(t) { return String(t.type || '').toLowerCase() === 'loan_disbursement'; }));
        var repaymentsTotal = sum(completedTx.filter(function(t) { return String(t.type || '').toLowerCase() === 'loan_repayment'; }));
        if (repaymentsTotal === 0 && repayments.length) repaymentsTotal = sum(repayments);
        var withdrawalTotal = sum(completedTx.filter(function(t) { return String(t.type || '').toLowerCase() === 'withdrawal'; }));
        if (withdrawalTotal === 0) withdrawalTotal = sum(withdrawals.filter(function(w) { return String(w.status || '').toLowerCase() === 'completed'; }));
        var activeLoanBalance = sum(activeLoans.map(function(l) { return {amount: Math.max(0, numberValue(l.total_repayment) - numberValue(l.amount_paid))}; }));
        var expectedRepayment = sum(loans.filter(function(l) { return ['active','completed','defaulted'].indexOf(String(l.status || '').toLowerCase()) >= 0; }).map(function(l) { return {amount:numberValue(l.total_repayment)}; }));
        var paidAgainstLoans = sum(repayments);
        if (paidAgainstLoans === 0) paidAgainstLoans = repaymentsTotal;
        var collectionRate = expectedRepayment > 0 ? Math.min(100, paidAgainstLoans / expectedRepayment * 100) : 0;
        var now = new Date();
        var overdueLoans = activeLoans.filter(function(l) { return l.repayment_due_date && new Date(l.repayment_due_date).getTime() < now.getTime() && numberValue(l.amount_paid) < numberValue(l.total_repayment); });

        var months = [];
        for (var mi = 11; mi >= 0; mi--) {
            var md = new Date(now.getFullYear(), now.getMonth() - mi, 1);
            months.push({key:md.getFullYear() + '-' + String(md.getMonth()+1).padStart(2,'0'), label:md.toLocaleString('en',{month:'short'}) + ' ' + String(md.getFullYear()).slice(-2), savings:0, repayments:0, disbursements:0, withdrawals:0, registrations:0});
        }
        var monthMap = {}; months.forEach(function(m) { monthMap[m.key] = m; });
        completedTx.forEach(function(t) {
            var d = new Date(t.created_at); if (isNaN(d.getTime())) return;
            var key = d.getFullYear() + '-' + String(d.getMonth()+1).padStart(2,'0');
            var m = monthMap[key]; if (!m) return;
            var a = numberValue(t.amount), type = String(t.type || '').toLowerCase();
            if (type === 'savings') m.savings += a;
            else if (type === 'registration') m.registrations += a;
            else if (type === 'loan_repayment') m.repayments += a;
            else if (type === 'loan_disbursement') m.disbursements += a;
            else if (type === 'withdrawal') m.withdrawals += a;
        });
        repayments.forEach(function(r) { var d=new Date(r.payment_date||r.created_at); if(isNaN(d.getTime()))return; var key=d.getFullYear()+'-'+String(d.getMonth()+1).padStart(2,'0'); if(monthMap[key]) monthMap[key].repayments += numberValue(r.amount); });
        withdrawals.filter(function(w){return String(w.status||'').toLowerCase()==='completed';}).forEach(function(w){var d=new Date(w.request_date||w.created_at);if(isNaN(d.getTime()))return;var key=d.getFullYear()+'-'+String(d.getMonth()+1).padStart(2,'0');if(monthMap[key])monthMap[key].withdrawals+=numberValue(w.amount);});

        var aging = {due7:0,due30:0,due60:0,due90:0,over90:0};
        activeLoans.forEach(function(l) {
            var due = new Date(l.repayment_due_date || ''); if (isNaN(due.getTime())) return;
            var balance = Math.max(0, numberValue(l.total_repayment) - numberValue(l.amount_paid)); if (balance <= 0 || due >= now) return;
            var days = Math.floor((now.getTime() - due.getTime()) / 86400000);
            if(days <= 7) aging.due7 += balance; else if(days <= 30) aging.due30 += balance; else if(days <= 60) aging.due60 += balance; else if(days <= 90) aging.due90 += balance; else aging.over90 += balance;
        });

        var guarantors = loans.filter(function(l){return l.guarantor1_id || l.guarantor2_id;}).map(function(l){
            var borrower=memberById[String(l.member_id)]||{};
            var g1=memberById[String(l.guarantor1_id)]||{}, g2=memberById[String(l.guarantor2_id)]||{};
            return {borrower:borrower,amount:numberValue(l.amount),interestRate:numberValue(l.interest_rate),totalRepayment:numberValue(l.total_repayment),amountPaid:numberValue(l.amount_paid),balance:Math.max(0,numberValue(l.total_repayment)-numberValue(l.amount_paid)),g1:g1.report_ref||l.guarantor1_id||'',g1Status:l.guarantor1_status||'pending',g2:g2.report_ref||l.guarantor2_id||'',g2Status:l.guarantor2_status||'pending',status:l.status||''};
        });
        var guaranteePending=guarantors.filter(function(x){return x.g1Status==='pending'||x.g2Status==='pending';}).length;
        var guaranteeAccepted=guarantors.filter(function(x){return x.g1Status==='accepted'&&x.g2Status==='accepted';}).length;
        var guaranteeDeclined=guarantors.filter(function(x){return x.g1Status==='declined'||x.g2Status==='declined';}).length;

        var auditActors = {};
        auditRaw.forEach(function(a){ if(a.actor_id) auditActors[String(a.actor_id)] = true; });
        var actorIds=Object.keys(auditActors);
        if(actorIds.length){
            for(var ai=0;ai<actorIds.length;ai+=100){
                var aid=actorIds.slice(ai,ai+100);
                var ar=await supabaseRequest('GET','members?select=id,unique_member_id,full_name&id=in.('+aid.map(encodeURIComponent).join(',')+')&limit=100');
                if(ar.statusCode===200&&Array.isArray(ar.data)) ar.data.forEach(function(m){memberById[String(m.id)]=memberById[String(m.id)]||m;});
            }
        }
        var audit = auditRaw.map(function(a){
            var m=memberById[String(a.entity_id)]||memberById[String((a.new_values||{}).member_id)]||{};
            var actor=memberById[String(a.actor_id)]||{};
            return {date:a.created_at,action:a.action,member:{report_ref:m.unique_member_id||'',full_name:m.full_name||''},actor:{report_ref:actor.unique_member_id||'',full_name:actor.full_name||''},amount:numberValue((a.new_values||{}).amount||((a.metadata||{}).amount)),mpesa:(a.new_values||{}).mpesa_code||((a.metadata||{}).mpesa_code)||'',status:(a.new_values||{}).status||((a.metadata||{}).status)||'',description:(a.metadata||{}).description||a.entity_type||''};
        });

        return {
            success:true,
            generatedAt:new Date().toISOString(),
            members:members,
            transactions:transactions,
            loans:loans,
            repayments:repayments,
            withdrawals:withdrawals,
            guarantors:guarantors,
            audit:audit,
            months:months,
            aging:aging,
            summary:{
                totalMembers:members.length,
                activeMembers:members.filter(function(m){return m.is_active===true;}).length,
                savings:savings,
                totalSavings:savings,
                registrationFees:registrationFees,
                disbursements:disbursements,
                loanDisbursements:disbursements,
                repayments:repaymentsTotal,
                loanRepayments:repaymentsTotal,
                withdrawals:withdrawalTotal,
                activeLoans:activeLoans.length,
                completedLoans:completedLoans.length,
                defaultedLoans:defaultedLoans.length,
                pendingLoans:pendingLoans.length,
                pendingTransactions:pendingTransactions.length,
                pendingWithdrawals:pendingWithdrawals.length,
                overdueLoans:overdueLoans.length,
                activeLoanBalance:activeLoanBalance,
                expectedRepayment:expectedRepayment,
                paidAgainstLoans:paidAgainstLoans,
                collectionRate:collectionRate,
                netFundMovement:savings+registrationFees+repaymentsTotal-disbursements-withdrawalTotal,
                guaranteePending:guaranteePending,
                guaranteeAccepted:guaranteeAccepted,
                guaranteeDeclined:guaranteeDeclined
            }
        };
    } catch (e) {
        Logger.log('getManagementReportData: ' + e.message);
        return {success:false,message:e.message};
    }
}

async function synchronizeMemberAccountAge(data) {
    try {
        var actorId = await resolveMemberUuidRequired_(data && data.memberId, 'Member');
        var actor = await getActor(actorId, data && data.sessionToken);
        var role = String(actor.role || '').toLowerCase();

        // Allow the member to synchronize only their own account.
        var targetId = await resolveMemberUuidRequired_(data && (data.targetMemberId || data.memberId), 'Member');
        if (String(targetId) !== String(actorId) &&
            ['admin', 'super_admin'].indexOf(role) < 0) {
            throw new Error('You cannot update another member account.');
        }

        var result = await supabaseRequest(
            'GET',
            'members?select=id,registration_date,created_at,account_age_months&id=eq.' +
            encodeURIComponent(targetId) + '&limit=1'
        );
        if (result.statusCode !== 200 || !result.data || !result.data.length) {
            throw new Error('Member not found.');
        }

        var member = result.data[0];
        var start = member.registration_date || member.created_at;
        var startDate = start ? new Date(start) : new Date();
        var now = new Date();

        var months =
            (now.getFullYear() - startDate.getFullYear()) * 12 +
            (now.getMonth() - startDate.getMonth());

        if (now.getDate() < startDate.getDate()) months--;
        months = Math.max(0, months);

        var update = await supabaseRequest(
            'PATCH',
            'members?id=eq.' + encodeURIComponent(targetId),
            { account_age_months: months }
        );

        if (update.statusCode !== 200) {
            throw new Error('Could not synchronize account age.');
        }

        return { success: true, accountAgeMonths: months };
    } catch (e) {
        Logger.log('synchronizeMemberAccountAge: ' + e.message);
        return { success: false, message: e.message };
    }
}

function initiateKcbMpesaPayment(data) {
    return {
        success: false,
        message: 'KCB M-Pesa integration is not enabled in this database build. Please use the manual M-Pesa payment option.'
    };
}

function getKcbPaymentStatus(data) {
    return {
        success: false,
        payment: {
            status: 'failed',
            message: 'KCB M-Pesa integration is not enabled in this database build.'
        }
    };
}

async function checkMpesaCode(data) {
    try {
        const endpoint = 'transactions?select=mpesa_code&mpesa_code=eq.' + encodeURIComponent(data.mpesaCode);
        const result = await supabaseRequest('GET', endpoint);
        
        if (result.statusCode === 200 && result.data && result.data.length > 0) {
            return { exists: true };
        }
        return { exists: false };
    } catch (error) {
        return { exists: false, error: error.message };
    }
}

async function processSavings(data) {
    try {
        var memberId = data && data.memberId;
        var actorId = data && data.actorId;
        if (String(actorId) !== String(memberId)) throw new Error('You can only post payments for your own member account.');
        var amount = numberValue(data && data.amount);
        var mpesaCode = String((data && data.mpesaCode) || '').trim().toUpperCase();
        if (!memberId) throw new Error('Member ID is required');
        if (amount <= 0) throw new Error('Enter a valid amount');
        if (!mpesaCode) throw new Error('M-Pesa confirmation code is required');

        var memberResult = await supabaseRequest('GET', 'members?select=id,full_name,unique_member_id,phone_number,is_active,registration_fee_paid,registration_fee_status,registration_fee_amount,savings_balance&id=eq.' + encodeURIComponent(memberId));
        if (memberResult.statusCode !== 200 || !memberResult.data || !memberResult.data.length) throw new Error('Member not found');
        var member = memberResult.data[0];

        // One M-Pesa confirmation code may only be used once across the whole ledger.
        var duplicateEndpoints = [
            'transactions?select=id&mpesa_code=eq.' + encodeURIComponent(mpesaCode) + '&limit=1',
            'loan_repayments?select=id&mpesa_code=eq.' + encodeURIComponent(mpesaCode) + '&limit=1'
        ];
        var dup = await supabaseFetchAll(duplicateEndpoints);
        if ((dup[0].statusCode === 200 && dup[0].data && dup[0].data.length) ||
            (dup[1].statusCode === 200 && dup[1].data && dup[1].data.length)) {
            throw new Error('This M-Pesa confirmation code has already been used.');
        }

        var isRegistrationPayment = !member.is_active && !member.registration_fee_paid && member.registration_fee_status !== 'approved';
        if (isRegistrationPayment && Math.abs(amount - CONFIG.REGISTRATION_FEE) > 0.001) {
            throw new Error('Registration fee must be exactly KES ' + CONFIG.REGISTRATION_FEE + '.');
        }
        if (!isRegistrationPayment && !member.is_active) {
            throw new Error('Activate your account first by completing the registration fee payment.');
        }

        var transactionData = {
            member_id: memberId,
            type: isRegistrationPayment ? 'registration' : 'savings',
            amount: amount,
            payment_method: 'mpesa',
            mpesa_code: mpesaCode,
            description: isRegistrationPayment ? 'Registration fee - Pending Admin Approval' : 'Savings deposit - Pending Admin Approval',
            status: 'pending',
            created_by: memberId,
            created_at: new Date().toISOString()
        };
        var transResult = await supabaseRequest('POST', 'transactions', transactionData);
        if (transResult.statusCode !== 201) throw new Error('Failed to create transaction');

        if (isRegistrationPayment) {
            await supabaseRequest('PATCH', 'members?id=eq.' + encodeURIComponent(memberId), {
                registration_fee_status: 'pending',
                registration_fee_amount: amount
            });
        }

        // Notification is intentionally after the ledger write; a WhatsApp failure must not fail the payment.
        await notifyAdmins('💰 ' + (isRegistrationPayment ? 'REGISTRATION FEE PAYMENT' : 'SAVINGS DEPOSIT REQUEST') + '\n' +
            'Member: ' + member.full_name + '\n' +
            'ID: ' + member.unique_member_id + '\n' +
            'Amount: KES ' + amount.toFixed(2) + '\n' +
            'M-Pesa Code: ' + mpesaCode + '\n\nAwaiting admin approval');

        return {
            success: true,
            message: isRegistrationPayment ?
                'Registration fee submitted! Awaiting admin approval.' :
                'Savings deposit submitted! Awaiting admin approval.',
            transactionId: transResult.data && transResult.data[0] ? transResult.data[0].id : null
        };
    } catch (error) {
        return { success: false, message: error.message };
    }
}

async function notifyAdmins(message) {
    try {
        var result = await supabaseRequest('GET', 'members?select=phone_number&role=in.(admin,super_admin)&is_active=eq.true&limit=50');
        if (result.statusCode === 200 && Array.isArray(result.data)) {
            result.data.forEach(function(admin) {
                if (admin.phone_number) sendWhatsAppAlert(admin.phone_number, message);
            });
        }
    } catch (e) {
        Logger.log('Admin notification failed: ' + e.message);
    }
}

async function approveRegistrationFee(data) {
    try {
        var memberId = typeof data === 'object' ? data.memberId : data;
        var actorId = typeof data === 'object' ? data.actorId : null;
        await requirePermission(actorId, 'registration_approval', undefined, data && data.sessionToken);
        Logger.log('=== APPROVING REGISTRATION FEE ===');
        Logger.log('Member ID: ' + memberId);
        
        const memberResult = await supabaseRequest('GET', 'members?select=*&id=eq.' + encodeURIComponent(memberId));
        
        if (memberResult.statusCode !== 200 || !memberResult.data || memberResult.data.length === 0) {
            throw new Error('Member not found');
        }
        
        const member = memberResult.data[0];
        Logger.log('Member found: ' + member.full_name);
        
        if (member.is_active) {
            return { success: false, message: 'Member is already active' };
        }
        
        const transResult = await supabaseRequest('GET', 
            'transactions?select=*&member_id=eq.' + encodeURIComponent(memberId) + 
            '&type=eq.registration&status=eq.pending&order=created_at.desc&limit=1');
        
        let amount = CONFIG.REGISTRATION_FEE || 500;
        let mpesaCode = 'N/A';
        let transactionId = null;
        
        if (transResult.statusCode === 200 && transResult.data && transResult.data.length > 0) {
            amount = transResult.data[0].amount || 500;
            mpesaCode = transResult.data[0].mpesa_code || 'N/A';
            transactionId = transResult.data[0].id;
        }
        
        const updateEndpoint = 'members?id=eq.' + encodeURIComponent(memberId);
        const updateData = {
            registration_fee_paid: true,
            registration_fee_status: 'approved',
            is_active: true,
            // Registration fee is an account-opening fee, not savings.
            savings_balance: numberValue(member.savings_balance),
            updated_at: new Date().toISOString()
        };
        
        const result = await supabaseRequest('PATCH', updateEndpoint, updateData);
        
        if (result.statusCode !== 200) {
            throw new Error('Failed to approve registration fee: ' + JSON.stringify(result.data));
        }
        
        if (transactionId) {
            const transUpdateEndpoint = 'transactions?id=eq.' + transactionId;
            await supabaseRequest('PATCH', transUpdateEndpoint, {
                status: 'completed',
                description: 'Registration fee approved - Account Activated'
            });
        }
        
        sendWhatsAppAlert(
            member.phone_number,
            '✅ ACCOUNT ACTIVATED\n' +
            'Dear ' + member.full_name + ',\n' +
            'Your registration fee of KES ' + amount + ' has been approved!\n' +
            'Your savings balance remains KES ' + numberValue(member.savings_balance).toFixed(2) + '\n' +
            'You can now access all features.\n\n' +
            'Welcome to Brightlife CBO! 🎉'
        );
        
        sendWhatsAppAlert(
            CONFIG.ADMIN_WHATSAPP,
            '✅ REGISTRATION FEE APPROVED\n' +
            'Member: ' + member.full_name + '\n' +
            'ID: ' + member.unique_member_id + '\n' +
            'Amount: KES ' + amount + '\n' +
            'Account activated successfully!'
        );
        
        return { 
            success: true, 
            message: 'Registration fee approved. Member activated successfully.'
        };
    } catch (error) {
        Logger.log('Error in approveRegistrationFee: ' + error.message);
        return { success: false, message: error.message };
    }
}

async function rejectRegistrationFee(data) {
    try {
        var memberId = typeof data === 'object' ? data.memberId : data;
        var actorId = typeof data === 'object' ? data.actorId : null;
        await requirePermission(actorId, 'registration_approval', undefined, data && data.sessionToken);
        const memberResult = await supabaseRequest('GET', 'members?select=*&id=eq.' + encodeURIComponent(memberId));
        
        if (memberResult.statusCode !== 200 || !memberResult.data || memberResult.data.length === 0) {
            throw new Error('Member not found');
        }
        
        const member = memberResult.data[0];
        
        const transResult = await supabaseRequest('GET', 
            'transactions?select=*&member_id=eq.' + encodeURIComponent(memberId) + 
            '&type=eq.registration&status=eq.pending&order=created_at.desc&limit=1');
        
        let transactionId = null;
        let amount = CONFIG.REGISTRATION_FEE;
        
        if (transResult.statusCode === 200 && transResult.data && transResult.data.length > 0) {
            transactionId = transResult.data[0].id;
            amount = transResult.data[0].amount || CONFIG.REGISTRATION_FEE;
        }
        
        const updateEndpoint = 'members?id=eq.' + encodeURIComponent(memberId);
        const result = await supabaseRequest('PATCH', updateEndpoint, {
            registration_fee_paid: false,
            registration_fee_status: 'rejected',
            is_active: false
        });
        
        if (result.statusCode !== 200) {
            throw new Error('Failed to reject registration fee');
        }
        
        if (transactionId) {
            const transUpdateEndpoint = 'transactions?id=eq.' + transactionId;
            await supabaseRequest('PATCH', transUpdateEndpoint, {
                status: 'rejected',
                description: 'Registration fee - Rejected by Admin'
            });
        }
        
        sendWhatsAppAlert(
            member.phone_number,
            '❌ REGISTRATION FEE REJECTED\n' +
            'Dear ' + member.full_name + ',\n' +
            'Your registration fee of KES ' + amount + ' has been rejected.\n' +
            'Please contact admin for assistance or resubmit.\n\n' +
            'Contact: ' + CONFIG.ADMIN_WHATSAPP
        );
        
        return { success: true, message: 'Registration fee rejected. Member informed.' };
    } catch (error) {
        return { success: false, message: error.message };
    }
}

async function approveSavings(data) {
    try {
        var transactionId = typeof data === 'object' ? data.transactionId : data;
        var actorId = typeof data === 'object' ? data.actorId : null;
        await requirePermission(actorId, 'savings_approval', ['super_admin','admin','treasurer'], data && data.sessionToken);
        const transResult = await supabaseRequest('GET', 'transactions?select=*&id=eq.' + encodeURIComponent(transactionId));
        
        if (transResult.statusCode !== 200 || !transResult.data || transResult.data.length === 0) {
            throw new Error('Transaction not found');
        }
        
        const transaction = transResult.data[0];
        if (transaction.status !== 'pending' || transaction.type !== 'savings') {
            throw new Error('This savings transaction is no longer pending.');
        }
        
        const memberResult = await supabaseRequest('GET', 'members?select=*&id=eq.' + encodeURIComponent(transaction.member_id));
        
        if (memberResult.statusCode !== 200 || !memberResult.data || memberResult.data.length === 0) {
            throw new Error('Member not found');
        }
        
        const member = memberResult.data[0];
        const currentBalance = numberValue(member.savings_balance);
        const depositAmount = numberValue(transaction.amount);
        if (depositAmount <= 0) throw new Error('Invalid savings amount.');
        const newBalance = currentBalance + depositAmount;
        const updateEndpoint = 'members?id=eq.' + encodeURIComponent(transaction.member_id) + '&savings_balance=eq.' + encodeURIComponent(String(currentBalance));
        const balanceUpdate = await supabaseRequest('PATCH', updateEndpoint, { savings_balance: newBalance });
        if (balanceUpdate.statusCode !== 200 || !Array.isArray(balanceUpdate.data) || balanceUpdate.data.length !== 1) throw new Error('Savings balance changed while approving this deposit. Please refresh and retry.');
        
        const transUpdateEndpoint = 'transactions?id=eq.' + encodeURIComponent(transactionId) + '&status=eq.pending';
        const transUpdate = await supabaseRequest('PATCH', transUpdateEndpoint, {
            status: 'completed',
            description: 'Savings deposit - Approved'
        });
        if (transUpdate.statusCode !== 200 || !Array.isArray(transUpdate.data) || transUpdate.data.length !== 1) {
            await supabaseRequest('PATCH', 'members?id=eq.' + encodeURIComponent(transaction.member_id) + '&savings_balance=eq.' + encodeURIComponent(String(newBalance)), {savings_balance:currentBalance});
            throw new Error('Savings approval could not be finalized. The balance was restored.');
        }
        
        sendWhatsAppAlert(
            member.phone_number,
            '✅ SAVINGS APPROVED\n' +
            'Dear ' + member.full_name + ',\n' +
            'Your savings deposit of KES ' + transaction.amount + ' has been approved!\n' +
            'New balance: KES ' + newBalance
        );
        
        return { success: true, message: 'Savings approved successfully' };
    } catch (error) {
        return { success: false, message: error.message };
    }
}

async function rejectSavings(data) {
    try {
        var transactionId = typeof data === 'object' ? data.transactionId : data;
        var actorId = typeof data === 'object' ? data.actorId : null;
        await requirePermission(actorId, 'savings_approval', ['super_admin','admin','treasurer'], data && data.sessionToken);
        const transResult = await supabaseRequest('GET', 'transactions?select=*&id=eq.' + encodeURIComponent(transactionId));
        
        if (transResult.statusCode !== 200 || !transResult.data || transResult.data.length === 0) {
            throw new Error('Transaction not found');
        }
        
        const transaction = transResult.data[0];
        
        const transUpdateEndpoint = 'transactions?id=eq.' + encodeURIComponent(transactionId);
        await supabaseRequest('PATCH', transUpdateEndpoint, {
            status: 'rejected',
            description: 'Savings deposit - Rejected by Admin'
        });
        
        const memberResult = await supabaseRequest('GET', 'members?select=full_name,phone_number&id=eq.' + encodeURIComponent(transaction.member_id));
        if (memberResult.statusCode === 200 && memberResult.data && memberResult.data.length > 0) {
            const member = memberResult.data[0];
            sendWhatsAppAlert(
                member.phone_number,
                '❌ SAVINGS REJECTED\n' +
                'Dear ' + member.full_name + ',\n' +
                'Your savings deposit of KES ' + transaction.amount + ' has been rejected.\n' +
                'Please contact admin for more information.'
            );
        }
        
        return { success: true, message: 'Savings rejected successfully' };
    } catch (error) {
        return { success: false, message: error.message };
    }
}

async function approveWithdrawal(data) {
    try {
        var withdrawalId = typeof data === 'object' ? data.withdrawalId : data;
        var actorId = typeof data === 'object' ? data.actorId : null;
        await requirePermission(actorId, 'withdrawal_approval', undefined, data && data.sessionToken);
        const endpoint = 'withdrawal_requests?select=*&id=eq.' + 
                        encodeURIComponent(withdrawalId);
        const result = await supabaseRequest('GET', endpoint);
        
        if (result.statusCode !== 200 || !result.data || result.data.length === 0) {
            throw new Error('Withdrawal not found');
        }
        
        const withdrawal = result.data[0];
        if (withdrawal.status !== 'pending') throw new Error('This withdrawal is no longer pending.');
        
        const memberResult = await supabaseRequest('GET', 'members?select=id,savings_balance,full_name,phone_number&id=eq.' + encodeURIComponent(withdrawal.member_id));
        const member = memberResult.statusCode === 200 && memberResult.data && memberResult.data.length > 0 ? memberResult.data[0] : {};
        
        const currentBalance = numberValue(member.savings_balance);
        const withdrawalAmount = numberValue(withdrawal.amount);
        if (withdrawalAmount <= 0 || withdrawalAmount > currentBalance) throw new Error('Withdrawal exceeds the member savings balance.');
        const newBalance = Math.max(0, currentBalance - withdrawalAmount);
        const updateEndpoint = 'members?id=eq.' + encodeURIComponent(withdrawal.member_id) + '&savings_balance=eq.' + encodeURIComponent(String(currentBalance));
        const balanceUpdate = await supabaseRequest('PATCH', updateEndpoint, { savings_balance: newBalance });
        if (balanceUpdate.statusCode !== 200 || !Array.isArray(balanceUpdate.data) || balanceUpdate.data.length !== 1) throw new Error('Savings balance changed while approving this withdrawal. Please refresh and retry.');
        
        const wEndpoint = 'withdrawal_requests?id=eq.' + encodeURIComponent(withdrawalId) + '&status=eq.pending';
        const withdrawalUpdate = await supabaseRequest('PATCH', wEndpoint, {
            status: 'approved',
            approved_date: new Date().toISOString()
        });
        if (withdrawalUpdate.statusCode !== 200 || !Array.isArray(withdrawalUpdate.data) || withdrawalUpdate.data.length !== 1) {
            await supabaseRequest('PATCH', 'members?id=eq.' + encodeURIComponent(withdrawal.member_id) + '&savings_balance=eq.' + encodeURIComponent(String(newBalance)), {savings_balance:currentBalance});
            throw new Error('Withdrawal could not be finalized. The savings balance was restored.');
        }
        
        const transEndpoint = 'transactions';
        await supabaseRequest('POST', transEndpoint, {
            member_id: withdrawal.member_id,
            type: 'withdrawal',
            amount: withdrawal.amount,
            description: 'Withdrawal approved - KES ' + withdrawal.amount,
            status: 'completed',
            created_by: null,
            created_at: new Date().toISOString()
        });
        
        if (member.phone_number) {
            sendWhatsAppAlert(
                member.phone_number,
                '✅ WITHDRAWAL APPROVED\n' +
                'Dear ' + member.full_name + ',\n' +
                'Your withdrawal of KES ' + withdrawal.amount + ' has been approved!\n' +
                'New balance: KES ' + newBalance
            );
        }
        
        return { success: true, message: 'Withdrawal approved' };
    } catch (error) {
        return { success: false, message: error.message };
    }
}

async function rejectWithdrawal(data) {
    try {
        var withdrawalId = typeof data === 'object' ? data.withdrawalId : data;
        var actorId = typeof data === 'object' ? data.actorId : null;
        await requirePermission(actorId, 'withdrawal_approval', undefined, data && data.sessionToken);
        const endpoint = 'withdrawal_requests?select=*&id=eq.' + 
                        encodeURIComponent(withdrawalId);
        const result = await supabaseRequest('GET', endpoint);
        
        if (result.statusCode !== 200 || !result.data || result.data.length === 0) {
            throw new Error('Withdrawal not found');
        }
        
        const withdrawal = result.data[0];
        
        const memberResult = await supabaseRequest('GET', 'members?select=full_name,phone_number&id=eq.' + encodeURIComponent(withdrawal.member_id));
        const member = memberResult.statusCode === 200 && memberResult.data && memberResult.data.length > 0 ? memberResult.data[0] : {};
        
        const wEndpoint = 'withdrawal_requests?id=eq.' + encodeURIComponent(withdrawalId);
        await supabaseRequest('PATCH', wEndpoint, {
            status: 'rejected',
            notes: 'Rejected by Admin'
        });
        
        if (member.phone_number) {
            sendWhatsAppAlert(
                member.phone_number,
                '❌ WITHDRAWAL REJECTED\n' +
                'Dear ' + (member.full_name || 'Member') + ',\n' +
                'Your withdrawal request of KES ' + withdrawal.amount + ' has been rejected.\n' +
                'Please contact admin for more information.'
            );
        }
        
        return { success: true, message: 'Withdrawal rejected' };
    } catch (error) {
        return { success: false, message: error.message };
    }
}

async function applyForLoan(data) {
    try {
        var memberId = data && data.memberId;
        var actorId = data && data.actorId;
        if (String(actorId) !== String(memberId)) throw new Error('You can only apply for a loan for your own member account.');
        var loanData = data && data.loanData ? data.loanData : {};
        var amount = numberValue(loanData.amount);
        var days = parseInt(loanData.repaymentDays, 10);
        if (!memberId) throw new Error('Member ID is required');
        if (amount <= 0) throw new Error('Enter a valid loan amount');
        if (!isFinite(days) || days < 1) throw new Error('Invalid repayment period');

        var memberResult = await supabaseRequest('GET', 'members?select=id,full_name,unique_member_id,phone_number,is_active,biodata_completed,savings_balance,loan_limit,registration_date&id=eq.' + encodeURIComponent(memberId));
        if (memberResult.statusCode !== 200 || !memberResult.data || !memberResult.data.length) throw new Error('Member not found');
        var member = memberResult.data[0];
        if (!member.is_active) throw new Error('Account is inactive. Complete registration first.');
        if (!member.biodata_completed) throw new Error('Complete your profile before applying for a loan.');

        var existingLoanResult = await supabaseRequest('GET', 'loans?select=id,status&member_id=eq.' + encodeURIComponent(memberId) + '&status=in.(pending,active)&limit=1');
        if (existingLoanResult.statusCode === 200 && Array.isArray(existingLoanResult.data) && existingLoanResult.data.length) {
            throw new Error('You already have a pending or active loan. Complete it before applying for another loan.');
        }

        var savingsMonths = await getCompletedSavingsMonths(memberId);
        if (savingsMonths.length < CONFIG.MIN_SAVINGS_MONTHS) {
            throw new Error('You must have consistent savings in at least ' + CONFIG.MIN_SAVINGS_MONTHS + ' different months before applying for a loan. Current: ' + savingsMonths.length + '.');
        }

        var savingsBalance = numberValue(member.savings_balance);
        var hardCap = savingsBalance * CONFIG.MAX_LOAN_MULTIPLIER;
        if (hardCap <= 0) throw new Error('You do not have eligible savings for a loan yet.');

        var loanCalculation = await getActiveLoanCalculation(memberId, savingsBalance);
        var effectiveLimit = Math.min(hardCap, numberValue(loanCalculation.limit));
        if (effectiveLimit <= 0) throw new Error('Your current loan eligibility limit is KES 0. Increase eligible savings before applying.');
        if (amount > effectiveLimit) {
            throw new Error('Maximum loan is KES ' + effectiveLimit.toFixed(2) + '. Active method: ' + loanCalculation.activeMethod.toUpperCase() + '.');
        }

        var guarantor1 = String(loanData.guarantor1Id || '').trim();
        var guarantor2 = String(loanData.guarantor2Id || '').trim();
        if (!guarantor1 || !guarantor2) throw new Error('At least 2 active member guarantors are required.');
        if (guarantor1 === guarantor2) throw new Error('Choose two different guarantors.');

        // Confirm both guarantors are active members. The current SQL schema does not contain
        // guarantor acceptance fields, so selection is stored for admin verification.
        var gResults = await supabaseFetchAll([
            'members?select=id,unique_member_id,full_name,is_active&id=eq.' + encodeURIComponent(guarantor1),
            'members?select=id,unique_member_id,full_name,is_active&id=eq.' + encodeURIComponent(guarantor2)
        ]);
        if (gResults[0].statusCode !== 200 || !gResults[0].data || !gResults[0].data.length || !gResults[0].data[0].is_active) throw new Error('Guarantor 1 must be an active member.');
        if (gResults[1].statusCode !== 200 || !gResults[1].data || !gResults[1].data.length || !gResults[1].data[0].is_active) throw new Error('Guarantor 2 must be an active member.');

        var interestRate = getLoanInterestRate(days, loanCalculation.organizationSettings);
        var totalRepayment = amount * (1 + interestRate);
        var dueDate = new Date();
        dueDate.setDate(dueDate.getDate() + days);
        var nowIso = new Date().toISOString();

        var loanResult = await supabaseRequest('POST', 'loans', {
            member_id: memberId,
            amount: amount,
            repayment_period: days + ' days',
            interest_rate: interestRate,
            total_repayment: totalRepayment,
            guarantor1_id: guarantor1,
            guarantor2_id: guarantor2,
            status: 'pending',
            repayment_due_date: dueDate.toISOString(),
            amount_paid: 0,
            is_fully_paid: false,
            application_date: nowIso,
            created_at: nowIso
        });
        if (loanResult.statusCode !== 201) throw new Error('Failed to submit loan application');

        await notifyAdmins('💳 LOAN APPLICATION\n' +
            'Member: ' + member.full_name + '\n' +
            'ID: ' + member.unique_member_id + '\n' +
            'Amount: KES ' + amount.toFixed(2) + '\n' +
            'Period: ' + days + ' days\n' +
            'Interest: ' + (interestRate * 100) + '%\n' +
            'Total Repayment: KES ' + totalRepayment.toFixed(2) + '\n' +
            'Maximum by savings: KES ' + hardCap.toFixed(2));

        var createdLoan = loanResult.data && loanResult.data[0] ? loanResult.data[0] : {};
        return {
            success: true,
            message: 'Loan application submitted successfully! Awaiting admin approval.',
            loanId: createdLoan.id || null,
            loanLimit: effectiveLimit,
            qualifyingSavingsMonths: savingsMonths.length
        };
    } catch (error) {
        return { success: false, message: error.message };
    }
}

async function approveLoan(data) {
    try {
        var loanId = typeof data === 'object' ? data.loanId : data;
        var actorId = typeof data === 'object' ? data.actorId : null;
        await requirePermission(actorId, 'loan_approval', undefined, data && data.sessionToken);
        const endpoint = 'loans?select=*&id=eq.' + encodeURIComponent(loanId);
        const result = await supabaseRequest('GET', endpoint);
        
        if (result.statusCode !== 200 || !result.data || result.data.length === 0) {
            throw new Error('Loan not found');
        }
        
        const loan = result.data[0];
        if (loan.status !== 'pending') throw new Error('This loan is no longer pending.');
        
        const memberResult = await supabaseRequest('GET', 'members?select=id,full_name,unique_member_id,phone_number&id=eq.' + encodeURIComponent(loan.member_id));
        const member = memberResult.statusCode === 200 && memberResult.data && memberResult.data.length > 0 ? memberResult.data[0] : {};
        
        const approvalTime = new Date().toISOString();
        const updateEndpoint = 'loans?id=eq.' + encodeURIComponent(loanId) + '&status=eq.pending';
        const loanUpdate = await supabaseRequest('PATCH', updateEndpoint, {
            status: 'active',
            approved_date: approvalTime,
            approved_by: actorId
        });
        if (loanUpdate.statusCode !== 200) throw new Error('Failed to approve loan. It may already have been processed.');
        
        const transEndpoint = 'transactions';
        await supabaseRequest('POST', transEndpoint, {
            member_id: loan.member_id,
            type: 'loan_disbursement',
            amount: loan.amount,
            description: 'Loan approved - KES ' + loan.amount,
            status: 'completed',
            created_by: null,
            created_at: new Date().toISOString()
        });
        
        if (member.phone_number) {
            sendWhatsAppAlert(
                member.phone_number,
                '✅ LOAN APPROVED\n' +
                'Amount: KES ' + loan.amount + '\n' +
                'Repayment Period: ' + loan.repayment_period + '\n' +
                'Interest: ' + (loan.interest_rate * 100) + '%\n' +
                'Total Repayment: KES ' + (loan.total_repayment || loan.amount * (1 + loan.interest_rate)).toFixed(2) + '\n' +
                'Due Date: ' + new Date(loan.repayment_due_date).toLocaleDateString()
            );
        }
        
        return { success: true, message: 'Loan approved and disbursed' };
    } catch (error) {
        return { success: false, message: error.message };
    }
}

async function rejectLoan(data) {
    try {
        var loanId = typeof data === 'object' ? data.loanId : data;
        var actorId = typeof data === 'object' ? data.actorId : null;
        await requirePermission(actorId, 'loan_approval', undefined, data && data.sessionToken);
        const endpoint = 'loans?id=eq.' + encodeURIComponent(loanId);
        await supabaseRequest('PATCH', endpoint, { status: 'rejected' });
        return { success: true, message: 'Loan rejected' };
    } catch (error) {
        return { success: false, message: error.message };
    }
}

async function repayLoan(data) {
    try {
        var loanId = data && data.loanId;
        var memberId = data && data.memberId;
        var actorId = data && data.actorId;
        if (String(actorId) !== String(memberId)) throw new Error('You can only repay your own loan.');
        var amount = numberValue(data && data.amount);
        var mpesaCode = String((data && data.mpesaCode) || '').trim().toUpperCase();
        if (!loanId || !memberId) throw new Error('Loan and member are required');
        if (amount <= 0) throw new Error('Enter a valid repayment amount');
        if (!mpesaCode) throw new Error('M-Pesa confirmation code is required');

        var endpoints = [
            'loans?select=*&id=eq.' + encodeURIComponent(loanId) + '&limit=1',
            'transactions?select=id&mpesa_code=eq.' + encodeURIComponent(mpesaCode) + '&limit=1',
            'loan_repayments?select=id&mpesa_code=eq.' + encodeURIComponent(mpesaCode) + '&limit=1'
        ];
        var r = await supabaseFetchAll(endpoints);
        if (r[0].statusCode !== 200 || !r[0].data || !r[0].data.length) throw new Error('Loan not found');
        if ((r[1].statusCode === 200 && r[1].data && r[1].data.length) || (r[2].statusCode === 200 && r[2].data && r[2].data.length)) {
            throw new Error('This M-Pesa confirmation code has already been used.');
        }
        var loan = r[0].data[0];
        if (String(loan.member_id) !== String(memberId)) throw new Error('This loan does not belong to the logged-in member.');
        if (loan.status !== 'active') throw new Error('Loan is not active or already completed');

        var totalRepayment = numberValue(loan.total_repayment || numberValue(loan.amount) * (1 + numberValue(loan.interest_rate)));
        var currentPaid = numberValue(loan.amount_paid);
        var remaining = Math.max(0, totalRepayment - currentPaid);
        if (amount > remaining) throw new Error('Payment exceeds remaining balance of KES ' + remaining.toFixed(2) + '.');
        var newAmountPaid = currentPaid + amount;
        var isFullyPaid = newAmountPaid >= totalRepayment - 0.001;
        var nowIso = new Date().toISOString();

        var update = await supabaseRequest('PATCH', 'loans?id=eq.' + encodeURIComponent(loanId) + '&status=eq.active&amount_paid=eq.' + encodeURIComponent(String(currentPaid)), {
            amount_paid: newAmountPaid,
            is_fully_paid: isFullyPaid,
            status: isFullyPaid ? 'completed' : 'active',
            updated_at: nowIso
        });
        if (update.statusCode !== 200 || !Array.isArray(update.data) || update.data.length !== 1) throw new Error('Loan balance changed while this payment was being processed. Please refresh and try again.');

        var repayment = await supabaseRequest('POST', 'loan_repayments', {
            loan_id: loanId,
            member_id: memberId,
            amount: amount,
            payment_method: 'mpesa',
            mpesa_code: mpesaCode,
            payment_date: nowIso,
            created_at: nowIso
        });
        if (repayment.statusCode !== 201) {
            await supabaseRequest('PATCH', 'loans?id=eq.' + encodeURIComponent(loanId) + '&amount_paid=eq.' + encodeURIComponent(String(newAmountPaid)), {amount_paid:currentPaid,is_fully_paid:false,status:'active',updated_at:new Date().toISOString()});
            throw new Error('Repayment could not be recorded. No balance was retained for this payment. Please retry.');
        }

        var trans = await supabaseRequest('POST', 'transactions', {
            member_id: memberId,
            type: 'loan_repayment',
            amount: amount,
            payment_method: 'mpesa',
            mpesa_code: mpesaCode,
            description: 'Loan repayment',
            status: 'completed',
            created_by: memberId,
            created_at: nowIso
        });
        if (trans.statusCode !== 201) Logger.log('Warning: repayment transaction ledger insert failed: ' + JSON.stringify(trans));

        return {
            success: true,
            message: 'Repayment of KES ' + amount.toFixed(2) + ' recorded. ' +
                (isFullyPaid ? 'Loan fully paid!' : 'Remaining: KES ' + (totalRepayment - newAmountPaid).toFixed(2))
        };
    } catch (error) {
        return { success: false, message: error.message };
    }
}

async function requestWithdrawal(data) {
    try {
        const memberId = data && data.memberId;
        const actorId = data && data.actorId;
        if (String(actorId) !== String(memberId)) throw new Error('You can only request a withdrawal for your own member account.');
        const endpoint = 'members?select=savings_balance,full_name,is_active,registration_fee_amount,registration_fee_paid&id=eq.' + 
                        encodeURIComponent(data.memberId);
        const result = await supabaseRequest('GET', endpoint);
        
        if (result.statusCode !== 200 || !result.data || result.data.length === 0) {
            throw new Error('Member not found');
        }
        
        const member = result.data[0];
        
        if (!member.is_active) {
            throw new Error('Account is inactive. Pay registration fee to activate.');
        }
        
        const pendingWithdrawalsResult = await supabaseRequest('GET', 'withdrawal_requests?select=amount&member_id=eq.' + encodeURIComponent(data.memberId) + '&status=eq.pending&limit=500');
        const pendingReserved = pendingWithdrawalsResult.statusCode === 200 && Array.isArray(pendingWithdrawalsResult.data) ? pendingWithdrawalsResult.data.reduce(function(sum,w){return sum+numberValue(w.amount);},0) : 0;
        const withdrawableBalance = Math.max(0, numberValue(member.savings_balance) - pendingReserved);
        
        if (numberValue(data.amount) > withdrawableBalance) {
            throw new Error('Insufficient available savings. KES ' + pendingReserved.toFixed(2) + ' is already reserved in pending withdrawals.');
        }
        
        if (member.savings_balance < data.amount) {
            throw new Error('Insufficient savings. Available: KES ' + member.savings_balance);
        }
        
        const wEndpoint = 'withdrawal_requests';
        await supabaseRequest('POST', wEndpoint, {
            member_id: data.memberId,
            amount: data.amount,
            phone: data.phone || '',
            status: 'pending',
            request_date: new Date().toISOString(),
            created_at: new Date().toISOString()
        });
        
        const adminsResult = await supabaseRequest('GET', 'members?select=phone_number&role=in.(admin,super_admin)&is_active=eq.true');
        if (adminsResult.statusCode === 200 && adminsResult.data) {
            adminsResult.data.forEach(admin => {
                sendWhatsAppAlert(
                    admin.phone_number,
                    '🏦 WITHDRAWAL REQUEST\n' +
                    'Member: ' + member.full_name + '\n' +
                    'Amount: KES ' + data.amount + '\n' +
                    'Phone: ' + (data.phone || 'N/A') + '\n' +
                    'Withdrawable Balance: KES ' + withdrawableBalance
                );
            });
        }
        
        return { 
            success: true, 
            message: 'Withdrawal request submitted. Admin will process within 24 hours.' 
        };
    } catch (error) {
        return { success: false, message: error.message };
    }
}

async function getAdminDashboard(data) {
    try {
        var requesterId = data && (data.memberId || data.actorId);
        var actor = await getActor(requesterId, data && data.sessionToken);
        var canManage = actorCan(actor, 'view_reports') || actorCan(actor, 'view_members') || actorCan(actor, 'view_transactions') || actorCan(actor, 'view_savings') || actorCan(actor, 'view_repayments') || actorCan(actor, 'registration_approval') || actorCan(actor, 'savings_approval') || actorCan(actor, 'loan_approval') || actorCan(actor, 'withdrawal_approval') || actorCan(actor, 'profile_approval');
        if (!canManage) throw new Error('You do not have permission to access the organization dashboard');

        // Do not depend on Supabase embedded relations here. If a foreign-key
        // relationship is missing or changed, an embedded select can fail the
        // entire approval queue and make the dashboard display zero items.
        // Fetch the operational tables independently and enrich the rows below.
        var endpoints = [
            'transactions?select=*&order=created_at.desc&limit=5000',
            'members?select=id,full_name,unique_member_id,phone_number,email,registration_fee_paid,registration_fee_status,registration_fee_amount,is_active,biodata_completed,created_at&order=created_at.desc&limit=5000',
            'loans?select=*&order=application_date.desc&limit=5000',
            'withdrawal_requests?select=*&order=request_date.desc&limit=5000',
            'biodata_approvals?select=*&order=created_at.desc&limit=5000',
            'loans?select=*&status=eq.active&order=repayment_due_date.asc&limit=5000',
            'loan_repayments?select=*&order=payment_date.desc&limit=100',
            'members?select=id,unique_member_id,full_name,id_number,phone_number,email,role,registration_fee_paid,registration_fee_status,registration_fee_amount,is_active,biodata_completed,biodata_locked,savings_balance,withdrawal_fee,profile_edit_status,occupation,address,next_of_kin,next_of_kin_phone,next_of_kin_relation,account_age_months,loan_limit,loan_growth_score,loan_growth_tier,loan_growth_evaluation,loan_growth_last_evaluated,total_loans_taken,total_loans_completed,total_loans_defaulted,on_time_repayments,late_repayments,total_savings_contributed,savings_consistency_score,permissions,registration_date,created_at,updated_at&order=created_at.desc&limit=5000'
        ];
        var r = await supabaseFetchAll(endpoints);
        function arr(i) { return r[i] && r[i].statusCode === 200 && Array.isArray(r[i].data) ? r[i].data : []; }
        var allTransactions = arr(0);
        var allMembers = arr(1);
        var allLoans = arr(2);
        var allWithdrawals = arr(3);
        var allProfileEdits = arr(4);
        var activeLoans = arr(5);
        var recentRepayments = arr(6);

        // Build a reliable member lookup and attach member summaries locally.
        // This keeps approval queues working even when Supabase relationship
        // metadata is unavailable for embedded selects.
        var memberById = {};
        allMembers.forEach(function(m) { memberById[String(m.id)] = m; });
        function memberSummary(memberId) {
            var m = memberById[String(memberId)] || {};
            return {
                id: m.id || memberId,
                full_name: m.full_name || 'Unknown Member',
                unique_member_id: m.unique_member_id || '',
                phone_number: m.phone_number || '',
                email: m.email || ''
            };
        }
        allTransactions.forEach(function(t) { if (!t.members) t.members = memberSummary(t.member_id); });
        allLoans.forEach(function(l) { if (!l.members) l.members = memberSummary(l.member_id); });
        allWithdrawals.forEach(function(w) { if (!w.members) w.members = memberSummary(w.member_id); });
        allProfileEdits.forEach(function(e) { if (!e.members) e.members = memberSummary(e.member_id); });
        activeLoans.forEach(function(l) { if (!l.members) l.members = memberSummary(l.member_id); });
        recentRepayments.forEach(function(r) { if (!r.members) r.members = memberSummary(r.member_id); });

        function pending(v) { return String(v || '').trim().toLowerCase() === 'pending'; }
        var pendingTransactions = allTransactions.filter(function(t) { return pending(t.status); });
        var pendingRegistrations = allMembers.filter(function(m) {
            return !m.is_active && (pending(m.registration_fee_status) || !m.registration_fee_paid) &&
                allTransactions.some(function(t) { return String(t.member_id) === String(m.id) && pending(t.status) && String(t.type || '').toLowerCase() === 'registration'; });
        });
        if (!pendingRegistrations.length) {
            pendingRegistrations = allMembers.filter(function(m) { return !m.is_active && pending(m.registration_fee_status); });
        }
        var pendingLoans = allLoans.filter(function(l) { return pending(l.status); });
        var pendingWithdrawals = allWithdrawals.filter(function(w) { return pending(w.status); });
        var pendingProfileEdits = allProfileEdits.filter(function(e) { return pending(e.status) && String(e.request_type || '').toLowerCase() === 'profile_edit'; });

        var statsResult = await getDashboardStats({memberId: actor.id, sessionToken: data && data.sessionToken});
        if (!statsResult.success) throw new Error(statsResult.message || 'Unable to load dashboard statistics.');
        var stats = {
            totalMembers: statsResult.totalMembers, activeMembers: statsResult.activeMembers,
            pendingMembers: statsResult.pendingMembers, pendingRegistrations: statsResult.pendingRegistrations,
            pendingTransactions: statsResult.pendingTransactions, pendingWithdrawals: statsResult.pendingWithdrawals,
            pendingLoans: statsResult.pendingLoans, activeLoans: statsResult.totalActiveLoans,
            totalLoans: statsResult.totalLoans, defaultedLoans: statsResult.defaultedLoans,
            totalSavings: statsResult.totalSavings, pendingProfileEdits: statsResult.pendingProfileEdits,
            overdueLoans: statsResult.overdueLoans, activeLoanBalance: statsResult.activeLoanBalance,
            loanDisbursements: statsResult.loanDisbursements, loanRepayments: statsResult.loanRepayments,
            todaySavingsDeposits: statsResult.todaySavingsDeposits, todayLoanRepaymentsAmount: statsResult.todayLoanRepaymentsAmount
        };
        stats.pendingRegistrations = pendingRegistrations.length;
        stats.pendingTransactions = pendingTransactions.length;
        stats.pendingLoans = pendingLoans.length;
        stats.pendingWithdrawals = pendingWithdrawals.length;
        stats.pendingProfileEdits = pendingProfileEdits.length;

        return {success:true,pendingRegistrations:pendingRegistrations,pendingTransactions:pendingTransactions,pendingLoans:pendingLoans,pendingWithdrawals:pendingWithdrawals,pendingProfileEdits:pendingProfileEdits,activeLoans:activeLoans,recentRepayments:recentRepayments,allMembers:allMembers,stats:stats};
    } catch (error) {
        Logger.log('Error in getAdminDashboard: ' + error.message);
        return {success:false,message:error.message};
    }
}

async function getDashboardStats(data) {
    try {
        var actor = await getActor(data && (data.actorId || data.memberId), data && data.sessionToken);
        if (!actorCan(actor, 'view_reports') && !actorCan(actor, 'view_members') && !actorCan(actor, 'view_transactions') && !actorCan(actor, 'view_savings') && !actorCan(actor, 'view_repayments')) throw new Error('You do not have permission to view dashboard statistics.');
        var endpoints = [
            'members?select=id,is_active,registration_fee_paid,registration_fee_status&limit=5000',
            'transactions?select=id,member_id,amount,type,status,created_at&limit=20000',
            'withdrawal_requests?select=id,status,amount&limit=10000',
            'loans?select=id,amount,total_repayment,amount_paid,status,repayment_due_date,created_at&limit=10000',
            'biodata_approvals?select=id,status,request_type&limit=10000'
        ];
        var r = await supabaseFetchAll(endpoints);
        function arr(i){ return r[i] && r[i].statusCode === 200 && Array.isArray(r[i].data) ? r[i].data : []; }
        var members=arr(0), tx=arr(1), withdrawals=arr(2), loans=arr(3), profileEdits=arr(4);
        function isPending(v){return String(v||'').toLowerCase()==='pending';}
        var completed=tx.filter(function(t){return String(t.status||'').toLowerCase()==='completed';});
        var pendingTx=tx.filter(function(t){return isPending(t.status);});
        var pendingWithdrawals=withdrawals.filter(function(w){return isPending(w.status);});
        var pendingLoans=loans.filter(function(l){return isPending(l.status);});
        var pendingProfile=profileEdits.filter(function(e){return isPending(e.status)&&String(e.request_type||'').toLowerCase()==='profile_edit';});
        var pendingRegistrations=members.filter(function(m){return !m.is_active && (isPending(m.registration_fee_status) || !m.registration_fee_paid) && tx.some(function(t){return String(t.member_id)===String(m.id)&&isPending(t.status)&&String(t.type||'').toLowerCase()==='registration';});});
        if(!pendingRegistrations.length) pendingRegistrations=members.filter(function(m){return !m.is_active&&isPending(m.registration_fee_status);});
        function sum(list){return list.reduce(function(a,t){return a+numberValue(t.amount);},0);}
        var savings=sum(completed.filter(function(t){return String(t.type||'').toLowerCase()==='savings';}));
        var repayments=sum(completed.filter(function(t){return String(t.type||'').toLowerCase()==='loan_repayment';}));
        var disbursements=sum(completed.filter(function(t){return String(t.type||'').toLowerCase()==='loan_disbursement';}));
        var activeLoans=loans.filter(function(l){return String(l.status||'').toLowerCase()==='active';});
        var defaultedLoans=loans.filter(function(l){return String(l.status||'').toLowerCase()==='defaulted';});
        var now=new Date();
        var overdueLoans=activeLoans.filter(function(l){return l.repayment_due_date&&new Date(l.repayment_due_date)<now&&numberValue(l.amount_paid)<numberValue(l.total_repayment);});
        var activeBalance=sum(activeLoans.map(function(l){return {amount:Math.max(0,numberValue(l.total_repayment)-numberValue(l.amount_paid))};}));
        var todayKey=Utilities.formatDate(now, Session.getScriptTimeZone() || 'Africa/Nairobi', 'yyyy-MM-dd');
        var todaySavings=sum(completed.filter(function(t){var d=new Date(t.created_at);return String(t.type||'').toLowerCase()==='savings'&&!isNaN(d.getTime())&&Utilities.formatDate(d,Session.getScriptTimeZone()||'Africa/Nairobi','yyyy-MM-dd')===todayKey;}));
        var todayRepayments=sum(completed.filter(function(t){var d=new Date(t.created_at);return String(t.type||'').toLowerCase()==='loan_repayment'&&!isNaN(d.getTime())&&Utilities.formatDate(d,Session.getScriptTimeZone()||'Africa/Nairobi','yyyy-MM-dd')===todayKey;}));
        return {success:true,totalMembers:members.length,activeMembers:members.filter(function(m){return m.is_active===true;}).length,pendingMembers:pendingRegistrations.length,pendingRegistrations:pendingRegistrations.length,pendingTransactions:pendingTx.length,pendingWithdrawals:pendingWithdrawals.length,pendingLoans:pendingLoans.length,pendingProfileEdits:pendingProfile.length,totalSavings:savings,totalActiveLoans:activeLoans.length,totalLoans:loans.length,defaultedLoans:defaultedLoans.length,overdueLoans:overdueLoans.length,activeLoanBalance:activeBalance,loanDisbursements:disbursements,loanRepayments:repayments,todaySavingsDeposits:todaySavings,todayLoanRepaymentsAmount:todayRepayments};
    } catch (error) { return {success:false,message:error.message}; }
}

async function getLoanGrowthSettings() {
    try {
        const result = await supabaseRequest('GET', 'loan_growth_settings?limit=1');
        
        if (result.statusCode !== 200 || !result.data || result.data.length === 0) {
            var defaultSettings = getDefaultLoanGrowthSettings();
            defaultSettings.active_method = 'default';
            return {
                success: true,
                settings: defaultSettings
            };
        }
        
        var settings = result.data[0];
        if (!settings.active_method) {
            settings.active_method = 'default';
        }
        
        return {
            success: true,
            settings: settings
        };
    } catch (error) {
        Logger.log('Error in getLoanGrowthSettings: ' + error.message);
        return { success: false, message: error.message };
    }
}

function getDefaultLoanGrowthSettings() {
    return {
        platinum_threshold: 90,
        gold_threshold: 75,
        silver_threshold: 60,
        bronze_threshold: 45,
        platinum_multiplier: 3.0,
        gold_multiplier: 2.5,
        silver_multiplier: 2.0,
        bronze_multiplier: 1.5,
        basic_multiplier: 1.0,
        repayment_weight: 40,
        savings_weight: 30,
        borrowing_weight: 20,
        reliability_weight: 10,
        on_time_bonus_threshold: 5,
        on_time_bonus_amount: 10000,
        savings_bonus_threshold: 12,
        savings_bonus_amount: 15000,
        min_loan_limit: 3000,
        max_loan_limit: 500000,
        base_loan_multiplier: 3.0,
        interest_rate_7days: 12.0,
        interest_rate_14days: 16.0,
        interest_rate_20days: 18.0,
        interest_rate_21plus: 20.0,
        registration_fee: 500,
        min_savings_months: 3,
        default_repayment_days: 30,
        late_payment_penalty: 5.0,
        active_method: 'default'
    };
}

async function updateLoanGrowthSettings(data) {
    try {
        const settings = data.settings;
        const adminId = data.adminId;
        await requirePermission(adminId, 'manage_settings', ['super_admin','admin'], data && data.sessionToken);
        
        const checkResult = await supabaseRequest('GET', 'loan_growth_settings?limit=1');
        let result;
        
        if (checkResult.statusCode === 200 && checkResult.data && checkResult.data.length > 0) {
            const id = checkResult.data[0].id;
            result = await supabaseRequest('PATCH', 'loan_growth_settings?id=eq.' + id, {
                platinum_threshold: settings.platinum_threshold,
                gold_threshold: settings.gold_threshold,
                silver_threshold: settings.silver_threshold,
                bronze_threshold: settings.bronze_threshold,
                platinum_multiplier: settings.platinum_multiplier,
                gold_multiplier: settings.gold_multiplier,
                silver_multiplier: settings.silver_multiplier,
                bronze_multiplier: settings.bronze_multiplier,
                basic_multiplier: settings.basic_multiplier,
                repayment_weight: settings.repayment_weight,
                savings_weight: settings.savings_weight,
                borrowing_weight: settings.borrowing_weight,
                reliability_weight: settings.reliability_weight,
                on_time_bonus_threshold: settings.on_time_bonus_threshold,
                on_time_bonus_amount: settings.on_time_bonus_amount,
                savings_bonus_threshold: settings.savings_bonus_threshold,
                savings_bonus_amount: settings.savings_bonus_amount,
                min_loan_limit: settings.min_loan_limit,
                max_loan_limit: settings.max_loan_limit,
                base_loan_multiplier: normalizeLoanMultiplier(settings.base_loan_multiplier, 3),
                active_method: settings.active_method === 'advanced' ? 'advanced' : 'default',
                updated_at: new Date().toISOString()
            });
        } else {
            result = await supabaseRequest('POST', 'loan_growth_settings', {
                platinum_threshold: settings.platinum_threshold || 90,
                gold_threshold: settings.gold_threshold || 75,
                silver_threshold: settings.silver_threshold || 60,
                bronze_threshold: settings.bronze_threshold || 45,
                platinum_multiplier: settings.platinum_multiplier || 3.0,
                gold_multiplier: settings.gold_multiplier || 2.5,
                silver_multiplier: settings.silver_multiplier || 2.0,
                bronze_multiplier: settings.bronze_multiplier || 1.5,
                basic_multiplier: settings.basic_multiplier || 1.0,
                repayment_weight: settings.repayment_weight || 40,
                savings_weight: settings.savings_weight || 30,
                borrowing_weight: settings.borrowing_weight || 20,
                reliability_weight: settings.reliability_weight || 10,
                on_time_bonus_threshold: settings.on_time_bonus_threshold || 5,
                on_time_bonus_amount: settings.on_time_bonus_amount || 10000,
                savings_bonus_threshold: settings.savings_bonus_threshold || 12,
                savings_bonus_amount: settings.savings_bonus_amount || 15000,
                min_loan_limit: settings.min_loan_limit || 3000,
                max_loan_limit: settings.max_loan_limit || 500000,
                base_loan_multiplier: normalizeLoanMultiplier(settings.base_loan_multiplier, 3),
                active_method: settings.active_method === 'advanced' ? 'advanced' : 'default',
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString()
            });
        }
        
        if (result.statusCode !== 200 && result.statusCode !== 201) {
            throw new Error('Failed to update loan growth settings');
        }

        // Recalculate stored member limits after any policy change so the active method
        // and its multipliers are reflected consistently across the portal.
        var activeMembersResult = await supabaseRequest('GET', 'members?select=id&is_active=eq.true&limit=5000');
        var recalculated = 0;
        if (activeMembersResult.statusCode === 200 && Array.isArray(activeMembersResult.data)) {
            for (const m of activeMembersResult.data) { const evalResult = await evaluateLoanGrowth(m.id); if (evalResult && evalResult.success) recalculated++; }
        }
        return { success: true, message: 'Loan growth settings updated successfully. ' + recalculated + ' active member limit(s) refreshed.' };
    } catch (error) {
        return { success: false, message: error.message };
    }
}

async function activateLoanGrowthMethod(data) {
    try {
        const method = String(data.method || '').trim().toLowerCase();
        const adminId = data.adminId || data.actorId;
        await requirePermission(adminId, 'manage_settings', ['super_admin','admin'], data && data.sessionToken);
        if (method !== 'default' && method !== 'advanced') {
            throw new Error('Invalid loan growth method.');
        }
        
        const checkResult = await supabaseRequest('GET', 'loan_growth_settings?limit=1');
        let result;
        
        if (checkResult.statusCode === 200 && checkResult.data && checkResult.data.length > 0) {
            const id = checkResult.data[0].id;
            result = await supabaseRequest('PATCH', 'loan_growth_settings?id=eq.' + id, {
                active_method: method,
                updated_at: new Date().toISOString()
            });
            Logger.log('Updated existing settings');
        } else {
            result = await supabaseRequest('POST', 'loan_growth_settings', {
                platinum_threshold: 90,
                gold_threshold: 75,
                silver_threshold: 60,
                bronze_threshold: 45,
                platinum_multiplier: 3.0,
                gold_multiplier: 2.5,
                silver_multiplier: 2.0,
                bronze_multiplier: 1.5,
                basic_multiplier: 1.0,
                repayment_weight: 40,
                savings_weight: 30,
                borrowing_weight: 20,
                reliability_weight: 10,
                on_time_bonus_threshold: 5,
                on_time_bonus_amount: 10000,
                savings_bonus_threshold: 12,
                savings_bonus_amount: 15000,
                min_loan_limit: 3000,
                max_loan_limit: 500000,
                base_loan_multiplier: 3.0,
                active_method: method,
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString()
            });
            Logger.log('Created new settings with method: ' + method);
        }
        
        if (result.statusCode !== 200 && result.statusCode !== 201) {
            throw new Error('Failed to activate loan growth method: ' + JSON.stringify(result));
        }
        
        Logger.log('Re-evaluating all members with new method...');
        const membersResult = await supabaseRequest('GET', 'members?select=id,is_active&is_active=eq.true');
        
        var updatedCount = 0;
        
        if (membersResult.statusCode === 200 && membersResult.data) {
            for (var i = 0; i < membersResult.data.length; i++) {
                var member = membersResult.data[i];
                var evalResult = await evaluateLoanGrowth(member.id);
                if (evalResult.success) {
                    updatedCount++;
                }
            }
            Logger.log('Re-evaluated ' + updatedCount + ' members');
        }
        
        return { 
            success: true, 
            message: 'Loan growth method activated: ' + method.toUpperCase() + '. ' + updatedCount + ' members re-evaluated.'
        };
    } catch (error) {
        Logger.log('Error in activateLoanGrowthMethod: ' + error.message);
        return { success: false, message: error.message };
    }
}

async function evaluateLoanGrowth(memberId) {
    try {
        var requestedRef = (memberId && typeof memberId === 'object') ? memberId.memberId : memberId;
        if (!requestedRef) throw new Error('Member reference is required.');
        var resolvedMemberId = await resolveMemberUuidRequired_(requestedRef, 'Member');
        Logger.log('=== EVALUATING LOAN GROWTH FOR MEMBER: ' + requestedRef + ' -> ' + resolvedMemberId);
        
        const settingsResult = await getLoanGrowthSettings();
        if (!settingsResult.success) {
            throw new Error('Could not load loan growth settings');
        }
        const settings = settingsResult.settings;
        
        const activeMethod = settings.active_method || 'default';
        Logger.log('Active Method: ' + activeMethod);
        
        const memberResult = await supabaseRequest('GET', 'members?select=*&id=eq.' + encodeURIComponent(resolvedMemberId));
        if (memberResult.statusCode !== 200 || !memberResult.data || memberResult.data.length === 0) {
            throw new Error('Member not found');
        }
        const member = memberResult.data[0];
        
        const loansResult = await supabaseRequest('GET', 
            'loans?select=*&member_id=eq.' + encodeURIComponent(resolvedMemberId) + '&order=application_date.desc');
        const loans = loansResult.statusCode === 200 ? loansResult.data : [];
        
        const savingsResult = await supabaseRequest('GET', 
            'transactions?select=*&member_id=eq.' + encodeURIComponent(resolvedMemberId) + '&type=eq.savings&status=eq.completed&order=created_at.desc');
        const savingsTransactions = savingsResult.statusCode === 200 ? savingsResult.data : [];
        
        const repaymentsResult = await supabaseRequest('GET', 
            'loan_repayments?select=*&member_id=eq.' + encodeURIComponent(resolvedMemberId) + '&order=payment_date.desc');
        const repayments = repaymentsResult.statusCode === 200 ? repaymentsResult.data : [];
        
        const evaluation = calculateLoanGrowthMetrics(member, loans, savingsTransactions, repayments, settings);
        const tierResult = determineTier(evaluation.overallScore, settings);
        
        let newLimit;
        if (activeMethod === 'advanced') {
            newLimit = calculateAdvancedLoanLimit(evaluation, tierResult, settings);
            Logger.log('Using Advanced method - New Limit: ' + newLimit);
        } else {
            newLimit = calculateDefaultLoanLimit(evaluation, settings);
            Logger.log('Using Default method - New Limit: ' + newLimit);
        }
        
        const updateData = {
            loan_limit: newLimit,
            loan_growth_score: evaluation.overallScore,
            loan_growth_tier: tierResult.tier,
            loan_growth_evaluation: evaluation,
            loan_growth_last_evaluated: new Date().toISOString(),
            total_loans_taken: loans.length,
            total_loans_completed: loans.filter(l => l.status === 'completed').length,
            total_loans_defaulted: loans.filter(l => l.status === 'defaulted').length,
            on_time_repayments: evaluation.breakdown.repayment.onTimeRepayments,
            late_repayments: evaluation.breakdown.repayment.lateRepayments,
            total_savings_contributed: savingsTransactions.reduce((sum, t) => sum + numberValue(t.amount), 0),
            savings_consistency_score: evaluation.breakdown.savings.consistencyScore || 0
        };
        
        const updateResult = await supabaseRequest('PATCH', 'members?id=eq.' + encodeURIComponent(resolvedMemberId), updateData);
        
        if (updateResult.statusCode !== 200) {
            Logger.log('Failed to update member loan growth: ' + JSON.stringify(updateResult));
        }
        
        const message = generateLoanGrowthMessage(evaluation, tierResult, newLimit, member.loan_limit || 0, activeMethod);
        
        return {
            success: true,
            evaluation: evaluation,
            tier: tierResult,
            currentLimit: member.loan_limit || settings.min_loan_limit || 3000,
            newLimit: newLimit,
            increased: newLimit > (member.loan_limit || 0),
            activeMethod: activeMethod,
            message: message
        };
        
    } catch (error) {
        Logger.log('Error in evaluateLoanGrowth: ' + error.message);
        return { success: false, message: error.message };
    }
}

function calculateDefaultLoanLimit(evaluation, settings) {
    const eligibleSavings = Math.max(0, evaluation.breakdown.savings.currentBalance);
    let multiplier = normalizeLoanMultiplier(settings.base_loan_multiplier, CONFIG.MAX_LOAN_MULTIPLIER);
    let limit = eligibleSavings * multiplier;
    limit = Math.min(eligibleSavings * CONFIG.MAX_LOAN_MULTIPLIER, limit);
    limit = Math.min(settings.max_loan_limit || 500000, limit);
    return Math.round(limit);
}

function calculateAdvancedLoanLimit(evaluation, tierResult, settings) {
    const eligibleSavings = Math.max(0, evaluation.breakdown.savings.currentBalance);
    let limit = eligibleSavings * Math.min(Number(tierResult.tierMultiplier) || 1, CONFIG.MAX_LOAN_MULTIPLIER);
    
    let bonus = 0;
    if (evaluation.breakdown.repayment.onTimeRepayments >= (settings.on_time_bonus_threshold || 5) && 
        evaluation.breakdown.repayment.completedLoans >= 3) {
        bonus += settings.on_time_bonus_amount || 10000;
    }
    if (evaluation.breakdown.savings.savingsFrequency >= (settings.savings_bonus_threshold || 12) && 
        evaluation.breakdown.savings.currentBalance >= 50000) {
        bonus += settings.savings_bonus_amount || 15000;
    }
    
    limit = limit + bonus;
    limit = Math.min(eligibleSavings * CONFIG.MAX_LOAN_MULTIPLIER, limit);
    limit = Math.min(settings.max_loan_limit || 500000, limit);
    return Math.round(limit);
}

function calculateLoanGrowthMetrics(member, loans, savingsTransactions, repayments, settings) {
    let repaymentScore = 0;
    const totalLoans = loans.length;
    const completedLoans = loans.filter(l => l.status === 'completed').length;
    const activeLoans = loans.filter(l => l.status === 'active').length;
    const defaultedLoans = loans.filter(l => l.status === 'defaulted').length;
    let onTimeRepayments = 0;
    let lateRepayments = 0;
    
    loans.forEach(loan => {
        if (loan.status === 'completed' || loan.status === 'active') {
            const dueDate = new Date(loan.repayment_due_date);
            const loanRepayments = repayments.filter(r => r.loan_id === loan.id);
            
            if (loanRepayments.length > 0) {
                const lastPayment = new Date(loanRepayments[loanRepayments.length - 1].payment_date);
                if (lastPayment <= dueDate) {
                    onTimeRepayments++;
                } else {
                    lateRepayments++;
                }
            }
        }
    });
    
    if (totalLoans === 0) {
        repaymentScore = 50;
    } else {
        const onTimeRatio = totalLoans > 0 ? onTimeRepayments / totalLoans : 0;
        const completedRatio = totalLoans > 0 ? completedLoans / totalLoans : 0;
        const defaultRatio = totalLoans > 0 ? defaultedLoans / totalLoans : 0;
        
        repaymentScore = (onTimeRatio * 40) + (completedRatio * 30) + (30 - (defaultRatio * 50));
        repaymentScore = Math.max(0, Math.min(100, repaymentScore));
    }
    
    let savingsScore = 0;
    const totalSavings = savingsTransactions.reduce((sum, t) => sum + numberValue(t.amount), 0);
    const averageSavings = savingsTransactions.length > 0 ? totalSavings / savingsTransactions.length : 0;
    const savingsFrequency = savingsTransactions.length;
    const currentSavings = numberValue(member.savings_balance);
    
    const threeMonthsAgo = new Date();
    threeMonthsAgo.setMonth(threeMonthsAgo.getMonth() - 3);
    const recentSavings = savingsTransactions.filter(t => new Date(t.created_at) >= threeMonthsAgo);
    const recentSavingsCount = recentSavings.length;
    const consistencyScore = Math.min(20, recentSavingsCount * 3);
    
    if (savingsFrequency === 0) {
        savingsScore = 30;
    } else {
        const balanceScore = Math.min(30, currentSavings / 1000);
        const frequencyScore = Math.min(30, savingsFrequency * 2);
        const averageScore = Math.min(20, averageSavings / 500);
        
        savingsScore = balanceScore + frequencyScore + consistencyScore + averageScore;
        savingsScore = Math.max(0, Math.min(100, savingsScore));
    }
    
    let borrowingScore = 0;
    const highestLoan = loans.reduce((max, l) => Math.max(max, numberValue(l.amount)), 0);
    const averageLoan = loans.length > 0 ? loans.reduce((sum, l) => sum + numberValue(l.amount), 0) / loans.length : 0;
    
    if (totalLoans === 0) {
        borrowingScore = 40;
    } else {
        const experienceScore = Math.min(30, totalLoans * 5);
        const highestScore = Math.min(30, highestLoan / 1000);
        const averageScore = Math.min(20, averageLoan / 500);
        const completedBonus = Math.min(20, completedLoans * 5);
        
        borrowingScore = experienceScore + highestScore + averageScore + completedBonus;
        borrowingScore = Math.max(0, Math.min(100, borrowingScore));
    }
    
    let reliabilityScore = 0;
    const activeRatio = totalLoans > 0 ? activeLoans / totalLoans : 0;
    const activeRisk = Math.max(0, 30 - (activeRatio * 50));
    const defaultPenalty = Math.min(50, defaultedLoans * 20);
    const accountAge = new Date() - new Date(member.registration_date);
    const accountAgeMonths = accountAge / (1000 * 60 * 60 * 24 * 30);
    const ageScore = Math.min(20, accountAgeMonths * 2);
    const profileScore = member.biodata_completed ? 15 : 0;
    
    reliabilityScore = activeRisk + ageScore + profileScore - defaultPenalty;
    reliabilityScore = Math.max(0, Math.min(100, reliabilityScore));
    
    const overallScore = (repaymentScore * (settings.repayment_weight / 100)) + 
                        (savingsScore * (settings.savings_weight / 100)) + 
                        (borrowingScore * (settings.borrowing_weight / 100)) + 
                        (reliabilityScore * (settings.reliability_weight / 100));
    
    return {
        overallScore: Math.round(overallScore * 100) / 100,
        breakdown: {
            repayment: {
                score: Math.round(repaymentScore),
                totalLoans: totalLoans,
                completedLoans: completedLoans,
                activeLoans: activeLoans,
                defaultedLoans: defaultedLoans,
                onTimeRepayments: onTimeRepayments,
                lateRepayments: lateRepayments,
                weight: settings.repayment_weight + '%'
            },
            savings: {
                score: Math.round(savingsScore),
                totalSavings: totalSavings,
                averageSavings: averageSavings,
                savingsFrequency: savingsFrequency,
                recentSavingsCount: recentSavingsCount,
                currentBalance: currentSavings,
                consistencyScore: consistencyScore,
                weight: settings.savings_weight + '%'
            },
            borrowing: {
                score: Math.round(borrowingScore),
                totalLoans: totalLoans,
                highestLoan: highestLoan,
                averageLoan: averageLoan,
                completedLoans: completedLoans,
                weight: settings.borrowing_weight + '%'
            },
            reliability: {
                score: Math.round(reliabilityScore),
                activeRatio: activeRatio,
                defaultPenalty: defaultPenalty,
                accountAgeMonths: Math.round(accountAgeMonths),
                profileComplete: member.biodata_completed,
                weight: settings.reliability_weight + '%'
            }
        }
    };
}

function determineTier(score, settings) {
    let tier, tierLabel, tierMultiplier;
    
    if (score >= settings.platinum_threshold) {
        tier = 'platinum';
        tierLabel = 'Platinum (Elite)';
        tierMultiplier = settings.platinum_multiplier;
    } else if (score >= settings.gold_threshold) {
        tier = 'gold';
        tierLabel = 'Gold (Premium)';
        tierMultiplier = settings.gold_multiplier;
    } else if (score >= settings.silver_threshold) {
        tier = 'silver';
        tierLabel = 'Silver (Advanced)';
        tierMultiplier = settings.silver_multiplier;
    } else if (score >= settings.bronze_threshold) {
        tier = 'bronze';
        tierLabel = 'Bronze (Standard)';
        tierMultiplier = settings.bronze_multiplier;
    } else {
        tier = 'basic';
        tierLabel = 'Basic (Entry)';
        tierMultiplier = settings.basic_multiplier;
    }
    
    return { tier, tierLabel, tierMultiplier };
}

function generateLoanGrowthMessage(evaluation, tierResult, newLimit, currentLimit, activeMethod) {
    let message = '';
    const increase = newLimit - currentLimit;
    const tierEmojis = {
        'platinum': '💎',
        'gold': '🏆',
        'silver': '🥈',
        'bronze': '🥉',
        'basic': '📘'
    };
    
    const methodDisplay = activeMethod === 'advanced' ? 'Advanced (Multiplier Based)' : 'Default (3x Savings)';
    message = '📊 Calculation Method: ' + methodDisplay + '\n\n';
    
    if (increase > 0) {
        message += '🎉 Congratulations! Your loan limit has increased from KES ' + currentLimit.toFixed(2) + ' to KES ' + newLimit.toFixed(2) + '. ';
        message += 'This is a KES ' + increase.toFixed(2) + ' increase! ';
    } else if (increase === 0 && currentLimit > 0) {
        message += '📊 Your loan limit remains at KES ' + currentLimit.toFixed(2) + '. ';
    } else {
        message += '📊 Your loan limit is KES ' + newLimit.toFixed(2) + '. ';
    }
    
    message += '\n\n📈 Your Tier: ' + (tierEmojis[tierResult.tier] || '') + ' ' + tierResult.tierLabel;
    message += '\n⭐ Overall Score: ' + evaluation.overallScore + '/100';
    
    if (activeMethod === 'advanced') {
        message += '\n🔢 Multiplier: ' + tierResult.tierMultiplier + 'x';
    } else {
        message += '\n🔢 Multiplier: 3.0x (Default)';
    }
    
    const recommendations = generateRecommendations(evaluation, tierResult);
    if (recommendations.length > 0) {
        message += '\n\n💡 Recommendations to improve:';
        recommendations.forEach(rec => {
            message += '\n• ' + rec.area + ': ' + rec.message;
        });
    }
    
    return message;
}

async function checkActiveLoanGrowthMethod() {
    try {
        var result = await supabaseRequest('GET', 'loan_growth_settings?limit=1');
        
        if (result.statusCode !== 200 || !result.data || result.data.length === 0) {
            return {
                success: true,
                activeMethod: 'default',
                message: 'No settings found. Using default method.',
                settings: null
            };
        }
        
        var settings = result.data[0];
        var activeMethod = settings.active_method || 'default';
        
        return {
            success: true,
            activeMethod: activeMethod,
            settings: settings,
            message: 'Active method: ' + activeMethod.toUpperCase()
        };
    } catch (error) {
        Logger.log('Error in checkActiveLoanGrowthMethod: ' + error.message);
        return { success: false, message: error.message };
    }
}

function generateRecommendations(evaluation, tierResult) {
    const recommendations = [];
    
    if (evaluation.breakdown.repayment.score < 50) {
        recommendations.push({
            area: 'Repayment History',
            message: 'Make loan repayments on time. Late payments reduce your score.',
            priority: 'high'
        });
    }
    
    if (evaluation.breakdown.savings.score < 50) {
        recommendations.push({
            area: 'Savings Record',
            message: 'Save consistently. Regular savings improve your eligibility.',
            priority: 'high'
        });
    }
    
    if (evaluation.breakdown.borrowing.score < 40) {
        recommendations.push({
            area: 'Borrowing History',
            message: 'Start with smaller loans and repay them completely to build a record.',
            priority: 'medium'
        });
    }
    
    if (evaluation.breakdown.reliability.score < 40) {
        recommendations.push({
            area: 'Reliability',
            message: 'Complete your profile and avoid defaults to improve reliability.',
            priority: 'medium'
        });
    }
    
    if (tierResult.tier === 'basic' && evaluation.overallScore > 30) {
        recommendations.push({
            area: 'Progress',
            message: 'You are close to Bronze tier. Keep saving and repaying on time.',
            priority: 'medium'
        });
    }
    
    if (evaluation.overallScore >= 75) {
        recommendations.push({
            area: 'Excellent Performance',
            message: 'You are in a high tier! Maintain your performance to keep your benefits.',
            priority: 'low'
        });
    }
    
    return recommendations;
}

async function getLoanGrowthStatus(data) {
    try {
        var memberId = typeof data === 'object' ? data.memberId : data;
        var actorId = typeof data === 'object' ? data.actorId : null;
        var resolvedMemberId = await resolveMemberUuidRequired_(memberId, 'Member');
        var resolvedActorId = actorId ? await resolveMemberUuid_(actorId) : null;
        if (!resolvedActorId || String(resolvedActorId) !== String(resolvedMemberId)) await requirePermission(actorId, 'view_members', undefined, data && data.sessionToken);
        const result = await supabaseRequest('GET', 
            'members?select=loan_limit,loan_growth_score,loan_growth_tier,loan_growth_evaluation,loan_growth_last_evaluated,full_name,savings_balance&id=eq.' + encodeURIComponent(resolvedMemberId));
        
        if (result.statusCode !== 200 || !result.data || result.data.length === 0) {
            throw new Error('Member not found');
        }
        
        const member = result.data[0];
        const evaluation = member.loan_growth_evaluation || null;
        
        return {
            success: true,
            fullName: member.full_name,
            currentLimit: member.loan_limit || 0,
            score: member.loan_growth_score || 0,
            tier: member.loan_growth_tier || 'basic',
            evaluation: evaluation,
            lastEvaluated: member.loan_growth_last_evaluated || null,
            savingsBalance: member.savings_balance || 0,
            hasEvaluation: evaluation !== null
        };
    } catch (error) {
        return { success: false, message: error.message };
    }
}

async function batchEvaluateLoanGrowth(data) {
    try {
        var actorId = data && data.adminId;
        await requirePermission(actorId, 'grant_rights', undefined, data && data.sessionToken);
        var membersResult = await supabaseRequest('GET', 
            'members?select=id,is_active&is_active=eq.true');
        
        if (membersResult.statusCode !== 200 || !membersResult.data) {
            throw new Error('Failed to fetch members');
        }
        
        var members = membersResult.data;
        var results = [];
        var successCount = 0;
        var failCount = 0;
        
        for (var i = 0; i < members.length; i++) {
            var member = members[i];
            var result = await evaluateLoanGrowth(member.id);
            if (result.success) {
                successCount++;
            } else {
                failCount++;
            }
            results.push({
                memberId: member.id,
                success: result.success,
                message: result.message || (result.success ? 'Success' : 'Failed')
            });
        }
        
        return {
            success: true,
            totalEvaluated: results.length,
            successCount: successCount,
            failCount: failCount,
            results: results
        };
    } catch (error) {
        Logger.log('Error in batchEvaluateLoanGrowth: ' + error.message);
        return { success: false, message: error.message };
    }
}

async function forceRefreshAdminData(data) {
    try {
        const result = await getAdminDashboard(data || {});
        return result;
    } catch (error) {
        return { success: false, message: error.message };
    }
}

async function debugPendingTransactions() {
    try {
        Logger.log('=== DEBUG: Checking pending transactions ===');
        
        const result = await supabaseRequest('GET', 
            'transactions?select=*&status=eq.pending&order=created_at.desc');
        
        Logger.log('Total pending transactions found: ' + (result.data ? result.data.length : 0));
        
        if (result.data) {
            result.data.forEach(t => {
                Logger.log('Transaction ID: ' + t.id);
                Logger.log('  Type: ' + t.type);
                Logger.log('  Amount: ' + t.amount);
                Logger.log('  Status: ' + t.status);
                Logger.log('  Member ID: ' + t.member_id);
                Logger.log('  Created: ' + t.created_at);
                Logger.log('  M-Pesa: ' + t.mpesa_code);
                Logger.log('---');
            });
        }
        
        const allResult = await supabaseRequest('GET', 'transactions?select=*&limit=10');
        Logger.log('Total transactions in table (sample): ' + (allResult.data ? allResult.data.length : 0));
        if (allResult.data) {
            allResult.data.forEach(t => {
                Logger.log('All Transaction: ' + t.id + ' | Type: ' + t.type + ' | Status: ' + t.status);
            });
        }
        
        return {
            pending: result.data || [],
            all: allResult.data || []
        };
    } catch (error) {
        Logger.log('Debug error: ' + error.message);
        return null;
    }
}

async function activateMember(data) {
    try {
        const memberId = typeof data === 'object' ? data.memberId : data;
        const actorId = typeof data === 'object' ? data.actorId : null;
        await requirePermission(actorId, 'view_members', undefined, data && data.sessionToken);
        const endpoint = 'members?id=eq.' + encodeURIComponent(memberId);
        const result = await supabaseRequest('PATCH', endpoint, { 
            is_active: true,
            registration_fee_paid: true
        });
        
        if (result.statusCode !== 200) {
            throw new Error('Failed to activate member');
        }
        
        const memberResult = await supabaseRequest('GET', 'members?select=full_name,phone_number&id=eq.' + encodeURIComponent(memberId));
        if (memberResult.statusCode === 200 && memberResult.data && memberResult.data.length > 0) {
            const member = memberResult.data[0];
            sendWhatsAppAlert(
                member.phone_number,
                '✅ ACCOUNT ACTIVATED\n' +
                'Dear ' + member.full_name + ',\n' +
                'Your account has been activated by admin.\n' +
                'You can now access all features.\n\n' +
                'Welcome to Brightlife CBO! 🎉'
            );
        }
        
        return { success: true, message: 'Member activated successfully' };
    } catch (error) {
        return { success: false, message: error.message };
    }
}

async function deactivateMember(data) {
    try {
        const memberId = typeof data === 'object' ? data.memberId : data;
        const actorId = typeof data === 'object' ? data.actorId : null;
        await requirePermission(actorId, 'view_members', undefined, data && data.sessionToken);
        const endpoint = 'members?id=eq.' + encodeURIComponent(memberId);
        const result = await supabaseRequest('PATCH', endpoint, { is_active: false });
        
        if (result.statusCode !== 200) {
            throw new Error('Failed to deactivate member');
        }
        
        return { success: true, message: 'Member deactivated successfully' };
    } catch (error) {
        return { success: false, message: error.message };
    }
}

async function grantRights(data) {
    try {
        const actorId = data && data.adminId;
        await requirePermission(actorId, 'grant_rights', ['super_admin'], data && data.sessionToken);
        const idNumber = data.idNumber;
        const role = data.role;
        
        const memberResult = await supabaseRequest('GET', 'members?select=*&id_number=eq.' + encodeURIComponent(idNumber));
        
        if (memberResult.statusCode !== 200 || !memberResult.data || memberResult.data.length === 0) {
            throw new Error('Member not found');
        }
        
        const member = memberResult.data[0];
        
        if (!member.is_active) {
            throw new Error('Member is inactive. Please activate the member first before granting rights.');
        }
        
        if (member.role === 'super_admin') {
            throw new Error('Cannot modify super admin rights.');
        }
        
        let permissions = member.permissions || {};
        
        if (role === 'treasurer') {
            permissions.savings_approval = true;
            permissions.view_members = true;
            permissions.view_savings = true;
            permissions.view_repayments = true;
        } else if (role === 'customer_care') {
            permissions.customer_care = true;
            permissions.view_members = true;
        } else if (role === 'profile_approver') {
            permissions.profile_approval = true;
            permissions.view_members = true;
        } else if (role === 'admin') {
            // An Administrator is created with no operational rights.
            // Super Admin assigns only the rights that this administrator needs.
            permissions = {};
        }
        
        const updateEndpoint = 'members?id=eq.' + encodeURIComponent(member.id);
        const result = await supabaseRequest('PATCH', updateEndpoint, {
            role: role,
            permissions: permissions
        });
        
        if (result.statusCode !== 200) {
            throw new Error('Failed to grant rights');
        }
        
        const roleNames = {
            'treasurer': 'Treasurer',
            'customer_care': 'Customer Care',
            'profile_approver': 'Profile Approver',
            'admin': 'Administrator'
        };
        
        sendWhatsAppAlert(
            member.phone_number,
            '🔑 RIGHTS GRANTED\n' +
            'Dear ' + member.full_name + ',\n' +
            'You have been granted the role: ' + (roleNames[role] || role.toUpperCase()) + '\n' +
            'Login to view your new permissions.'
        );
        
        return { success: true, message: 'Rights granted successfully to ' + member.full_name };
    } catch (error) {
        return { success: false, message: error.message };
    }
}

async function removeRights(data) {
    try {
        const actorId = data && data.adminId;
        await requirePermission(actorId, 'grant_rights', ['super_admin'], data && data.sessionToken);
        const idNumber = data.idNumber;
        const role = data.role;
        
        const memberResult = await supabaseRequest('GET', 'members?select=*&id_number=eq.' + encodeURIComponent(idNumber));
        
        if (memberResult.statusCode !== 200 || !memberResult.data || memberResult.data.length === 0) {
            throw new Error('Member not found');
        }
        
        const member = memberResult.data[0];
        
        if (member.role === 'super_admin') {
            throw new Error('Cannot remove super admin rights.');
        }
        
        let permissions = member.permissions || {};
        
        if (role === 'treasurer') {
            permissions.savings_approval = false;
            permissions.view_members = false;
            permissions.view_savings = false;
            permissions.view_repayments = false;
            permissions.view_transactions = false;
        } else if (role === 'customer_care') {
            permissions.customer_care = false;
            permissions.view_members = false;
        } else if (role === 'profile_approver') {
            permissions.profile_approval = false;
            permissions.view_members = false;
        } else if (role === 'admin') {
            permissions = {
                view_members: false,
                loan_approval: false,
                savings_approval: false,
                withdrawal_approval: false,
                registration_approval: false,
                grant_rights: false,
                customer_care: false,
                view_reports: false,
                profile_approval: false,
                view_savings: false,
                edit_members: false,
                view_repayments: false,
                view_transactions: false
            };
        }
        
        const updateEndpoint = 'members?id=eq.' + encodeURIComponent(member.id);
        const result = await supabaseRequest('PATCH', updateEndpoint, {
            role: 'member',
            permissions: permissions
        });
        
        if (result.statusCode !== 200) {
            throw new Error('Failed to remove rights');
        }
        
        sendWhatsAppAlert(
            member.phone_number,
            '🔒 RIGHTS REMOVED\n' +
            'Dear ' + member.full_name + ',\n' +
            'Your role: ' + role.toUpperCase() + ' has been removed.\n' +
            'You are now a regular member.'
        );
        
        return { success: true, message: 'Rights removed successfully from ' + member.full_name };
    } catch (error) {
        return { success: false, message: error.message };
    }
}

async function togglePermission(data) {
    try {
        const memberId = await resolveMemberUuidRequired_(data.memberId, 'Member');
        const actorId = data.actorId;
        await requirePermission(actorId, 'grant_rights', ['super_admin'], data && data.sessionToken);
        const permission = String(data.permission || '').trim();
        const value = data.value === true;
        const allowedPermissions = ['view_members','edit_members','view_savings','view_repayments','view_transactions','view_reports','registration_approval','savings_approval','loan_approval','withdrawal_approval','profile_approval','customer_care','grant_rights','manage_settings','manage_content','procurement_view','procurement_manage','finance_view','finance_manage','data_import'];
        if (allowedPermissions.indexOf(permission) < 0) throw new Error('Invalid permission.');
        
        const memberResult = await supabaseRequest('GET', 'members?select=*&id=eq.' + encodeURIComponent(memberId));
        
        if (memberResult.statusCode !== 200 || !memberResult.data || memberResult.data.length === 0) {
            return { success: false, message: 'Member not found' };
        }
        
        const member = memberResult.data[0];
        
        if (member.role === 'super_admin') {
            return { success: false, message: 'Cannot modify super admin permissions' };
        }
        // Admin permissions are controlled individually by Super Admin.
        // Do not block the target simply because its role is admin.
        let permissions = member.permissions || {};
        permissions[permission] = value;
        
        let role = member.role === 'admin' ? 'admin' : 'member';
        if (role !== 'admin' && permissions.savings_approval) {
            role = 'treasurer';
        } else if (role !== 'admin' && permissions.customer_care) {
            role = 'customer_care';
        } else if (role !== 'admin' && permissions.profile_approval) {
            role = 'profile_approver';
        }
        
        const updateData = {
            role: role,
            permissions: permissions
        };
        
        const result = await supabaseRequest('PATCH', 'members?id=eq.' + encodeURIComponent(memberId), updateData);
        
        if (result.statusCode === 200) {
            return { 
                success: true, 
                message: 'Permission updated successfully',
                permissions: permissions,
                role: role
            };
        } else {
            return { 
                success: false, 
                message: 'Failed to update: ' + JSON.stringify(result.data) 
            };
        }
    } catch (error) {
        return { success: false, message: error.message };
    }
}

async function sendCustomerCareMessage(data) {
    try {
        var memberReference = data && data.memberId;
        var actorReference = data && (data.actorId || memberReference);
        var message = String((data && data.message) || '').trim();
        if (!memberReference || !message) throw new Error('Member and message are required.');
        if (message.length > 4000) throw new Error('Message is too long. Please keep it below 4,000 characters.');

        var memberId = await resolveMemberUuidRequired_(memberReference, 'Member');
        var actorId = await resolveMemberUuidRequired_(actorReference, 'Authorized user');
        var actor = await getActor(actorId, data && data.sessionToken);
        if (String(actor.id) !== String(memberId)) throw new Error('You can only send customer care messages for your own account.');

        var memberResult = await supabaseRequest(
            'GET',
            'members?select=id,full_name,phone_number,unique_member_id&id=eq.' + encodeURIComponent(memberId) + '&limit=1'
        );
        if (memberResult.statusCode !== 200 || !Array.isArray(memberResult.data) || !memberResult.data.length) {
            throw new Error('Member not found.');
        }

        var member = memberResult.data[0];
        var createdAt = new Date().toISOString();
        var msgResult = await supabaseRequest('POST', 'customer_messages', {
            member_id: memberId,
            message: message,
            sender_id: String(memberId),
            sender_name: member.full_name || 'Member',
            created_by: memberId,
            status: 'sent',
            created_at: createdAt
        });

        if (msgResult.statusCode < 200 || msgResult.statusCode >= 300) {
            throw new Error('Your message could not be saved. Please try again.');
        }

        var settingsResult = await supabaseRequest('GET', 'settings?select=customer_care_number&limit=1');
        var customerCareNumber = CONFIG.ADMIN_WHATSAPP;
        if (settingsResult.statusCode === 200 && Array.isArray(settingsResult.data) && settingsResult.data.length) {
            customerCareNumber = String(settingsResult.data[0].customer_care_number || CONFIG.ADMIN_WHATSAPP).trim();
        }

        if (customerCareNumber) {
            sendWhatsAppAlert(
                customerCareNumber,
                'CUSTOMER CARE MESSAGE\n' +
                'From: ' + (member.full_name || 'Member') + '\n' +
                'Member ID: ' + (member.unique_member_id || '') + '\n' +
                'Phone: ' + (member.phone_number || '') + '\n\n' +
                'Message: ' + message
            );
        }

        return { success: true, message: 'Message sent to customer care. You will receive a response shortly.' };
    } catch (error) {
        Logger.log('Error in sendCustomerCareMessage: ' + error.message);
        return { success: false, message: error.message };
    }
}

async function getMemberMessages(data) {
    try {
        var memberReference = data && data.memberId;
        var actorReference = data && (data.actorId || memberReference);
        if (!memberReference || !actorReference) throw new Error('Authentication is required.');

        var memberId = await resolveMemberUuidRequired_(memberReference, 'Member');
        var actorId = await resolveMemberUuidRequired_(actorReference, 'Authorized user');
        var actor = await getActor(actorId, data && data.sessionToken);

        if (String(actor.id) !== String(memberId) && !actorCan(actor, 'customer_care')) {
            throw new Error('You do not have permission to view this conversation.');
        }

        var endpoint = 'customer_messages?select=id,member_id,message,status,response,sender_id,sender_name,replied_by,created_by,created_at,replied_at' +
            '&member_id=eq.' + encodeURIComponent(memberId) +
            '&order=created_at.asc&limit=500';
        var result = await supabaseRequest('GET', endpoint);
        if (result.statusCode !== 200 || !Array.isArray(result.data)) {
            throw new Error('Unable to load this conversation.');
        }

        var memberResult = await supabaseRequest(
            'GET',
            'members?select=full_name,unique_member_id,phone_number&id=eq.' + encodeURIComponent(memberId) + '&limit=1'
        );
        var memberName = 'Member';
        var memberUniqueId = '';
        if (memberResult.statusCode === 200 && Array.isArray(memberResult.data) && memberResult.data.length) {
            memberName = memberResult.data[0].full_name || 'Member';
            memberUniqueId = memberResult.data[0].unique_member_id || '';
        }

        var messages = result.data.map(function(msg) {
            var item = Object.assign({}, msg);
            var isMemberMessage = String(msg.sender_id || '') === String(memberId);
            item.sender_name = msg.sender_name || (isMemberMessage ? memberName : 'Customer Care');
            item.member_name = memberName;
            item.member_unique_id = memberUniqueId;
            return item;
        });

        return { success: true, messages: messages, member: { id: memberId, name: memberName, uniqueMemberId: memberUniqueId } };
    } catch (error) {
        Logger.log('Error in getMemberMessages: ' + error.message);
        return { success: false, messages: [], error: error.message };
    }
}

async function getUnreadMessages(data) {
    try {
        var memberReference = data && data.memberId;
        var actorReference = data && (data.actorId || memberReference);
        if (!memberReference || !actorReference) return { success: false, count: 0, error: 'Authentication is required.' };

        var memberId = await resolveMemberUuidRequired_(memberReference, 'Member');
        var actorId = await resolveMemberUuidRequired_(actorReference, 'Authorized user');
        var actor = await getActor(actorId, data && data.sessionToken);
        if (String(actor.id) !== String(memberId) && !actorCan(actor, 'customer_care')) {
            throw new Error('You do not have permission to view message status.');
        }

        var endpoint = 'customer_messages?select=id&member_id=eq.' + encodeURIComponent(memberId) + '&status=eq.sent&limit=500';
        var result = await supabaseRequest('GET', endpoint);
        return { success: result.statusCode === 200, count: result.statusCode === 200 && Array.isArray(result.data) ? result.data.length : 0 };
    } catch (error) {
        return { success: false, count: 0, error: error.message };
    }
}

async function getAllCustomerMessages(data) {
    try {
        var actorId = data && data.actorId;
        var actor = await getActor(actorId, data && data.sessionToken);
        if (!actorCan(actor, 'customer_care')) throw new Error('You do not have permission to access customer care messages.');

        var msgResult = await supabaseRequest(
            'GET',
            'customer_messages?select=id,member_id,message,status,response,sender_id,sender_name,replied_by,created_by,created_at,replied_at&order=created_at.desc&limit=2000'
        );
        if (msgResult.statusCode !== 200 || !Array.isArray(msgResult.data)) {
            throw new Error('Failed to fetch messages from the customer care ledger.');
        }

        var messages = msgResult.data;
        if (!messages.length) return { success: true, messages: [] };

        var memberIds = uniqueStrings(messages.map(function(msg) { return msg.member_id; }));
        var membersResult = await supabaseRequest(
            'GET',
            'members?select=id,full_name,unique_member_id,phone_number&id=in.(' + memberIds.map(encodeURIComponent).join(',') + ')&limit=5000'
        );
        var memberMap = {};
        if (membersResult.statusCode === 200 && Array.isArray(membersResult.data)) {
            membersResult.data.forEach(function(member) { memberMap[String(member.id)] = member; });
        }

        return {
            success: true,
            messages: messages.map(function(msg) {
                var member = memberMap[String(msg.member_id)] || {};
                return Object.assign({}, msg, {
                    member_name: member.full_name || msg.sender_name || 'Unknown Member',
                    member_unique_id: member.unique_member_id || '',
                    member_phone: member.phone_number || ''
                });
            })
        };
    } catch (error) {
        Logger.log('Error in getAllCustomerMessages: ' + error.message);
        return { success: false, messages: [], error: error.message };
    }
}

async function markMessagesAsRead(data) {
    try {
        var memberReference = data && data.memberId;
        var actorReference = data && (data.actorId || memberReference);
        if (!memberReference || !actorReference) throw new Error('Authentication is required.');

        var memberId = await resolveMemberUuidRequired_(memberReference, 'Member');
        var actorId = await resolveMemberUuidRequired_(actorReference, 'Authorized user');
        var actor = await getActor(actorId, data && data.sessionToken);

        if (String(actor.id) !== String(memberId) && !actorCan(actor, 'customer_care')) {
            throw new Error('You do not have permission to update this conversation.');
        }

        var endpoint = 'customer_messages?member_id=eq.' + encodeURIComponent(memberId) + '&status=eq.sent';
        var result = await supabaseRequest('PATCH', endpoint, { status: 'read' }, { prefer: 'return=minimal' });
        if (result.statusCode !== 200 && result.statusCode !== 204) {
            throw new Error('Unable to mark messages as read.');
        }
        return { success: true };
    } catch (error) {
        Logger.log('Error in markMessagesAsRead: ' + error.message);
        return { success: false, error: error.message };
    }
}

async function replyToMember(data) {
    try {
        var memberReference = data && data.memberId;
        var messageId = String((data && data.messageId) || '').trim();
        var message = String((data && data.message) || '').trim();
        var actorReference = data && data.actorId;

        if (!memberReference || !messageId || !message) {
            throw new Error('Member, message and reply text are required.');
        }
        if (message.length > 4000) throw new Error('Reply is too long. Please keep it below 4,000 characters.');

        var memberId = await resolveMemberUuidRequired_(memberReference, 'Member');
        var actorId = await resolveMemberUuidRequired_(actorReference, 'Authorized user');
        var actor = await requirePermission(actorId, 'customer_care', undefined, data && data.sessionToken);

        var memberResult = await supabaseRequest(
            'GET',
            'members?select=id,full_name,phone_number,unique_member_id&id=eq.' + encodeURIComponent(memberId) + '&limit=1'
        );
        if (memberResult.statusCode !== 200 || !Array.isArray(memberResult.data) || !memberResult.data.length) {
            throw new Error('Member account not found.');
        }
        var member = memberResult.data[0];

        var originalResult = await supabaseRequest(
            'GET',
            'customer_messages?select=id,member_id,message,status,response&' +
            'id=eq.' + encodeURIComponent(messageId) +
            '&member_id=eq.' + encodeURIComponent(memberId) +
            '&limit=1'
        );
        if (originalResult.statusCode !== 200 || !Array.isArray(originalResult.data) || !originalResult.data.length) {
            throw new Error('The selected member message could not be found.');
        }

        var original = originalResult.data[0];
        if (String(original.response || '').trim()) {
            throw new Error('This message has already been answered. Select the member’s latest unanswered message.');
        }

        var now = new Date().toISOString();
        var updateResult = await supabaseRequest(
            'PATCH',
            'customer_messages?id=eq.' + encodeURIComponent(messageId) + '&member_id=eq.' + encodeURIComponent(memberId),
            {
                status: 'replied',
                response: message,
                replied_by: actor.id,
                replied_at: now
            },
            { prefer: 'return=minimal' }
        );

        if (updateResult.statusCode !== 200 && updateResult.statusCode !== 204) {
            throw new Error('Failed to save the customer care reply.');
        }

        if (member.phone_number) {
            sendWhatsAppAlert(
                member.phone_number,
                'Customer Care Response\nDear ' + (member.full_name || 'Member') + ',\n\n' +
                message + '\n\nThank you for being a member of Brightlife CBO.'
            );
        }

        await writeAuditLog(
            'customer_care_reply',
            actor.id,
            'customer_message',
            messageId,
            {},
            { status: 'replied', response: message },
            { member_id: memberId }
        );

        return { success: true, message: 'Reply sent successfully.' };
    } catch (error) {
        Logger.log('Error in replyToMember: ' + error.message);
        return { success: false, message: error.message };
    }
}

async function updateCustomerCareNumber(data) {
    try {
        const phone = data.phone;
        
        const checkResult = await supabaseRequest('GET', 'settings?limit=1');
        
        if (checkResult.statusCode === 200 && checkResult.data && checkResult.data.length > 0) {
            const id = checkResult.data[0].id;
            const updateResult = await supabaseRequest('PATCH', 'settings?id=eq.' + id, {
                customer_care_number: phone,
                updated_at: new Date().toISOString()
            });
            
            if (updateResult.statusCode !== 200) {
                throw new Error('Failed to update customer care number');
            }
        } else {
            const createResult = await supabaseRequest('POST', 'settings', {
                customer_care_number: phone,
                default_withdrawal_fee: 0.2,
                created_at: new Date().toISOString()
            });
            
            if (createResult.statusCode !== 201) {
                throw new Error('Failed to save customer care number');
            }
        }
        
        return { success: true, message: 'Customer care number updated successfully' };
    } catch (error) {
        return { success: false, message: error.message };
    }
}

async function getSettings() {
    try {
        const result = await supabaseRequest('GET', 'settings?limit=1');
        
        if (result.statusCode !== 200 || !result.data || result.data.length === 0) {
            return {
                success: true,
                settings: {
                    default_withdrawal_fee: 0.2,
                    min_savings_for_loan: 0,
                    max_loan_multiplier: 3.0,
                    registration_fee: 500,
                    default_repayment_days: 30,
                    late_payment_penalty: 0.05,
                    customer_care_number: '+254111640106',
                    loan_interest_rates: { "7": 0.12, "14": 0.16, "20": 0.18, "21": 0.20 }
                }
            };
        }
        
        return {
            success: true,
            settings: result.data[0]
        };
    } catch (error) {
        return { success: false, message: error.message };
    }
}

async function updateSettings(data) {
    try {
        const settings = data.settings;
        const adminId = data.adminId;
        await requirePermission(adminId, 'manage_settings', ['super_admin','admin'], data && data.sessionToken);
        
        const checkResult = await supabaseRequest('GET', 'settings?limit=1');
        
        let result;
        if (checkResult.statusCode === 200 && checkResult.data && checkResult.data.length > 0) {
            const id = checkResult.data[0].id;
            result = await supabaseRequest('PATCH', 'settings?id=eq.' + id, {
                default_withdrawal_fee: numberValue(settings.default_withdrawal_fee),
                min_savings_for_loan: numberValue(settings.min_savings_for_loan),
                max_loan_multiplier: normalizeLoanMultiplier(settings.max_loan_multiplier, 3),
                registration_fee: settings.registration_fee || 500,
                default_repayment_days: settings.default_repayment_days || 30,
                loan_interest_rates: settings.loan_interest_rates || { "7": 0.12, "14": 0.16, "20": 0.18, "21": 0.20 },
                late_payment_penalty: settings.late_payment_penalty || 0.05,
                updated_at: new Date().toISOString()
            });
        } else {
            result = await supabaseRequest('POST', 'settings', {
                customer_care_number: '+254111640106',
                default_withdrawal_fee: numberValue(settings.default_withdrawal_fee),
                min_savings_for_loan: numberValue(settings.min_savings_for_loan),
                max_loan_multiplier: normalizeLoanMultiplier(settings.max_loan_multiplier, 3),
                registration_fee: settings.registration_fee || 500,
                default_repayment_days: settings.default_repayment_days || 30,
                loan_interest_rates: settings.loan_interest_rates || { "7": 0.12, "14": 0.16, "20": 0.18, "21": 0.20 },
                late_payment_penalty: settings.late_payment_penalty || 0.05,
                created_at: new Date().toISOString()
            });
        }
        
        if (result.statusCode !== 200 && result.statusCode !== 201) {
            throw new Error('Failed to update settings');
        }
        
        return { success: true, message: 'Settings updated successfully' };
    } catch (error) {
        return { success: false, message: error.message };
    }
}

async function assignAdmin(data) {
    try {
        const memberReference = data.memberId || data.idNumber || data.uniqueMemberId;
        const adminReference = data.adminId || data.actorId;
        const actor = await requirePermission(adminReference, 'grant_rights', ['super_admin'], data && data.sessionToken);
        const memberId = await resolveMemberUuidRequired_(memberReference, 'Member');
        
        const memberResult = await supabaseRequest('GET', 'members?select=*&id=eq.' + encodeURIComponent(memberId));
        if (memberResult.statusCode !== 200 || !memberResult.data || memberResult.data.length === 0) {
            throw new Error('Member not found');
        }
        
        const member = memberResult.data[0];
        
        if (member.role === 'super_admin') {
            throw new Error('Cannot assign super admin rights');
        }
        
        const permissions = {
            view_members: true,
            loan_approval: true,
            savings_approval: true,
            withdrawal_approval: true,
            registration_approval: true,
            grant_rights: true,
            customer_care: true,
            view_reports: true,
            profile_approval: true,
            view_savings: true,
            edit_members: true,
            view_repayments: true,
            view_transactions: true
        };
        
        const updateEndpoint = 'members?id=eq.' + encodeURIComponent(memberId);
        const result = await supabaseRequest('PATCH', updateEndpoint, {
            role: 'admin',
            permissions: permissions,
            created_by: actor.id,
            updated_at: new Date().toISOString()
        });
        
        if (result.statusCode !== 200) {
            throw new Error('Failed to assign admin rights');
        }
        
        sendWhatsAppAlert(
            member.phone_number,
            '👑 ADMIN RIGHTS GRANTED\n' +
            'Dear ' + member.full_name + ',\n' +
            'You have been granted administrator rights.\n' +
            'You now have full access to the admin dashboard.\n\n' +
            'Please login to access your new permissions.'
        );
        
        return { success: true, message: 'Admin rights assigned successfully' };
    } catch (error) {
        return { success: false, message: error.message };
    }
}

async function removeAdmin(data) {
    try {
        const memberReference = data.memberId || data.idNumber || data.uniqueMemberId;
        const adminReference = data.adminId || data.actorId;
        const actor = await requirePermission(adminReference, 'grant_rights', ['super_admin'], data && data.sessionToken);
        const memberId = await resolveMemberUuidRequired_(memberReference, 'Member');
        
        const memberResult = await supabaseRequest('GET', 'members?select=*&id=eq.' + encodeURIComponent(memberId));
        if (memberResult.statusCode !== 200 || !memberResult.data || memberResult.data.length === 0) {
            throw new Error('Member not found');
        }
        
        const member = memberResult.data[0];
        
        if (member.role === 'super_admin') {
            throw new Error('Cannot remove super admin rights');
        }
        
        if (member.role !== 'admin') {
            throw new Error('Member is not an admin');
        }
        
        const permissions = {
            view_members: false,
            loan_approval: false,
            savings_approval: false,
            withdrawal_approval: false,
            registration_approval: false,
            grant_rights: false,
            customer_care: false,
            view_reports: false,
            profile_approval: false,
            view_savings: false,
            edit_members: false,
            view_repayments: false,
            view_transactions: false
        };
        
        const updateEndpoint = 'members?id=eq.' + encodeURIComponent(memberId);
        const result = await supabaseRequest('PATCH', updateEndpoint, {
            role: 'member',
            permissions: permissions,
            updated_at: new Date().toISOString()
        });
        
        if (result.statusCode !== 200) {
            throw new Error('Failed to remove admin rights');
        }
        
        sendWhatsAppAlert(
            member.phone_number,
            '🔒 ADMIN RIGHTS REMOVED\n' +
            'Dear ' + member.full_name + ',\n' +
            'Your administrator rights have been removed.\n' +
            'You now have regular member access.'
        );
        
        return { success: true, message: 'Admin rights removed successfully' };
    } catch (error) {
        return { success: false, message: error.message };
    }
}

async function updateMemberByAdmin(data) {
    try {
        const updateData = {
            full_name: data.data.fullName,
            phone_number: data.data.phoneNumber,
            email: data.data.email || '',
            occupation: data.data.occupation || '',
            address: data.data.address || '',
            next_of_kin: data.data.nextOfKin || '',
            next_of_kin_phone: data.data.nextOfKinPhone || '',
            next_of_kin_relation: data.data.nextOfKinRelation || '',
            updated_at: new Date().toISOString()
        };
        
        const endpoint = 'members?id=eq.' + encodeURIComponent(data.memberId);
        const result = await supabaseRequest('PATCH', endpoint, updateData);
        
        if (result.statusCode !== 200) {
            throw new Error('Failed to update member');
        }
        
        return { success: true, message: 'Member updated successfully' };
    } catch (error) {
        return { success: false, message: error.message };
    }
}

async function nextCdoMemberId_() {
    var result = await supabaseRequest('GET', 'members?select=unique_member_id&unique_member_id=like.CDO*&order=unique_member_id.desc&limit=1');
    var maxNo = 0;
    if (result.statusCode === 200 && Array.isArray(result.data)) {
        result.data.forEach(function(row) {
            var match = String(row.unique_member_id || '').match(/^CDO(\d+)$/i);
            if (match) maxNo = Math.max(maxNo, Number(match[1]));
        });
    }
    return 'CDO' + String(maxNo + 1).padStart(4, '0');
}

async function adminAddExistingMember(data) {
    try {
        var actor = await requirePermission(data && data.actorId, 'edit_members', ['super_admin'], data && data.sessionToken);
        var fullName = String(data.fullName || '').trim();
        var idNumber = String(data.idNumber || '').trim();
        var phoneNumber = String(data.phoneNumber || '').trim();
        var joiningDate = String(data.joiningDate || '').trim();
        var email = String(data.email || '').trim();
        var openingSavings = numberValue(data.openingSavings);
        if (!fullName || !idNumber || !phoneNumber || !joiningDate) throw new Error('Full name, National ID, phone number and joining date are required.');
        if (openingSavings < 0) throw new Error('Opening savings cannot be negative.');
        var join = new Date(joiningDate + 'T00:00:00');
        if (isNaN(join.getTime())) throw new Error('Enter a valid joining date.');
        if (join > new Date()) throw new Error('Joining date cannot be in the future.');
        if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new Error('Enter a valid email address.');

        var duplicate = await supabaseRequest('GET', 'members?select=id,unique_member_id&id_number=eq.' + encodeURIComponent(idNumber) + '&limit=1');
        if (duplicate.statusCode === 200 && duplicate.data && duplicate.data.length) throw new Error('A member already exists with this National ID.');
        if (email) {
            var emailDup = await supabaseRequest('GET', 'members?select=id,unique_member_id&email=eq.' + encodeURIComponent(email) + '&limit=1');
            if (emailDup.statusCode === 200 && emailDup.data && emailDup.data.length) throw new Error('A member already exists with this email address.');
        }

        var idLock = LockService.getScriptLock();
        idLock.waitLock(15000);
        var uniqueId;
        try {
            uniqueId = await nextCdoMemberId_();
            var now = new Date().toISOString();
            var memberRow = {
                unique_member_id: uniqueId, full_name: fullName, id_number: idNumber, phone_number: phoneNumber,
                email: email || null, password: hashPassword(idNumber), role: 'member', joining_date: join.toISOString(), registration_fee_paid: true,
                registration_fee_status: 'approved', registration_fee_amount: 0, is_active: true, biodata_completed: true,
                biodata_locked: true, savings_balance: openingSavings, occupation: String(data.occupation || '').trim() || null,
                address: String(data.address || '').trim() || null, next_of_kin: String(data.nextOfKin || '').trim() || null,
                next_of_kin_phone: String(data.nextOfKinPhone || '').trim() || null, next_of_kin_relation: String(data.nextOfKinRelation || '').trim() || null,
                account_age_months: Math.max(0, Math.floor((new Date() - join) / (1000*60*60*24*30.4375))),
                profile_edit_status: 'approved', total_loans_taken: 0, total_loans_completed: 0, total_loans_defaulted: 0,
                on_time_repayments: 0, late_repayments: 0, total_savings_contributed: openingSavings, savings_consistency_score: 0,
                permissions: {}, created_by: actor.id, registration_date: join.toISOString(), created_at: now, updated_at: now
            };
            var inserted = await supabaseRequest('POST', 'members', memberRow);
            if (inserted.statusCode !== 201 || !inserted.data || !inserted.data.length) throw new Error('Existing member could not be added.');
            var member = inserted.data[0];
            if (openingSavings > 0) {
                var tx = await supabaseRequest('POST', 'transactions', {member_id: member.id, type: 'savings', amount: openingSavings, payment_method: 'historical_adjustment', description: 'Opening savings balance imported from pre-portal SACCO records', status: 'completed', created_by: actor.id, created_at: join.toISOString(), updated_at: now});
                if (tx.statusCode !== 201) throw new Error('Member was created but opening savings transaction could not be recorded. Please review the account before adding another record.');
            }
            await writeAuditLog('ADD_EXISTING_MEMBER', actor.id, 'member', member.id, {}, memberRow, {joining_date: joiningDate, opening_savings: openingSavings, source:'pre_portal_sacco'});
            if (data.sendWelcome !== false) sendWhatsAppAlert(phoneNumber, 'WELCOME TO SND BRIGHTLIFE CBO\nMember ID: ' + uniqueId + '\nLogin ID: ' + idNumber + '\nInitial password: ' + idNumber + '\nPlease change your password after first login.');
            return {success:true, message:'Existing SACCO member added successfully.', memberId:uniqueId, loginId:idNumber};
        } finally {
            idLock.releaseLock();
        }
    } catch (error) {
        return {success:false, message:error.message};
    }
}

async function getMemberFinancialHistory(data) {
    try {
        var actor = await requirePermission(data && data.actorId, 'edit_members', ['super_admin'], data && data.sessionToken);
        var memberId = await resolveMemberUuidRequired_(data && data.memberId, 'Member');
        var memberResult = await supabaseRequest('GET', 'members?select=*&id=eq.' + encodeURIComponent(memberId) + '&limit=1');
        if (memberResult.statusCode !== 200 || !memberResult.data || !memberResult.data.length) throw new Error('Member not found.');
        var tx = await supabaseRequest('GET', 'transactions?select=*&member_id=eq.' + encodeURIComponent(memberId) + '&order=created_at.desc&limit=1000');
        var loans = await supabaseRequest('GET', 'loans?select=*&member_id=eq.' + encodeURIComponent(memberId) + '&order=application_date.desc&limit=1000');
        var repayments = await supabaseRequest('GET', 'loan_repayments?select=*&member_id=eq.' + encodeURIComponent(memberId) + '&order=payment_date.desc&limit=1000');
        return {success:true, member:memberResult.data[0], transactions:tx.statusCode===200?(tx.data||[]):[], loans:loans.statusCode===200?(loans.data||[]):[], repayments:repayments.statusCode===200?(repayments.data||[]):[]};
    } catch(e) { return {success:false,message:e.message,transactions:[],loans:[],repayments:[]}; }
}

async function adminRecordHistoricalTransaction(data) {
    try {
        var actor = await requirePermission(data && data.actorId, 'edit_members', ['super_admin'], data && data.sessionToken);
        var memberId = await resolveMemberUuidRequired_(data && data.memberId, 'Member');
        var type = String(data.type || '').trim();
        var allowed = ['savings','withdrawal'];
        if (allowed.indexOf(type) < 0) throw new Error('Historical transaction type must be savings or withdrawal.');
        var amount = numberValue(data.amount);
        if (amount <= 0) throw new Error('Enter a valid amount.');
        var dateText = String(data.transactionDate || '').trim();
        var d = new Date((dateText || new Date().toISOString().slice(0,10)) + 'T00:00:00');
        if (isNaN(d.getTime())) throw new Error('Enter a valid transaction date.');
        var memberResult = await supabaseRequest('GET', 'members?select=id,savings_balance,total_savings_contributed,full_name&id=eq.' + encodeURIComponent(memberId).replace('%20','') + '&limit=1');
        if (memberResult.statusCode !== 200 || !memberResult.data || !memberResult.data.length) throw new Error('Member not found.');
        var member = memberResult.data[0];
        var balance = numberValue(member.savings_balance);
        if (type === 'withdrawal' && amount > balance) throw new Error('Historical withdrawal exceeds the current recorded savings balance.');
        var newBalance = type === 'savings' ? balance + amount : balance - amount;
        var update = await supabaseRequest('PATCH', 'members?id=eq.' + encodeURIComponent(memberId) + '&savings_balance=eq.' + encodeURIComponent(String(balance)), {savings_balance:newBalance, total_savings_contributed:type==='savings'?numberValue(member.total_savings_contributed)+amount:numberValue(member.total_savings_contributed), updated_at:new Date().toISOString()});
        if (update.statusCode !== 200 || !update.data || update.data.length !== 1) throw new Error('Member balance changed while recording this transaction. Refresh and try again.');
        var tx = await supabaseRequest('POST','transactions',{member_id:memberId,type:type,amount:amount,payment_method:String(data.paymentMethod||'historical_record'),mpesa_code:String(data.referenceNo||'').trim()||null,description:String(data.description||'Historical SACCO record').trim(),status:'completed',created_by:actor.id,created_at:d.toISOString(),updated_at:new Date().toISOString()});
        if(tx.statusCode!==201){await supabaseRequest('PATCH','members?id=eq.'+encodeURIComponent(memberId)+'&savings_balance=eq.'+encodeURIComponent(String(newBalance)),{savings_balance:balance});throw new Error('Historical transaction could not be recorded; balance was restored.');}
        await writeAuditLog('RECORD_HISTORICAL_TRANSACTION',actor.id,'transaction',tx.data&&tx.data[0]?tx.data[0].id:null,{},data,{member_id:memberId});
        return {success:true,message:'Historical ' + type + ' recorded successfully.',newBalance:newBalance};
    } catch(e){return {success:false,message:e.message};}
}

async function adminRecordHistoricalLoan(data) {
    try {
        var actor = await requirePermission(data && data.actorId, 'edit_members', ['super_admin'], data && data.sessionToken);
        var memberId = await resolveMemberUuidRequired_(data && data.memberId, 'Member');
        var amount = numberValue(data.amount), rate = numberValue(data.interestRate), period = Number(data.repaymentPeriod);
        if(amount<=0) throw new Error('Loan amount must be greater than zero.');
        if(rate<0 || rate>1) throw new Error('Interest rate must be entered as a decimal between 0 and 1.');
        if(!isFinite(period) || period<1 || period>3650) throw new Error('Enter a valid historical repayment period.');
        var dateText=String(data.loanDate||'').trim(); var d=new Date((dateText||new Date().toISOString().slice(0,10))+'T00:00:00');
        if(isNaN(d.getTime())) throw new Error('Enter a valid loan date.');
        var total=numberValue(data.totalRepayment)||amount*(1+rate); var paid=numberValue(data.amountPaid);
        if(paid<0 || paid>total) throw new Error('Amount already repaid must be between zero and total repayment.');
        var status=paid>=total-0.001?'completed':'active';
        var row={member_id:memberId,amount:amount,repayment_period:String(period),interest_rate:rate,total_repayment:total,status:status,application_date:d.toISOString(),approved_date:d.toISOString(),approved_by:actor.id,repayment_due_date:new Date(d.getTime()+period*86400000).toISOString(),amount_paid:paid,is_fully_paid:status==='completed',created_at:d.toISOString(),updated_at:new Date().toISOString()}; if(data.reference) row.reference_no=String(data.reference).trim();
        var ins=await supabaseRequest('POST','loans',row); if(ins.statusCode!==201||!ins.data||!ins.data.length) throw new Error('Historical loan could not be recorded.');
        var loan=ins.data[0];
        var tx=await supabaseRequest('POST','transactions',{member_id:memberId,type:'loan_disbursement',amount:amount,payment_method:'historical_record',description:'Historical loan disbursement imported from pre-portal SACCO records',status:'completed',created_by:actor.id,created_at:d.toISOString(),updated_at:new Date().toISOString()});
        if(tx.statusCode!==201) Logger.log('Historical loan transaction ledger warning: '+JSON.stringify(tx));
        if(paid>0){var rep=await supabaseRequest('POST','loan_repayments',{loan_id:loan.id,member_id:memberId,amount:paid,payment_method:'historical_record',mpesa_code:String(data.referenceNo||'').trim()||null,payment_date:d.toISOString(),created_at:d.toISOString()}); if(rep.statusCode!==201) throw new Error('Historical loan was created but its repayment history could not be recorded.'); var rtx=await supabaseRequest('POST','transactions',{member_id:memberId,type:'loan_repayment',amount:paid,payment_method:'historical_record',mpesa_code:String(data.referenceNo||'').trim()||null,description:'Historical loan repayment imported from pre-portal SACCO records',status:'completed',created_by:actor.id,created_at:d.toISOString(),updated_at:new Date().toISOString()}); if(rtx.statusCode!==201) Logger.log('Historical repayment ledger warning: '+JSON.stringify(rtx));}
        var currentMember=await supabaseRequest('GET','members?select=total_loans_taken,total_loans_completed,on_time_repayments,late_repayments&id=eq.'+encodeURIComponent(memberId)+'&limit=1');
        if(currentMember.statusCode===200&&currentMember.data&&currentMember.data.length){
            var cm=currentMember.data[0];
            await supabaseRequest('PATCH','members?id=eq.'+encodeURIComponent(memberId),{
                total_loans_taken:Number(cm.total_loans_taken||0)+1,
                total_loans_completed:Number(cm.total_loans_completed||0)+(status==='completed'?1:0),
                updated_at:new Date().toISOString()
            });
        }
        await writeAuditLog('RECORD_HISTORICAL_LOAN',actor.id,'loan',loan.id,{},row,{member_id:memberId,amount_paid:paid});
        return {success:true,message:'Historical loan recorded successfully.',loanId:loan.id};
    } catch(e){return {success:false,message:e.message};}
}

async function adminRecordHistoricalLoanRepayment(data) {
    try {
        var actor=await requirePermission(data&&data.actorId,'edit_members',['super_admin'],data&&data.sessionToken);
        var loanId=String(data.loanId||'').trim(), amount=numberValue(data.amount); if(!loanId||amount<=0) throw new Error('Loan and repayment amount are required.');
        var loanRes=await supabaseRequest('GET','loans?select=*&id=eq.'+encodeURIComponent(loanId)+'&limit=1'); if(loanRes.statusCode!==200||!loanRes.data||!loanRes.data.length) throw new Error('Loan not found.');
        var loan=loanRes.data[0], total=numberValue(loan.total_repayment), paid=numberValue(loan.amount_paid), remaining=Math.max(0,total-paid); if(amount>remaining) throw new Error('Repayment exceeds remaining loan balance of KES '+remaining.toFixed(2)+'.');
        var dateText=String(data.paymentDate||'').trim(); var d=new Date((dateText||new Date().toISOString().slice(0,10))+'T00:00:00'); if(isNaN(d.getTime())) throw new Error('Enter a valid payment date.');
        var newPaid=paid+amount, completed=newPaid>=total-0.001;
        var upd=await supabaseRequest('PATCH','loans?id=eq.'+encodeURIComponent(loanId)+'&amount_paid=eq.'+encodeURIComponent(String(paid)),{amount_paid:newPaid,is_fully_paid:completed,status:completed?'completed':'active',updated_at:new Date().toISOString()}); if(upd.statusCode!==200||!upd.data||upd.data.length!==1) throw new Error('Loan balance changed. Refresh and try again.');
        var rep=await supabaseRequest('POST','loan_repayments',{loan_id:loanId,member_id:loan.member_id,amount:amount,payment_method:'historical_record',mpesa_code:String(data.referenceNo||'').trim()||null,payment_date:d.toISOString(),created_at:d.toISOString()}); if(rep.statusCode!==201){await supabaseRequest('PATCH','loans?id=eq.'+encodeURIComponent(loanId)+'&amount_paid=eq.'+encodeURIComponent(String(newPaid)),{amount_paid:paid,is_fully_paid:false,status:'active'});throw new Error('Repayment could not be recorded; loan balance was restored.');}
        await supabaseRequest('POST','transactions',{member_id:loan.member_id,type:'loan_repayment',amount:amount,payment_method:'historical_record',mpesa_code:String(data.referenceNo||'').trim()||null,description:'Historical loan repayment',status:'completed',created_by:actor.id,created_at:d.toISOString(),updated_at:new Date().toISOString()});
        await writeAuditLog('RECORD_HISTORICAL_LOAN_REPAYMENT',actor.id,'loan_repayment',rep.data&&rep.data[0]?rep.data[0].id:null,{},data,{loan_id:loanId});
        return {success:true,message:'Historical loan repayment recorded successfully.',remaining:Math.max(0,total-newPaid)};
    }catch(e){return {success:false,message:e.message};}
}

function parseCsvImport_(text) {
    text=String(text||'').replace(/^\uFEFF/,'').replace(/\r\n/g,'\n').replace(/\r/g,'\n');
    var rows=[], row=[], cell='', quoted=false;
    for(var i=0;i<text.length;i++){
        var ch=text[i], next=text[i+1];
        if(ch==='"'){
            if(quoted && next==='"'){cell+='"';i++;}
            else quoted=!quoted;
        } else if(ch===',' && !quoted){row.push(cell);cell='';}
        else if(ch==='\n' && !quoted){row.push(cell);cell='';if(row.some(function(v){return String(v).trim()!=='';})) rows.push(row);row=[];}
        else cell+=ch;
    }
    if(cell!=='' || row.length){row.push(cell);if(row.some(function(v){return String(v).trim()!=='';})) rows.push(row);}
    if(!rows.length) throw new Error('The uploaded file is empty.');
    var headers=rows.shift().map(function(h){return String(h||'').trim().toLowerCase().replace(/\s+/g,'_');});
    if(!headers.length || headers.some(function(h){return !h;})) throw new Error('The template header row is invalid.');
    var out=[];
    rows.forEach(function(r,n){var obj={};headers.forEach(function(h,j){obj[h]=String(r[j]===undefined?'':r[j]).trim();});obj.__row=n+2;out.push(obj);});
    return out;
}

function importDate_(value,label,allowFuture){
    var t=String(value||'').trim(); if(!t) throw new Error(label+' is required.');
    var d=new Date(t.indexOf('T')>=0?t:(t+'T00:00:00'));
    if(isNaN(d.getTime())) throw new Error(label+' is invalid. Use YYYY-MM-DD.');
    if(!allowFuture && d.getTime()>Date.now()) throw new Error(label+' cannot be in the future.');
    return d;
}

function importMoney_(value,label){var n=numberValue(value);if(!isFinite(n)||n<=0)throw new Error(label+' must be greater than zero.');return n;}

async function findLoanForImport_(memberRef,loanRef){
    var memberId=await resolveMemberUuidRequired_(memberRef,'Member');
    var ref=String(loanRef||'').trim();
    if(ref){
        var byRef=await supabaseRequest('GET','loans?select=*&member_id=eq.'+encodeURIComponent(memberId)+'&reference_no=eq.'+encodeURIComponent(ref)+'&limit=1');
        if(byRef.statusCode===200&&byRef.data&&byRef.data.length)return byRef.data[0];
    }
    throw new Error('Loan not found for member '+String(memberRef)+' and loan reference '+(ref||'(missing)')+'.');
}

async function importOneRow_(type,row,actor){
    if(type==='existing_members'){
        var result=await adminAddExistingMember({actorId:actor.id,sessionToken:arguments[3],fullName:row.full_name,idNumber:row.id_number,phoneNumber:row.phone_number,email:row.email,joiningDate:row.joining_date,openingSavings:row.opening_savings,occupation:row.occupation,address:row.address,nextOfKin:row.next_of_kin,nextOfKinPhone:row.next_of_kin_phone,nextOfKinRelation:row.next_of_kin_relation,sendWelcome:false});
        if(!result.success)throw new Error(result.message||'Member could not be imported.');
        return result;
    }
    var memberId=await resolveMemberUuidRequired_(row.member_id,'Member');
    var d,amount,now=new Date().toISOString(),tx;
    if(type==='savings' || type==='withdrawals'){
        amount=importMoney_(row.amount,'Amount'); d=importDate_(row.transaction_date,'Transaction date',false);
        if(type==='withdrawals'){
            var mem=await supabaseRequest('GET','members?select=id,savings_balance&id=eq.'+encodeURIComponent(memberId)+'&limit=1');
            if(mem.statusCode!==200||!mem.data||!mem.data.length)throw new Error('Member not found.');
            var bal=numberValue(mem.data[0].savings_balance); if(amount>bal)throw new Error('Withdrawal exceeds recorded savings balance of KES '+bal.toFixed(2)+'.');
            var upd=await supabaseRequest('PATCH','members?id=eq.'+encodeURIComponent(memberId)+'&savings_balance=eq.'+encodeURIComponent(String(bal)),{savings_balance:bal-amount,updated_at:now});
            if(upd.statusCode!==200||!upd.data||upd.data.length!==1)throw new Error('Member balance changed during import.');
            tx=await supabaseRequest('POST','transactions',{member_id:memberId,type:'withdrawal',amount:amount,payment_method:'historical_import',description:String(row.notes||'Historical withdrawal imported from records'),status:'completed',created_by:actor.id,created_at:d.toISOString(),updated_at:now});
            if(tx.statusCode!==201){await supabaseRequest('PATCH','members?id=eq.'+encodeURIComponent(memberId)+'&savings_balance=eq.'+encodeURIComponent(String(bal-amount)),{savings_balance:bal,updated_at:now});throw new Error('Withdrawal transaction failed; balance restored.');}
        } else {
            var mem2=await supabaseRequest('GET','members?select=id,savings_balance,total_savings&id=eq.'+encodeURIComponent(memberId)+'&limit=1');
            if(mem2.statusCode!==200||!mem2.data||!mem2.data.length)throw new Error('Member not found.');
            var bal2=numberValue(mem2.data[0].savings_balance), total2=numberValue(mem2.data[0].total_savings);
            var upd2=await supabaseRequest('PATCH','members?id=eq.'+encodeURIComponent(memberId)+'&savings_balance=eq.'+encodeURIComponent(String(bal2)),{savings_balance:bal2+amount,total_savings:total2+amount,updated_at:now});
            if(upd2.statusCode!==200||!upd2.data||upd2.data.length!==1)throw new Error('Member balance changed during import.');
            tx=await supabaseRequest('POST','transactions',{member_id:memberId,type:'savings',amount:amount,payment_method:'historical_import',description:String(row.notes||'Historical savings imported from records'),status:'completed',created_by:actor.id,created_at:d.toISOString(),updated_at:now});
            if(tx.statusCode!==201){await supabaseRequest('PATCH','members?id=eq.'+encodeURIComponent(memberId)+'&savings_balance=eq.'+encodeURIComponent(String(bal2+amount)),{savings_balance:bal2,total_savings:total2,updated_at:now});throw new Error('Savings transaction failed; balance restored.');}
        }
        return {success:true};
    }
    if(type==='loans'){
        amount=importMoney_(row.amount,'Loan amount'); d=importDate_(row.loan_date,'Loan date',false);
        var rate=numberValue(row.interest_rate); if(rate>1)rate=rate/100; if(rate<0||rate>1)throw new Error('Interest rate must be between 0 and 100%.');
        var period=Number(row.repayment_period); if(!isFinite(period)||period<1)throw new Error('Repayment period must be valid.');
        var total=numberValue(row.total_repayment)||amount*(1+rate),paid=numberValue(row.amount_paid);if(paid<0||paid>total)throw new Error('Amount paid is invalid.');
        var loanRow={member_id:memberId,amount:amount,repayment_period:String(period),interest_rate:rate,total_repayment:total,status:paid>=total-0.001?'completed':'active',application_date:d.toISOString(),approved_date:d.toISOString(),approved_by:actor.id,repayment_due_date:new Date(d.getTime()+period*86400000).toISOString(),amount_paid:paid,is_fully_paid:paid>=total-0.001,created_at:d.toISOString(),updated_at:now};
        if(row.loan_reference)loanRow.reference_no=String(row.loan_reference).trim();
        var ins=await supabaseRequest('POST','loans',loanRow);if(ins.statusCode!==201||!ins.data||!ins.data.length)throw new Error('Historical loan could not be imported.');
        var loan=ins.data[0];
        var txl=await supabaseRequest('POST','transactions',{member_id:memberId,type:'loan_disbursement',amount:amount,payment_method:'historical_import',description:'Historical loan disbursement imported from records',status:'completed',created_by:actor.id,created_at:d.toISOString(),updated_at:now});
        if(txl.statusCode!==201)Logger.log('Historical loan transaction could not be posted for '+loan.id);
        if(paid>0){var rep=await supabaseRequest('POST','loan_repayments',{loan_id:loan.id,member_id:memberId,amount:paid,payment_method:'historical_import',mpesa_code:String(row.reference||'').trim()||null,payment_date:d.toISOString(),created_at:d.toISOString()});if(rep.statusCode!==201)throw new Error('Loan imported but historical repayment could not be posted.');}
        return {success:true};
    }
    if(type==='loan_repayments'){
        amount=importMoney_(row.amount,'Repayment amount'); d=importDate_(row.repayment_date,'Repayment date',false);
        var loan=await findLoanForImport_(row.member_id,row.loan_reference);var totalL=numberValue(loan.total_repayment),paidL=numberValue(loan.amount_paid),remaining=Math.max(0,totalL-paidL);if(amount>remaining)throw new Error('Repayment exceeds remaining loan balance of KES '+remaining.toFixed(2)+'.');
        var newPaid=paidL+amount,complete=newPaid>=totalL-0.001;
        var upL=await supabaseRequest('PATCH','loans?id=eq.'+encodeURIComponent(loan.id)+'&amount_paid=eq.'+encodeURIComponent(String(paidL)),{amount_paid:newPaid,is_fully_paid:complete,status:complete?'completed':'active',updated_at:now});if(upL.statusCode!==200||!upL.data||upL.data.length!==1)throw new Error('Loan balance changed during import.');
        var rep2=await supabaseRequest('POST','loan_repayments',{loan_id:loan.id,member_id:loan.member_id,amount:amount,payment_method:'historical_import',mpesa_code:String(row.reference||'').trim()||null,payment_date:d.toISOString(),created_at:d.toISOString()});if(rep2.statusCode!==201){await supabaseRequest('PATCH','loans?id=eq.'+encodeURIComponent(loan.id)+'&amount_paid=eq.'+encodeURIComponent(String(newPaid)),{amount_paid:paidL,is_fully_paid:false,status:'active',updated_at:now});throw new Error('Repayment could not be imported; loan balance restored.');}
        await supabaseRequest('POST','transactions',{member_id:loan.member_id,type:'loan_repayment',amount:amount,payment_method:'historical_import',mpesa_code:String(row.reference||'').trim()||null,description:String(row.notes||'Historical loan repayment imported from records'),status:'completed',created_by:actor.id,created_at:d.toISOString(),updated_at:now});return {success:true};
    }
    if(type==='finance_entries'){
        var et=String(row.entry_type||'').toLowerCase();if(['income','expense'].indexOf(et)<0)throw new Error('Entry type must be income or expense.');amount=importMoney_(row.amount,'Amount');d=importDate_(row.entry_date,'Entry date',false);var fr=await supabaseRequest('POST','finance_entries',{entry_no:await nextNumberByTable_('finance_entries','FE','entry_no'),entry_type:et,category:String(row.category||'').trim()||'Other',amount:amount,description:String(row.description||'').trim()||'Historical finance entry',payment_method:String(row.payment_method||'').trim()||null,reference_no:String(row.reference_no||'').trim()||null,entry_date:d.toISOString(),status:'completed',created_by:actor.id,approved_by:actor.id,created_at:now,updated_at:now});if(fr.statusCode!==201)throw new Error('Finance entry could not be imported.');return {success:true};
    }
    if(type==='procurement_requests'){
        var item=String(row.item_description||'').trim(),cat=String(row.category||'').trim(),est=importMoney_(row.estimated_amount,'Estimated amount');if(!item||!cat)throw new Error('Item description and category are required.');d=importDate_(row.request_date,'Request date',false);var pr=await supabaseRequest('POST','procurement_requests',{request_no:await nextNumberByTable_('procurement_requests','PR','request_no'),requested_by:actor.id,supplier_name:String(row.supplier_name||'').trim()||null,category:cat,item_description:item,quantity:Number(row.quantity)||1,estimated_amount:est,approved_amount:numberValue(row.approved_amount)||null,status:['submitted','approved','ordered','received','paid','rejected','cancelled'].indexOf(String(row.status||'submitted').toLowerCase())>=0?String(row.status||'submitted').toLowerCase():'submitted',request_date:d.toISOString(),notes:String(row.notes||'').trim()||null,created_at:now,updated_at:now});if(pr.statusCode!==201)throw new Error('Procurement record could not be imported.');return {success:true};
    }
    throw new Error('Unsupported import type.');
}

async function importDataFile(data){
    try{
        var actor=await requirePermission(data&&data.actorId,'data_import',['super_admin'],data&&data.sessionToken);
        var type=String(data&&data.importType||'').trim();
        var allowed=['existing_members','savings','withdrawals','loans','loan_repayments','finance_entries','procurement_requests'];if(allowed.indexOf(type)<0)throw new Error('Select a valid data type.');
        var rows=parseCsvImport_(data&&data.csvText||'');if(rows.length>2000)throw new Error('Import is limited to 2,000 rows per file. Split larger files into batches.');
        var errors=[],success=0;
        for (const row of rows) { try { await importOneRow_(type,row,actor,data&&data.sessionToken); success++; } catch(e) { errors.push({row:row.__row,message:e.message}); } }
        await writeAuditLog('BULK_DATA_IMPORT',actor.id,'data_import',null,{}, {type:type,rows:rows.length,success:success,errors:errors.length},{errors:errors.slice(0,50)});
        return {success:errors.length===0,message:errors.length?'Import completed with '+success+' successful row(s) and '+errors.length+' failed row(s).':'Import completed successfully. '+success+' row(s) imported.',importType:type,totalRows:rows.length,successCount:success,errorCount:errors.length,errors:errors.slice(0,100)};
    }catch(e){return {success:false,message:e.message,totalRows:0,successCount:0,errorCount:0,errors:[]};}
}

async function nextNumberByTable_(table, prefix, column) {
    var result = await supabaseRequest('GET', table + '?select=' + encodeURIComponent(column) + '&order=' + encodeURIComponent(column) + '.desc&limit=1');
    var maxNo = 0;
    if (result.statusCode === 200 && Array.isArray(result.data) && result.data.length) {
        var match = String(result.data[0][column] || '').match(/(\d+)$/);
        if (match) maxNo = Number(match[1]);
    }
    return String(prefix) + String(maxNo + 1).padStart(5, '0');
}

async function getProcurementAndFinance(data) {
    try {
        var actor = await getActor(data && data.actorId, data && data.sessionToken);
        var canProcurement = actor.role === 'super_admin' || actor.permissions.procurement_view === true;
        var canFinance = actor.role === 'super_admin' || actor.permissions.finance_view === true;
        if (!canProcurement && !canFinance) throw new Error('You do not have permission to view procurement and finance records.');
        var procurement = [], finance = [];
        if (canProcurement) {
            var pr = await supabaseRequest('GET','procurement_requests?select=*&order=request_date.desc&limit=1000');
            if (pr.statusCode !== 200) throw new Error('Unable to load procurement records.');
            procurement = pr.data || [];
        }
        if (canFinance) {
            var fe = await supabaseRequest('GET','finance_entries?select=*&order=entry_date.desc&limit=1000');
            if (fe.statusCode !== 200) throw new Error('Unable to load finance records.');
            finance = fe.data || [];
        }
        var income = finance.filter(function(x){return x.entry_type === 'income' && x.status === 'completed';}).reduce(function(a,x){return a+numberValue(x.amount);},0);
        var expense = finance.filter(function(x){return x.entry_type === 'expense' && x.status === 'completed';}).reduce(function(a,x){return a+numberValue(x.amount);},0);
        var committed = procurement.filter(function(x){return ['approved','ordered','received','paid'].indexOf(x.status)>=0;}).reduce(function(a,x){return a+numberValue(x.approved_amount || x.estimated_amount);},0);
        return {success:true,procurement:procurement,finance:finance,summary:{income:income,expense:expense,net:income-expense,procurementCommitted:committed}};
    } catch(e){return {success:false,message:e.message,procurement:[],finance:[]};}
}

async function createProcurementRequest(data) {
    try {
        var actor = await requirePermission(data && data.actorId,'procurement_manage',['super_admin'],data && data.sessionToken);
        var item=String(data.itemDescription||'').trim(), category=String(data.category||'').trim(), supplier=String(data.supplierName||'').trim();
        var qty=numberValue(data.quantity)||1, amount=numberValue(data.estimatedAmount);
        if(!item||!category||amount<=0) throw new Error('Item/service, category and estimated amount are required.');
        var dateText=String(data.requestDate||'').trim(), d=new Date((dateText||new Date().toISOString().slice(0,10))+'T00:00:00'); if(isNaN(d.getTime())) throw new Error('Enter a valid request date.');
        var now=new Date().toISOString();
        var row={request_no:await nextNumberByTable_('procurement_requests','PR','request_no'),requested_by:actor.id,supplier_name:supplier||null,category:category,item_description:item,quantity:qty,estimated_amount:amount,approved_amount:null,status:'submitted',request_date:d.toISOString(),notes:String(data.notes||'').trim()||null,created_at:now,updated_at:now};
        var r=await supabaseRequest('POST','procurement_requests',row); if(r.statusCode!==201) throw new Error('Procurement request could not be saved.');
        await writeAuditLog('CREATE_PROCUREMENT_REQUEST',actor.id,'procurement',r.data&&r.data[0]?r.data[0].id:null,{},row,{});
        return {success:true,message:'Procurement request submitted successfully.',request:r.data&&r.data[0]?r.data[0]:null};
    }catch(e){return {success:false,message:e.message};}
}

async function updateProcurementStatus(data) {
    try {
        var actor=await requirePermission(data&&data.actorId,'procurement_manage',['super_admin'],data&&data.sessionToken);
        var id=String(data.procurementId||'').trim(), status=String(data.status||'').trim();
        var allowed=['submitted','approved','ordered','received','paid','rejected','cancelled'];
        if(!id||allowed.indexOf(status)<0) throw new Error('Invalid procurement status.');
        var existing=await supabaseRequest('GET','procurement_requests?select=*&id=eq.'+encodeURIComponent(id)+'&limit=1'); if(existing.statusCode!==200||!existing.data||!existing.data.length) throw new Error('Procurement request not found.');
        var x=existing.data[0], payload={status:status,updated_at:new Date().toISOString()};
        if(status==='approved'){payload.approved_amount=numberValue(data.approvedAmount)||numberValue(x.estimated_amount);payload.approved_date=new Date().toISOString();}
        if(status==='received'){payload.received_date=new Date().toISOString();}
        if(status==='paid'){payload.paid_date=new Date().toISOString();payload.receipt_no=String(data.referenceNo||x.receipt_no||'').trim()||null;}
        var r=await supabaseRequest('PATCH','procurement_requests?id=eq.'+encodeURIComponent(id)+'&status=eq.'+encodeURIComponent(String(x.status)),payload); if(r.statusCode!==200||!r.data||r.data.length!==1) throw new Error('Procurement status changed while you were editing it. Refresh and try again.');
        if(status==='paid'){
            var duplicate=await supabaseRequest('GET','finance_entries?select=id&procurement_id=eq.'+encodeURIComponent(id)+'&entry_type=eq.expense&limit=1');
            if(duplicate.statusCode===200&&duplicate.data&&duplicate.data.length===0){
                var amount=numberValue(payload.approved_amount||x.approved_amount||x.estimated_amount);
                var fe=await supabaseRequest('POST','finance_entries',{entry_no:await nextNumberByTable_('finance_entries','FE','entry_no'),entry_type:'expense',category:'Procurement - '+x.category,amount:amount,description:'Payment for '+x.item_description,payment_method:String(data.paymentMethod||'').trim()||'other',reference_no:String(data.referenceNo||x.receipt_no||'').trim()||null,procurement_id:id,entry_date:new Date().toISOString(),status:'completed',created_by:actor.id,approved_by:actor.id,created_at:new Date().toISOString(),updated_at:new Date().toISOString()});
                if(fe.statusCode!==201) throw new Error('Procurement was marked paid but the finance expense could not be posted. Review before continuing.');
            }
        }
        await writeAuditLog('UPDATE_PROCUREMENT_STATUS',actor.id,'procurement',id,{status:x.status},payload,{});
        return {success:true,message:'Procurement updated to '+status+'.'};
    }catch(e){return {success:false,message:e.message};}
}

async function createFinanceEntry(data) {
    try {
        var actor=await requirePermission(data&&data.actorId,'finance_manage',['super_admin'],data&&data.sessionToken);
        var type=String(data.entryType||'').trim(), category=String(data.category||'').trim(), description=String(data.description||'').trim(), amount=numberValue(data.amount);
        if(['income','expense'].indexOf(type)<0) throw new Error('Finance entry type must be income or expense.');
        if(!category||!description||amount<=0) throw new Error('Category, description and amount are required.');
        var dateText=String(data.entryDate||'').trim(), d=new Date((dateText||new Date().toISOString().slice(0,10))+'T00:00:00'); if(isNaN(d.getTime())) throw new Error('Enter a valid finance entry date.');
        var row={entry_no:await nextNumberByTable_('finance_entries','FE','entry_no'),entry_type:type,category:category,amount:amount,description:description,payment_method:String(data.paymentMethod||'').trim()||null,reference_no:String(data.referenceNo||'').trim()||null,procurement_id:data.procurementId||null,entry_date:d.toISOString(),status:'completed',created_by:actor.id,approved_by:actor.id,created_at:new Date().toISOString(),updated_at:new Date().toISOString()};
        var r=await supabaseRequest('POST','finance_entries',row); if(r.statusCode!==201) throw new Error('Finance entry could not be saved.');
        await writeAuditLog('CREATE_FINANCE_ENTRY',actor.id,'finance_entry',r.data&&r.data[0]?r.data[0].id:null,{},row,{});
        return {success:true,message:'Finance entry posted successfully.',entry:r.data&&r.data[0]?r.data[0]:null};
    }catch(e){return {success:false,message:e.message};}
}

async function getLoanById(data) {
    try {
        const endpoint = 'loans?select=*&id=eq.' + encodeURIComponent(data.loanId);
        const result = await supabaseRequest('GET', endpoint);
        
        if (result.statusCode !== 200 || !result.data || result.data.length === 0) {
            return { success: false, message: 'Loan not found' };
        }
        
        return { success: true, loan: result.data[0] };
    } catch (error) {
        return { success: false, message: error.message };
    }
}

async function getAllMemberTransactions(data) {
    try {
        const memberId = data.memberId;
        const limit = data.limit || 100;
        
        const endpoint = 'transactions?select=*&member_id=eq.' + 
                        encodeURIComponent(memberId) + 
                        '&order=created_at.desc&limit=' + limit;
        const result = await supabaseRequest('GET', endpoint);
        
        if (result.statusCode !== 200) {
            return { success: false, transactions: [], error: 'Failed to fetch transactions' };
        }
        
        return { success: true, transactions: result.data || [] };
    } catch (error) {
        Logger.log('Error in getAllMemberTransactions: ' + error.message);
        return { success: false, transactions: [], error: error.message };
    }
}

async function sendDailySummary() {
    try {
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        const tomorrow = new Date(today);
        tomorrow.setDate(tomorrow.getDate() + 1);
        
        const transEndpoint = 'transactions?select=*&created_at=gte.' + 
                             today.toISOString() + '&created_at=lt.' + tomorrow.toISOString();
        const transResult = await supabaseRequest('GET', transEndpoint);
        const transactions = transResult.statusCode === 200 ? transResult.data : [];
        
        let totalSavings = 0, totalRepayments = 0, totalRegistrations = 0;
        transactions.forEach(t => {
            if (t.type === 'savings') totalSavings += numberValue(t.amount);
            if (t.type === 'loan_repayment') totalRepayments += numberValue(t.amount);
            if (t.type === 'registration') totalRegistrations += numberValue(t.amount);
        });
        
        const membersEndpoint = 'members?select=*&created_at=gte.' + 
                               today.toISOString() + '&created_at=lt.' + tomorrow.toISOString();
        const membersResult = await supabaseRequest('GET', membersEndpoint);
        const newMembers = membersResult.statusCode === 200 ? membersResult.data : [];
        
        const pendingRegResult = await supabaseRequest('GET', 'members?select=count&is_active=eq.false&registration_fee_status=eq.pending');
        const pendingRegistrations = pendingRegResult.statusCode === 200 && pendingRegResult.data ? pendingRegResult.data[0]?.count || 0 : 0;
        
        const pendingTransResult = await supabaseRequest('GET', 'transactions?select=count&status=eq.pending');
        const pendingTransactions = pendingTransResult.statusCode === 200 && pendingTransResult.data ? pendingTransResult.data[0]?.count || 0 : 0;
        
        const pendingWResult = await supabaseRequest('GET', 'withdrawal_requests?select=count&status=eq.pending');
        const pendingWithdrawals = pendingWResult.statusCode === 200 && pendingWResult.data ? pendingWResult.data[0]?.count || 0 : 0;
        
        const pendingLoansResult = await supabaseRequest('GET', 'loans?select=count&status=eq.pending');
        const pendingLoans = pendingLoansResult.statusCode === 200 && pendingLoansResult.data ? pendingLoansResult.data[0]?.count || 0 : 0;
        
        const pendingProfileEditsResult = await supabaseRequest('GET', 'biodata_approvals?select=count&status=eq.pending&request_type=eq.profile_edit');
        const pendingProfileEdits = pendingProfileEditsResult.statusCode === 200 && pendingProfileEditsResult.data ? pendingProfileEditsResult.data[0]?.count || 0 : 0;
        
        let message = '📊 DAILY SUMMARY - ' + new Date().toLocaleDateString() + '\n\n';
        message += '💰 Savings: KES ' + totalSavings + '\n';
        message += '💳 Repayments: KES ' + totalRepayments + '\n';
        message += '👤 New Members: ' + (newMembers ? newMembers.length : 0) + '\n';
        message += '📝 Pending Registrations: ' + pendingRegistrations + '\n';
        message += '📝 Pending Transactions: ' + pendingTransactions + '\n';
        message += '📝 Pending Withdrawals: ' + pendingWithdrawals + '\n';
        message += '📝 Pending Loans: ' + pendingLoans + '\n';
        message += '📝 Pending Profile Edits: ' + pendingProfileEdits + '\n';
        
        const adminsResult = await supabaseRequest('GET', 'members?select=phone_number&role=in.(admin,super_admin)&is_active=eq.true');
        if (adminsResult.statusCode === 200 && adminsResult.data) {
            adminsResult.data.forEach(admin => {
                sendWhatsAppAlert(admin.phone_number, message);
            });
        }
        
        return { success: true, message: 'Summary sent' };
    } catch (error) {
        return { success: false, message: error.message };
    }
}

async function createAdminUser() {
    try {
        const checkResult = await supabaseRequest('GET', 'members?select=*&id_number=eq.SUPERADMIN001');
        
        const superAdminHash = 'bfcad60d018539a34637637a1d62f9517e7959f551ed6cf4b080ec94ab219183';
        const adminHash = 'a36aef5a11c4073fbe60314fc9df530a9d5f986533594d1f5190742ff9e0e408';
        
        if (checkResult.statusCode === 200 && checkResult.data && checkResult.data.length > 0) {
            Logger.log('Super admin already exists - updating password');
            
            const updateSuper = await supabaseRequest('PATCH', 'members?id_number=eq.SUPERADMIN001', {
                password: superAdminHash,
                updated_at: new Date().toISOString()
            });
            Logger.log('Super admin updated: ' + JSON.stringify(updateSuper));
            
            const updateAdmin = await supabaseRequest('PATCH', 'members?id_number=eq.ADMIN001', {
                password: adminHash,
                updated_at: new Date().toISOString()
            });
            Logger.log('Admin updated: ' + JSON.stringify(updateAdmin));
            
            return { 
                success: true, 
                message: 'Admin passwords updated successfully!',
                superAdmin: { id_number: 'SUPERADMIN001', password: 'mOrisky07.super' },
                admin: { id_number: 'ADMIN001', password: 'Admin@2026' }
            };
        }
        
        const superAdminData = {
            unique_member_id: 'SUPER-ADMIN-001',
            full_name: 'Super Administrator',
            id_number: 'SUPERADMIN001',
            phone_number: CONFIG.ADMIN_WHATSAPP || '+254111640106',
            email: 'superadmin@brightlife.co.ke',
            password: superAdminHash,
            role: 'super_admin',
            registration_fee_paid: true,
            registration_fee_status: 'approved',
            is_active: true,
            biodata_completed: true,
            biodata_locked: true,
            savings_balance: 0,
            profile_edit_status: 'approved',
            loan_limit: 500000,
            loan_growth_tier: 'platinum',
            loan_growth_score: 100,
            permissions: {
                view_members: true,
                loan_approval: true,
                savings_approval: true,
                withdrawal_approval: true,
                registration_approval: true,
                grant_rights: true,
                customer_care: true,
                view_reports: true,
                profile_approval: true,
                view_savings: true,
                edit_members: true,
                view_repayments: true,
                view_transactions: true
            },
            registration_date: new Date().toISOString(),
            created_at: new Date().toISOString()
        };
        
        const superResult = await supabaseRequest('POST', 'members', superAdminData);
        
        if (superResult.statusCode !== 201) {
            throw new Error('Failed to create super admin');
        }
        
        const superIdResult = await supabaseRequest('GET', 'members?select=id&id_number=eq.SUPERADMIN001');
        const superId = superIdResult.statusCode === 200 && superIdResult.data && superIdResult.data.length > 0 ? 
                       superIdResult.data[0].id : null;
        
        const adminData = {
            unique_member_id: 'ADMIN-001',
            full_name: 'System Administrator',
            id_number: 'ADMIN001',
            phone_number: CONFIG.ADMIN_WHATSAPP || '+254111640106',
            email: 'admin@brightlife.co.ke',
            password: adminHash,
            role: 'admin',
            registration_fee_paid: true,
            registration_fee_status: 'approved',
            is_active: true,
            biodata_completed: true,
            biodata_locked: true,
            savings_balance: 0,
            profile_edit_status: 'approved',
            loan_limit: 500000,
            loan_growth_tier: 'platinum',
            loan_growth_score: 100,
            permissions: {
                view_members: true,
                loan_approval: true,
                savings_approval: true,
                withdrawal_approval: true,
                registration_approval: true,
                grant_rights: false,
                customer_care: true,
                view_reports: true,
                profile_approval: true,
                view_savings: true,
                edit_members: true,
                view_repayments: true,
                view_transactions: true
            },
            created_by: superId,
            registration_date: new Date().toISOString(),
            created_at: new Date().toISOString()
        };
        
        const adminResult = await supabaseRequest('POST', 'members', adminData);
        Logger.log('Admin creation result: ' + JSON.stringify(adminResult));
        
        return { 
            success: true, 
            message: 'Super admin and admin created successfully!',
            superAdmin: { id_number: 'SUPERADMIN001', password: 'mOrisky07.super' },
            admin: { id_number: 'ADMIN001', password: 'Admin@2026' }
        };
    } catch (error) {
        Logger.log('Error creating admin: ' + error.message);
        return { success: false, message: error.message };
    }
}

async function testMemberStatus(memberId) {
    try {
        const result = await supabaseRequest('GET', 'members?select=id,full_name,is_active,registration_fee_status,savings_balance,profile_edit_status,loan_limit,loan_growth_tier&id=eq.' + encodeURIComponent(memberId));
        Logger.log('Member status: ' + JSON.stringify(result.data));
        return result.data;
    } catch (error) {
        Logger.log('Error: ' + error.message);
        return null;
    }
}

function generateSummaryTable(title, subtitle, data) {
    var html = '';
    html += '<html>';
    html += '<head>';
    html += '<style>';
    html += 'body { font-family: Arial, Helvetica, sans-serif; background-color: #f4f7fc; padding: 0; margin: 0; }';
    html += '.container { max-width: 550px; margin: 0 auto; background: white; border-radius: 12px; padding: 25px 20px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }';
    html += '.header { border-bottom: 3px solid #6C3CE1; padding-bottom: 12px; margin-bottom: 15px; text-align: center; }';
    html += '.header h1 { color: #1F2937; font-size: 20px; margin: 0; font-weight: 700; }';
    html += '.header .sub { color: #6B7280; font-size: 12px; margin-top: 3px; }';
    html += '.title { font-size: 16px; font-weight: 700; color: #1F2937; text-align: center; margin: 0 0 12px 0; }';
    html += 'table { width: 100%; border-collapse: collapse; margin: 0; border: 2px solid #6C3CE1; }';
    html += 'th { background-color: #6C3CE1; color: white; padding: 8px 12px; text-align: left; font-size: 12px; border: 1px solid #6C3CE1; font-weight: 600; }';
    html += 'td { padding: 7px 12px; border: 1px solid #D1D5DB; font-size: 12px; color: #1F2937; }';
    html += 'tr:nth-child(even) td { background-color: #F9FAFB; }';
    html += '.footer { margin-top: 15px; padding-top: 12px; border-top: 1px solid #E5E7EB; font-size: 10px; color: #9CA3AF; text-align: center; }';
    html += '.highlight { font-weight: 700; color: #6C3CE1; }';
    html += '.success { color: #10B981; }';
    html += '.warning { color: #F59E0B; }';
    html += '.danger { color: #EF4444; }';
    html += '.label { font-weight: 500; }';
    html += '.value { font-weight: 600; }';
    html += '</style>';
    html += '</head>';
    html += '<body>';
    html += '<div class="container">';
    html += '<div class="header">';
    html += '<h1>🏦 SND BRIGHTLIFE CBO</h1>';
    html += '<div class="sub">Savings & Loans Platform</div>';
    if (subtitle) {
        html += '<div class="sub" style="font-size: 11px; color: #9CA3AF; margin-top: 2px;">' + subtitle + '</div>';
    }
    html += '</div>';
    if (title) {
        html += '<div class="title">' + title + '</div>';
    }
    if (data && data.length > 0) {
        html += '<table>';
        html += '<thead><tr>';
        html += '<th style="width: 55%;">Metric</th>';
        html += '<th style="width: 45%;">Value</th>';
        html += '</tr></thead>';
        html += '<tbody>';
        for (var i = 0; i < data.length; i++) {
            var row = data[i];
            html += '<tr>';
            html += '<td class="label">' + row.label + '</td>';
            html += '<td class="value">' + row.value + '</td>';
            html += '</tr>';
        }
        html += '</tbody></table>';
    }
    html += '<div class="footer">';
    html += 'Brightlife CBO — Savings & Loans Platform<br>';
    html += 'This is an automated notification. Please do not reply to this email.';
    html += '</div>';
    html += '</div>';
    html += '</body>';
    html += '</html>';
    return html;
}

async function sendDailySummaryEmail() {
    try {
        var today = new Date();
        var dateStr = today.toLocaleDateString('en-US', { 
            month: 'numeric', 
            day: 'numeric', 
            year: 'numeric' 
        });
        var timeStr = today.toLocaleTimeString('en-US', { 
            hour: '2-digit', 
            minute: '2-digit', 
            second: '2-digit',
            hour12: true 
        });
        
        var todayStart = new Date(today);
        todayStart.setHours(0, 0, 0, 0);
        var todayEnd = new Date(today);
        todayEnd.setHours(23, 59, 59, 999);
        
        var membersResult = await supabaseRequest('GET', 'members?select=*');
        var allMembers = membersResult.statusCode === 200 ? membersResult.data : [];
        var totalMembers = allMembers.length || 0;
        
        var activeMembers = 0;
        var pendingRegistrations = 0;
        for (var i = 0; i < allMembers.length; i++) {
            if (allMembers[i].is_active) activeMembers++;
            if (!allMembers[i].is_active && allMembers[i].registration_fee_status === 'pending') pendingRegistrations++;
        }
        
        var transResult = await supabaseRequest('GET', 
            'transactions?select=*&created_at=gte.' + todayStart.toISOString() + '&created_at=lte.' + todayEnd.toISOString()
        );
        var transactions = transResult.statusCode === 200 ? transResult.data : [];
        
        var newMembersResult = await supabaseRequest('GET', 
            'members?select=*&created_at=gte.' + todayStart.toISOString() + '&created_at=lte.' + todayEnd.toISOString()
        );
        var newMembers = newMembersResult.statusCode === 200 ? newMembersResult.data : [];
        
        var totalSavings = 0;
        var loanRepayments = 0;
        for (var t = 0; t < transactions.length; t++) {
            var trans = transactions[t];
            if ((trans.type === 'savings' || trans.type === 'registration') && trans.status === 'completed') {
                totalSavings += numberValue(trans.amount);
            }
            if (trans.type === 'loan_repayment' && trans.status === 'completed') {
                loanRepayments += numberValue(trans.amount);
            }
        }
        
        var pendingTransResult = await supabaseRequest('GET', 'transactions?select=count&status=eq.pending');
        var pendingTransactions = 0;
        if (pendingTransResult.statusCode === 200 && pendingTransResult.data && pendingTransResult.data[0]) {
            pendingTransactions = pendingTransResult.data[0].count || 0;
        }
        
        var pendingLoansResult = await supabaseRequest('GET', 'loans?select=count&status=eq.pending');
        var pendingLoans = 0;
        if (pendingLoansResult.statusCode === 200 && pendingLoansResult.data && pendingLoansResult.data[0]) {
            pendingLoans = pendingLoansResult.data[0].count || 0;
        }
        
        var pendingWResult = await supabaseRequest('GET', 'withdrawal_requests?select=count&status=eq.pending');
        var pendingWithdrawals = 0;
        if (pendingWResult.statusCode === 200 && pendingWResult.data && pendingWResult.data[0]) {
            pendingWithdrawals = pendingWResult.data[0].count || 0;
        }
        
        var pendingEditsResult = await supabaseRequest('GET', 'biodata_approvals?select=count&status=eq.pending&request_type=eq.profile_edit');
        var pendingProfileEdits = 0;
        if (pendingEditsResult.statusCode === 200 && pendingEditsResult.data && pendingEditsResult.data[0]) {
            pendingProfileEdits = pendingEditsResult.data[0].count || 0;
        }
        
        var tableData = [
            { label: '📅 Date', value: dateStr + ' at ' + timeStr },
            { label: '🏢 Total Savings', value: 'KES ' + totalSavings.toFixed(2) },
            { label: '💳 Loan Repayments', value: 'KES ' + loanRepayments.toFixed(2) },
            { label: '🔵 New Members', value: newMembers.length },
            { label: '🔴 Pending Registrations', value: pendingRegistrations },
            { label: '🔴 Pending Transactions', value: pendingTransactions },
            { label: '🔴 Pending Withdrawals', value: pendingWithdrawals },
            { label: '🔴 Pending Loans', value: pendingLoans },
            { label: '🔴 Pending Profile Edits', value: pendingProfileEdits },
            { label: '⚙️ Total Members', value: totalMembers },
            { label: '🔔 Active Members', value: activeMembers }
        ];
        
        var subject = '📊 Daily Summary - ' + dateStr;
        var htmlBody = generateSummaryTable('DAILY SUMMARY', dateStr + ' at ' + timeStr, tableData);
        
        var adminsResult = await supabaseRequest('GET', 'members?select=email&role=in.(admin,super_admin)&is_active=eq.true&email=not.is.null');
        var adminEmails = [];
        if (adminsResult.statusCode === 200 && adminsResult.data) {
            for (var a = 0; a < adminsResult.data.length; a++) {
                if (adminsResult.data[a].email) {
                    adminEmails.push(adminsResult.data[a].email);
                }
            }
        }
        
        if (adminEmails.length > 0) {
            for (var e = 0; e < adminEmails.length; e++) {
                await sendEmailNotification(adminEmails[e], subject, htmlBody);
            }
        } else {
            await sendEmailNotification('morisky2001@gmail.com', subject, htmlBody);
        }
        
        Logger.log('Daily summary email sent');
        return { success: true, message: 'Daily summary sent' };
        
    } catch (error) {
        Logger.log('Error sending daily summary: ' + error.message);
        return { success: false, message: error.message };
    }
}

async function sendWeeklySummaryEmail() {
    try {
        var today = new Date();
        var weekStart = new Date(today);
        weekStart.setDate(weekStart.getDate() - 7);
        
        var dateRange = weekStart.toLocaleDateString('en-US', { 
            month: 'short', 
            day: 'numeric' 
        }) + ' - ' + today.toLocaleDateString('en-US', { 
            month: 'short', 
            day: 'numeric', 
            year: 'numeric' 
        });
        
        var transResult = await supabaseRequest('GET', 
            'transactions?select=*&created_at=gte.' + weekStart.toISOString()
        );
        var transactions = transResult.statusCode === 200 ? transResult.data : [];
        
        var newMembersResult = await supabaseRequest('GET', 
            'members?select=*&created_at=gte.' + weekStart.toISOString()
        );
        var newMembers = newMembersResult.statusCode === 200 ? newMembersResult.data : [];
        
        var loansResult = await supabaseRequest('GET', 
            'loans?select=*&application_date=gte.' + weekStart.toISOString()
        );
        var newLoans = loansResult.statusCode === 200 ? loansResult.data : [];
        
        var totalSavings = 0;
        var loanRepayments = 0;
        for (var t = 0; t < transactions.length; t++) {
            var trans = transactions[t];
            if ((trans.type === 'savings' || trans.type === 'registration') && trans.status === 'completed') {
                totalSavings += numberValue(trans.amount);
            }
            if (trans.type === 'loan_repayment' && trans.status === 'completed') {
                loanRepayments += numberValue(trans.amount);
            }
        }
        
        var membersResult = await supabaseRequest('GET', 'members?select=count');
        var totalMembers = 0;
        if (membersResult.statusCode === 200 && membersResult.data && membersResult.data[0]) {
            totalMembers = membersResult.data[0].count || 0;
        }
        
        var tableData = [
            { label: '📅 Period', value: dateRange },
            { label: '🏢 Total Savings', value: 'KES ' + totalSavings.toFixed(2) },
            { label: '💳 Loan Repayments', value: 'KES ' + loanRepayments.toFixed(2) },
            { label: '🔵 New Members', value: newMembers.length },
            { label: '📝 New Loans', value: newLoans.length },
            { label: '⚙️ Total Members', value: totalMembers }
        ];
        
        var subject = '📊 Weekly Summary - ' + dateRange;
        var htmlBody = generateSummaryTable('WEEKLY SUMMARY', dateRange, tableData);
        
        var allMembersResult = await supabaseRequest('GET', 'members?select=email&is_active=eq.true&email=not.is.null');
        var memberEmails = [];
        if (allMembersResult.statusCode === 200 && allMembersResult.data) {
            for (var m = 0; m < allMembersResult.data.length; m++) {
                if (allMembersResult.data[m].email) {
                    memberEmails.push(allMembersResult.data[m].email);
                }
            }
        }
        
        if (memberEmails.length > 0) {
            for (var e = 0; e < memberEmails.length; e++) {
                await sendEmailNotification(memberEmails[e], subject, htmlBody);
            }
        } else {
            await sendEmailNotification('morisky2001@gmail.com', subject, htmlBody);
        }
        
        Logger.log('Weekly summary email sent');
        return { success: true, message: 'Weekly summary sent' };
        
    } catch (error) {
        Logger.log('Error sending weekly summary: ' + error.message);
        return { success: false, message: error.message };
    }
}

async function sendMonthlySummaryEmail() {
    try {
        var today = new Date();
        var monthStart = new Date(today.getFullYear(), today.getMonth(), 1);
        var monthName = today.toLocaleString('default', { month: 'long', year: 'numeric' });
        
        var transResult = await supabaseRequest('GET', 
            'transactions?select=*&created_at=gte.' + monthStart.toISOString()
        );
        var transactions = transResult.statusCode === 200 ? transResult.data : [];
        
        var newMembersResult = await supabaseRequest('GET', 
            'members?select=*&created_at=gte.' + monthStart.toISOString()
        );
        var newMembers = newMembersResult.statusCode === 200 ? newMembersResult.data : [];
        
        var loansResult = await supabaseRequest('GET', 
            'loans?select=*&application_date=gte.' + monthStart.toISOString()
        );
        var newLoans = loansResult.statusCode === 200 ? loansResult.data : [];
        
        var totalSavings = 0;
        var loanRepayments = 0;
        var totalWithdrawals = 0;
        for (var t = 0; t < transactions.length; t++) {
            var trans = transactions[t];
            if ((trans.type === 'savings' || trans.type === 'registration') && trans.status === 'completed') {
                totalSavings += numberValue(trans.amount);
            }
            if (trans.type === 'loan_repayment' && trans.status === 'completed') {
                loanRepayments += numberValue(trans.amount);
            }
            if (trans.type === 'withdrawal' && trans.status === 'completed') {
                totalWithdrawals += numberValue(trans.amount);
            }
        }
        
        var membersResult = await supabaseRequest('GET', 'members?select=count');
        var totalMembers = 0;
        if (membersResult.statusCode === 200 && membersResult.data && membersResult.data[0]) {
            totalMembers = membersResult.data[0].count || 0;
        }
        
        var activeResult = await supabaseRequest('GET', 'members?select=count&is_active=eq.true');
        var activeMembers = 0;
        if (activeResult.statusCode === 200 && activeResult.data && activeResult.data[0]) {
            activeMembers = activeResult.data[0].count || 0;
        }
        
        var tableData = [
            { label: '📅 Month', value: monthName },
            { label: '🏢 Total Savings', value: 'KES ' + totalSavings.toFixed(2) },
            { label: '💳 Loan Repayments', value: 'KES ' + loanRepayments.toFixed(2) },
            { label: '🏦 Withdrawals', value: 'KES ' + totalWithdrawals.toFixed(2) },
            { label: '🔵 New Members', value: newMembers.length },
            { label: '📝 New Loans', value: newLoans.length },
            { label: '⚙️ Total Members', value: totalMembers },
            { label: '🔔 Active Members', value: activeMembers }
        ];
        
        var subject = '📊 Monthly Summary - ' + monthName;
        var htmlBody = generateSummaryTable('MONTHLY SUMMARY', monthName, tableData);
        
        var allMembersResult = await supabaseRequest('GET', 'members?select=email&is_active=eq.true&email=not.is.null');
        var memberEmails = [];
        if (allMembersResult.statusCode === 200 && allMembersResult.data) {
            for (var m = 0; m < allMembersResult.data.length; m++) {
                if (allMembersResult.data[m].email) {
                    memberEmails.push(allMembersResult.data[m].email);
                }
            }
        }
        
        if (memberEmails.length > 0) {
            for (var e = 0; e < memberEmails.length; e++) {
                await sendEmailNotification(memberEmails[e], subject, htmlBody);
            }
        } else {
            await sendEmailNotification('morisky2001@gmail.com', subject, htmlBody);
        }
        
        Logger.log('Monthly summary email sent');
        return { success: true, message: 'Monthly summary sent' };
        
    } catch (error) {
        Logger.log('Error sending monthly summary: ' + error.message);
        return { success: false, message: error.message };
    }
}

async function sendOverdueLoansAlert() {
    try {
        var today = new Date();
        
        var loansResult = await supabaseRequest('GET', 
            'loans?select=*,members(full_name,unique_member_id,phone_number,email)&status=eq.active&repayment_due_date=lt.' + today.toISOString()
        );
        var overdueLoans = loansResult.statusCode === 200 ? loansResult.data : [];
        
        if (overdueLoans.length === 0) {
            Logger.log('No overdue loans found');
            return { success: true, message: 'No overdue loans' };
        }
        
        var subject = '⚠️ Overdue Loans Alert - ' + overdueLoans.length + ' loans overdue';
        
        var tableData = [];
        for (var l = 0; l < overdueLoans.length; l++) {
            var loan = overdueLoans[l];
            var member = loan.members || {};
            var dueDate = new Date(loan.repayment_due_date);
            var daysOverdue = Math.floor((today - dueDate) / (1000 * 60 * 60 * 24));
            tableData.push({
                label: member.full_name || 'Unknown Member',
                value: 'KES ' + (loan.amount || 0).toFixed(2) + ' | ' + daysOverdue + ' days overdue'
            });
        }
        
        var htmlBody = generateSummaryTable('🚨 OVERDUE LOANS', new Date().toLocaleDateString(), tableData);
        
        var adminsResult = await supabaseRequest('GET', 'members?select=email&role=in.(admin,super_admin)&is_active=eq.true&email=not.is.null');
        var adminEmails = [];
        if (adminsResult.statusCode === 200 && adminsResult.data) {
            for (var a = 0; a < adminsResult.data.length; a++) {
                if (adminsResult.data[a].email) {
                    adminEmails.push(adminsResult.data[a].email);
                }
            }
        }
        
        for (var e = 0; e < adminEmails.length; e++) {
            await sendEmailNotification(adminEmails[e], subject, htmlBody);
        }
        
        for (var lo = 0; lo < overdueLoans.length; lo++) {
            var loan = overdueLoans[lo];
            var member = loan.members || {};
            if (member.email) {
                var dueDate = new Date(loan.repayment_due_date);
                var daysOverdue = Math.floor((today - dueDate) / (1000 * 60 * 60 * 24));
                var borrowerTableData = [
                    { label: '📅 Due Date', value: dueDate.toLocaleDateString() },
                    { label: '⏰ Days Overdue', value: daysOverdue + ' days' },
                    { label: '💰 Amount', value: 'KES ' + (loan.amount || 0).toFixed(2) }
                ];
                var borrowerHtml = generateSummaryTable('⚠️ LOAN OVERDUE NOTICE', 'Dear ' + member.full_name, borrowerTableData);
                await sendEmailNotification(member.email, '⚠️ Your Loan is Overdue', borrowerHtml);
            }
        }
        
        Logger.log('Overdue loans alert sent');
        return { success: true, message: 'Overdue loans alert sent' };
        
    } catch (error) {
        Logger.log('Error sending overdue loans alert: ' + error.message);
        return { success: false, message: error.message };
    }
}

async function sendPendingApprovalsReminder() {
    try {
        var pendingRegResult = await supabaseRequest('GET', 'members?select=count&is_active=eq.false&registration_fee_status=eq.pending');
        var pendingRegistrations = 0;
        if (pendingRegResult.statusCode === 200 && pendingRegResult.data && pendingRegResult.data[0]) {
            pendingRegistrations = pendingRegResult.data[0].count || 0;
        }
        
        var pendingTransResult = await supabaseRequest('GET', 'transactions?select=count&status=eq.pending');
        var pendingTransactions = 0;
        if (pendingTransResult.statusCode === 200 && pendingTransResult.data && pendingTransResult.data[0]) {
            pendingTransactions = pendingTransResult.data[0].count || 0;
        }
        
        var pendingLoansResult = await supabaseRequest('GET', 'loans?select=count&status=eq.pending');
        var pendingLoans = 0;
        if (pendingLoansResult.statusCode === 200 && pendingLoansResult.data && pendingLoansResult.data[0]) {
            pendingLoans = pendingLoansResult.data[0].count || 0;
        }
        
        var pendingWResult = await supabaseRequest('GET', 'withdrawal_requests?select=count&status=eq.pending');
        var pendingWithdrawals = 0;
        if (pendingWResult.statusCode === 200 && pendingWResult.data && pendingWResult.data[0]) {
            pendingWithdrawals = pendingWResult.data[0].count || 0;
        }
        
        var pendingEditsResult = await supabaseRequest('GET', 'biodata_approvals?select=count&status=eq.pending&request_type=eq.profile_edit');
        var pendingProfileEdits = 0;
        if (pendingEditsResult.statusCode === 200 && pendingEditsResult.data && pendingEditsResult.data[0]) {
            pendingProfileEdits = pendingEditsResult.data[0].count || 0;
        }
        
        var totalPending = pendingRegistrations + pendingTransactions + pendingLoans + pendingWithdrawals + pendingProfileEdits;
        
        if (totalPending === 0) {
            Logger.log('No pending approvals');
            return { success: true, message: 'No pending approvals' };
        }
        
        var tableData = [
            { label: '📝 Pending Registrations', value: pendingRegistrations },
            { label: '📝 Pending Transactions', value: pendingTransactions },
            { label: '📝 Pending Loans', value: pendingLoans },
            { label: '📝 Pending Withdrawals', value: pendingWithdrawals },
            { label: '📝 Pending Profile Edits', value: pendingProfileEdits },
            { label: '🔄 Total Pending', value: totalPending }
        ];
        
        var subject = '⏳ Pending Approvals Reminder - ' + totalPending + ' items';
        var htmlBody = generateSummaryTable('📋 PENDING APPROVALS', new Date().toLocaleDateString(), tableData);
        
        var adminsResult = await supabaseRequest('GET', 'members?select=email&role=in.(admin,super_admin)&is_active=eq.true&email=not.is.null');
        var adminEmails = [];
        if (adminsResult.statusCode === 200 && adminsResult.data) {
            for (var a = 0; a < adminsResult.data.length; a++) {
                if (adminsResult.data[a].email) {
                    adminEmails.push(adminsResult.data[a].email);
                }
            }
        }
        
        for (var e = 0; e < adminEmails.length; e++) {
            await sendEmailNotification(adminEmails[e], subject, htmlBody);
        }
        
        Logger.log('Pending approvals reminder sent');
        return { success: true, message: 'Pending approvals reminder sent' };
        
    } catch (error) {
        Logger.log('Error sending pending approvals reminder: ' + error.message);
        return { success: false, message: error.message };
    }
}

async function sendAccountActivationEmail(memberData) {
    var tableData = [
        { label: '👤 Name', value: memberData.full_name },
        { label: '🆔 Member ID', value: memberData.unique_member_id },
        { label: '💰 Savings Balance', value: 'KES ' + (memberData.savings_balance || 0).toFixed(2) },
        { label: '✅ Status', value: 'Active' }
    ];
    
    var subject = '✅ Account Activated - Welcome to Brightlife CBO!';
    var htmlBody = generateSummaryTable('🎉 ACCOUNT ACTIVATED', 'Welcome ' + memberData.full_name, tableData);
    
    if (memberData.email) {
        await sendEmailNotification(memberData.email, subject, htmlBody);
    }
}

async function sendSavingsApprovedEmail(memberData, amount, newBalance) {
    var tableData = [
        { label: '👤 Name', value: memberData.full_name },
        { label: '🆔 Member ID', value: memberData.unique_member_id },
        { label: '💰 Deposit Amount', value: 'KES ' + amount.toFixed(2) },
        { label: '📊 New Balance', value: 'KES ' + newBalance.toFixed(2) },
        { label: '✅ Status', value: 'Approved' }
    ];
    
    var subject = '✅ Savings Approved - KES ' + amount.toFixed(2);
    var htmlBody = generateSummaryTable('💰 SAVINGS DEPOSIT APPROVED', new Date().toLocaleDateString(), tableData);
    
    if (memberData.email) {
        await sendEmailNotification(memberData.email, subject, htmlBody);
    }
}

async function sendRegistrationAlert(memberData) {
    var tableData = [
        { label: '👤 Name', value: memberData.fullName },
        { label: '🆔 ID Number', value: memberData.idNumber },
        { label: '📱 Phone', value: memberData.phoneNumber },
        { label: '📧 Email', value: memberData.email || 'N/A' },
        { label: '🆔 Member ID', value: memberData.uniqueId },
        { label: '📅 Date', value: new Date().toLocaleString() }
    ];
    
    var subject = '🔔 New Registration - ' + memberData.fullName;
    var htmlBody = generateSummaryTable('📝 NEW MEMBER REGISTRATION', new Date().toLocaleString(), tableData);
    
    await sendEmailNotification(CONFIG.ADMIN_WHATSAPP, subject, htmlBody);
}

async function sendWithdrawalAlert(memberData, amount, phone) {
    var tableData = [
        { label: '👤 Name', value: memberData.full_name },
        { label: '🆔 Member ID', value: memberData.unique_member_id },
        { label: '💰 Amount', value: 'KES ' + amount.toFixed(2) },
        { label: '📱 Phone', value: phone || 'N/A' },
        { label: '📅 Date', value: new Date().toLocaleString() }
    ];
    
    var subject = '🏦 Withdrawal Request - ' + memberData.full_name;
    var htmlBody = generateSummaryTable('🏦 WITHDRAWAL REQUEST', 'Pending Approval', tableData);
    
    await sendEmailNotification(CONFIG.ADMIN_WHATSAPP, subject, htmlBody);
}

function testHashFunction() {
    var testPasswords = ['admin123', 'mOrisky07.super', 'Admin@2026'];
    var results = [];
    
    for (var i = 0; i < testPasswords.length; i++) {
        var hash = hashPassword(testPasswords[i]);
        results.push({
            password: testPasswords[i],
            hash: hash
        });
        Logger.log('Hash for "' + testPasswords[i] + '": ' + hash);
    }
    
    return results;
}

async function getAllTransactionsForAdmin(data) {
    try {
        var memberReference = data && (data.memberId || data.actorId);
        var actor = await getActor(memberReference, data && data.sessionToken);
        if (!actorCan(actor, 'view_transactions', ['super_admin', 'admin'])) {
            throw new Error('You do not have permission to view all transactions.');
        }

        var pageSize = 1000;
        var requestedLimit = Number(data && data.limit);
        if (!isFinite(requestedLimit) || requestedLimit <= 0) requestedLimit = 50000;
        requestedLimit = Math.min(Math.floor(requestedLimit), 50000);
        var requestedOffset = Number(data && data.offset);
        if (!isFinite(requestedOffset) || requestedOffset < 0) requestedOffset = 0;
        requestedOffset = Math.floor(requestedOffset);

        var transactions = [];
        var offset = requestedOffset;
        while (transactions.length < requestedLimit) {
            var batchLimit = Math.min(pageSize, requestedLimit - transactions.length);
            var endpoint = 'transactions?select=id,member_id,type,amount,payment_method,mpesa_code,description,status,created_by,created_at,updated_at' +
                '&order=created_at.desc&limit=' + batchLimit + '&offset=' + offset;
            var result = await supabaseRequest('GET', endpoint);
            if (result.statusCode !== 200 || !Array.isArray(result.data)) {
                throw new Error('Failed to fetch organization transactions.');
            }
            var batch = result.data;
            if (!batch.length) break;
            transactions = transactions.concat(batch);
            if (batch.length < batchLimit) break;
            offset += batch.length;
        }

        var memberIds = uniqueStrings(transactions.map(function(t) { return t.member_id; }));
        var memberById = {};
        if (memberIds.length) {
            for (var i = 0; i < memberIds.length; i += 100) {
                var ids = memberIds.slice(i, i + 100);
                var mr = await supabaseRequest('GET', 'members?select=id,unique_member_id,full_name,id_number,phone_number,email&id=in.(' + ids.map(encodeURIComponent).join(',') + ')&limit=100');
                if (mr.statusCode === 200 && Array.isArray(mr.data)) {
                    mr.data.forEach(function(m) { memberById[String(m.id)] = m; });
                }
            }
        }

        var processedTransactions = transactions.map(function(t) {
            var member = memberById[String(t.member_id)] || {};
            return {
                id: t.id,
                member_id: t.member_id,
                member_id_display: member.unique_member_id || '',
                member_name: member.full_name || 'Unknown Member',
                member_national_id: member.id_number || '',
                member_phone: member.phone_number || '',
                member_email: member.email || '',
                type: t.type,
                amount: numberValue(t.amount),
                payment_method: t.payment_method,
                mpesa_code: t.mpesa_code,
                description: t.description,
                status: t.status,
                created_by: t.created_by,
                created_at: t.created_at,
                updated_at: t.updated_at
            };
        });

        var totalCount = 0;
        var countResult = await supabaseRequest('GET', 'transactions?select=id&limit=1');
        if (countResult.statusCode === 200 && Array.isArray(countResult.data)) {
            // The complete row count is obtained with the same paginated reader below when necessary.
            // Prefer PostgREST Content-Range when available; otherwise count in pages.
        }
        var countOffset = 0;
        while (true) {
            var countBatch = await supabaseRequest('GET', 'transactions?select=id&limit=1000&offset=' + countOffset + '&order=created_at.desc');
            if (countBatch.statusCode !== 200 || !Array.isArray(countBatch.data) || !countBatch.data.length) break;
            totalCount += countBatch.data.length;
            if (countBatch.data.length < 1000) break;
            countOffset += countBatch.data.length;
            if (totalCount >= 50000) break;
        }

        return {
            success: true,
            transactions: processedTransactions,
            totalCount: totalCount,
            limit: requestedLimit,
            offset: requestedOffset
        };
    } catch (error) {
        Logger.log('Error in getAllTransactionsForAdmin: ' + error.message);
        return { success: false, message: error.message, transactions: [] };
    }
}

async function getAllRepaymentsForViewer(data) {
    try {
        var memberId = data && data.memberId;
        if (!memberId) throw new Error('Member ID is required');
        var auth = await supabaseRequest('GET', 'members?select=id,role,permissions&id=eq.' + encodeURIComponent(memberId));
        if (auth.statusCode !== 200 || !auth.data || !auth.data.length) throw new Error('Member not found');
        var u = auth.data[0], perms = u.permissions || {};
        var isOrg = ['super_admin','admin'].indexOf(u.role) >= 0 || perms.view_repayments === true;
        var endpoint = 'loan_repayments?select=id,loan_id,member_id,amount,payment_method,mpesa_code,payment_date,created_at&' + (isOrg ? '' : 'member_id=eq.' + encodeURIComponent(memberId) + '&') + 'order=payment_date.desc&limit=' + (isOrg ? '5000' : '500');
        var rr = await supabaseRequest('GET', endpoint);
        if (rr.statusCode !== 200) throw new Error('Failed to fetch repayment records');
        var repayments = Array.isArray(rr.data) ? rr.data : [];
        var loanIds = uniqueStrings(repayments.map(function(x){return x.loan_id;}));
        var memberIds = uniqueStrings(repayments.map(function(x){return x.member_id;}));
        var lookupEndpoints=[];
        if(loanIds.length) lookupEndpoints.push('loans?select=id,amount,status,total_repayment,amount_paid&id=in.(' + loanIds.map(encodeURIComponent).join(',') + ')');
        if(isOrg && memberIds.length) lookupEndpoints.push('members?select=id,full_name,unique_member_id,phone_number&id=in.(' + memberIds.map(encodeURIComponent).join(',') + ')');
        var lookups=lookupEndpoints.length?await supabaseFetchAll(lookupEndpoints):[];
        var lm={},mm={};
        lookups.forEach(function(r,i){
            if(r.statusCode!==200 || !Array.isArray(r.data)) return;
            if(i===0 && loanIds.length) r.data.forEach(function(l){lm[l.id]=l;});
            else r.data.forEach(function(m){mm[m.id]=m;});
        });
        repayments=repayments.map(function(r){var l=lm[r.loan_id]||{},m=mm[r.member_id]||{};return Object.assign({},r,{loan_amount:numberValue(l.amount),loan_status:l.status||'N/A',member_name:m.full_name||'',member_unique_id:m.unique_member_id||'',member_phone:m.phone_number||''});});
        var activeLoans=[];
        if(!isOrg){
            var activeResult=await supabaseRequest('GET','loans?select=id,amount,repayment_period,interest_rate,total_repayment,status,repayment_due_date,amount_paid,is_fully_paid&member_id=eq.'+encodeURIComponent(memberId)+'&status=eq.active&order=repayment_due_date.asc&limit=20');
            if(activeResult.statusCode===200 && Array.isArray(activeResult.data)) activeLoans=activeResult.data;
        }
        return {success:true, scope:isOrg?'organization':'member', repayments:repayments, activeLoans:activeLoans};
    } catch(e) { return {success:false,message:e.message,repayments:[]}; }
}

async function getTransactionSummaryForAdmin(data) {
    try {
        var memberId = data.memberId;
        
        Logger.log('=== GETTING TRANSACTION SUMMARY FOR ADMIN ===');
        Logger.log('Member ID: ' + memberId);
        
        await requirePermission(memberId, 'view_transactions', ['super_admin','admin'], data && data.sessionToken);
        
        // Get summary stats
        var result = await supabaseRequest('GET', 'transactions?select=type,amount,status');
        
        if (result.statusCode !== 200 || !result.data) {
            return { success: false, message: 'Failed to fetch transaction summary' };
        }
        
        var transactions = result.data;
        
        // Calculate totals
        var totalSavings = 0;
        var totalWithdrawals = 0;
        var totalRepayments = 0;
        var totalDisbursements = 0;
        var totalRegistrations = 0;
        var pendingCount = 0;
        var completedCount = 0;
        var rejectedCount = 0;
        var totalAmount = 0;
        
        for (var i = 0; i < transactions.length; i++) {
            var t = transactions[i];
            totalAmount += numberValue(t.amount);
            
            if (t.type === 'savings' || t.type === 'registration') {
                if (t.status === 'completed') {
                    if (t.type === 'savings') totalSavings += numberValue(t.amount);
                    if (t.type === 'registration') totalRegistrations += numberValue(t.amount);
                }
            }
            if (t.type === 'withdrawal' && t.status === 'completed') {
                totalWithdrawals += numberValue(t.amount);
            }
            if (t.type === 'loan_repayment' && t.status === 'completed') {
                totalRepayments += numberValue(t.amount);
            }
            if (t.type === 'loan_disbursement' && t.status === 'completed') {
                totalDisbursements += numberValue(t.amount);
            }
            
            if (t.status === 'pending') pendingCount++;
            if (t.status === 'completed') completedCount++;
            if (t.status === 'rejected') rejectedCount++;
        }
        
        return {
            success: true,
            summary: {
                totalSavings: totalSavings,
                totalWithdrawals: totalWithdrawals,
                totalRepayments: totalRepayments,
                totalDisbursements: totalDisbursements,
                totalRegistrations: totalRegistrations,
                pendingCount: pendingCount,
                completedCount: completedCount,
                rejectedCount: rejectedCount,
                totalAmount: totalAmount,
                totalTransactions: transactions.length
            }
        };
    } catch (error) {
        Logger.log('Error in getTransactionSummaryForAdmin: ' + error.message);
        return { success: false, message: error.message };
    }
}

async function getExecutiveDashboard(data) {
    try {
        var memberId = data && (data.memberId || data.actorId);
        if (!memberId) throw new Error('Member ID is required');
        var actor = await getActor(memberId, data && data.sessionToken);
        var user = actor;
        var permissions=effectivePermissions_(user.role,user.permissions);
        var isExecutive=['super_admin','admin','treasurer'].indexOf(String(user.role||'').toLowerCase())>=0 || permissions.view_reports===true;
        if(!isExecutive) return await getMemberExecutiveDashboard(memberId, data && data.sessionToken);

        var rs=await supabaseFetchAll([
            'members?select=id,full_name,unique_member_id,is_active,savings_balance,loan_limit,total_loans_taken,created_at&order=savings_balance.desc&limit=5000',
            'transactions?select=member_id,type,amount,status,created_at&order=created_at.desc&limit=20000',
            'loans?select=member_id,amount,total_repayment,status,application_date,repayment_due_date,amount_paid,created_at&order=created_at.desc&limit=10000',
            'withdrawal_requests?select=amount,status,created_at&limit=10000'
        ]);
        function arr(i){return rs[i]&&rs[i].statusCode===200&&Array.isArray(rs[i].data)?rs[i].data:[];}
        var members=arr(0),transactions=arr(1),loans=arr(2),withdrawals=arr(3);
        var completed=transactions.filter(function(t){return String(t.status||'').toLowerCase()==='completed';});
        function sum(list){return list.reduce(function(a,x){return a+numberValue(x.amount);},0);}
        var totalSavings=sum(completed.filter(function(t){return String(t.type||'').toLowerCase()==='savings';}));
        var registrationFees=sum(completed.filter(function(t){return String(t.type||'').toLowerCase()==='registration';}));
        var repayments=sum(completed.filter(function(t){return String(t.type||'').toLowerCase()==='loan_repayment';}));
        var disbursements=sum(completed.filter(function(t){return String(t.type||'').toLowerCase()==='loan_disbursement';}));
        var withdrawalsTotal=sum(withdrawals.filter(function(w){return String(w.status||'').toLowerCase()==='completed';}));
        var activeLoans=loans.filter(function(l){return String(l.status||'').toLowerCase()==='active';});
        var pendingLoans=loans.filter(function(l){return String(l.status||'').toLowerCase()==='pending';}).length;
        var pendingTransactions=transactions.filter(function(t){return String(t.status||'').toLowerCase()==='pending';}).length;
        var pendingWithdrawals=withdrawals.filter(function(w){return String(w.status||'').toLowerCase()==='pending';}).length;
        var defaulted=loans.filter(function(l){return String(l.status||'').toLowerCase()==='defaulted';}).length;
        var now=new Date(), overdue=activeLoans.filter(function(l){return l.repayment_due_date&&new Date(l.repayment_due_date)<now&&numberValue(l.amount_paid)<numberValue(l.total_repayment);}).length;
        var activeLoanBalance=sum(activeLoans.map(function(l){return {amount:Math.max(0,numberValue(l.total_repayment)-numberValue(l.amount_paid))};}));
        var months=[];
        for(var i=11;i>=0;i--){var d=new Date(now.getFullYear(),now.getMonth()-i,1);months.push({key:d.getFullYear()+'-'+String(d.getMonth()+1).padStart(2,'0'),label:d.toLocaleString('en',{month:'short'})+' '+String(d.getFullYear()).slice(-2),savings:0,repayments:0,registrations:0,loans:0,withdrawals:0});}
        var map={};months.forEach(function(m){map[m.key]=m;});
        completed.forEach(function(t){var d=new Date(t.created_at);if(isNaN(d.getTime()))return;var k=d.getFullYear()+'-'+String(d.getMonth()+1).padStart(2,'0');if(!map[k])return;var a=numberValue(t.amount);var type=String(t.type||'').toLowerCase();if(type==='savings')map[k].savings+=a;if(type==='registration')map[k].registrations+=a;if(type==='loan_repayment')map[k].repayments+=a;if(type==='loan_disbursement')map[k].loans+=a;});
        withdrawals.filter(function(w){return String(w.status||'').toLowerCase()==='completed';}).forEach(function(w){var d=new Date(w.created_at);if(isNaN(d.getTime()))return;var k=d.getFullYear()+'-'+String(d.getMonth()+1).padStart(2,'0');if(map[k])map[k].withdrawals+=numberValue(w.amount);});
        var topMembers=members.slice(0,50);
        return {success:true,scope:'organization',user:user,stats:{totalMembers:members.length,activeMembers:members.filter(function(m){return m.is_active===true;}).length,totalSavings:totalSavings,registrationFees:registrationFees,totalSavingsIncludingRegistration:totalSavings+registrationFees,loanDisbursements:disbursements,loanRepayments:repayments,totalWithdrawals:withdrawalsTotal,netFundMovement:totalSavings+registrationFees+repayments-disbursements-withdrawalsTotal,activeLoans:activeLoans.length,pendingLoans:pendingLoans,pendingTransactions:pendingTransactions,pendingWithdrawals:pendingWithdrawals,defaultedLoans:defaulted,overdueLoans:overdue,activeLoanBalance:activeLoanBalance},trend:months,topMembers:topMembers};
    } catch(e){return {success:false,message:e.message};}
}

async function getMemberExecutiveDashboard(memberId, sessionToken) {
    var result = await getMemberProfile({memberId:memberId, actorId:memberId, sessionToken:sessionToken});
    if(!result.success) return result;
    var p=result.profile||{}, tx=result.transactions||[], loans=result.loans||[], repayments=result.repayments||[];
    var months=[]; var now=new Date();
    for(var i=11;i>=0;i--){var d=new Date(now.getFullYear(),now.getMonth()-i,1);months.push({key:d.getFullYear()+'-'+String(d.getMonth()+1).padStart(2,'0'),label:d.toLocaleString('en',{month:'short'}),savings:0,repayments:0,loans:0});}
    var map={};months.forEach(function(m){map[m.key]=m;});
    tx.forEach(function(t){if(t.status!=='completed')return;var d=new Date(t.created_at);var k=d.getFullYear()+'-'+String(d.getMonth()+1).padStart(2,'0');if(map[k]&&t.type==='savings')map[k].savings+=numberValue(t.amount);});
    repayments.forEach(function(t){var d=new Date(t.payment_date||t.created_at);var k=d.getFullYear()+'-'+String(d.getMonth()+1).padStart(2,'0');if(map[k])map[k].repayments+=numberValue(t.amount);});
    loans.forEach(function(l){var d=new Date(l.application_date||l.created_at);var k=d.getFullYear()+'-'+String(d.getMonth()+1).padStart(2,'0');if(map[k])map[k].loans+=numberValue(l.amount);});
    return {success:true,scope:'member',profile:p,trend:months};
}

function htmlEscapeReport(v) {
    return String(v == null ? '' : v).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

function formatKes(v){ return 'KES ' + numberValue(v).toLocaleString('en-KE',{minimumFractionDigits:2,maximumFractionDigits:2}); }

async function getReportData(data) {
    var memberId=data&&data.memberId;
    if(!memberId) throw new Error('Member ID is required');
    var requester=await supabaseRequest('GET','members?select=id,role,permissions,full_name,unique_member_id&id=eq.'+encodeURIComponent(memberId));
    if(requester.statusCode!==200||!requester.data||!requester.data.length) throw new Error('User not found');
    var user=requester.data[0], perms=user.permissions||{};
    var admin=['super_admin','admin','treasurer'].indexOf(user.role)>=0 || perms.view_reports===true;
    var targetId=data.targetMemberId || null;
    if(!admin) targetId=memberId;

    // Organization report: administrators may request a complete report by leaving targetMemberId empty.
    if(admin && !targetId){
        var orgEndpoints=[
            'members?select=id,unique_member_id,full_name,is_active,savings_balance,loan_limit,total_loans_taken,total_loans_completed,total_loans_defaulted,registration_fee_paid,created_at&order=unique_member_id.asc&limit=5000',
            'transactions?select=id,member_id,type,amount,status,payment_method,mpesa_code,created_at&order=created_at.desc&limit=10000',
            'loans?select=id,member_id,amount,total_repayment,amount_paid,status,application_date,repayment_due_date&order=application_date.desc&limit=5000'
        ];
        var oo=await supabaseFetchAll(orgEndpoints);
        return {admin:true,organization:true,members:Array.isArray(oo[0].data)?oo[0].data:[],transactions:Array.isArray(oo[1].data)?oo[1].data:[],loans:Array.isArray(oo[2].data)?oo[2].data:[]};
    }

    var profile=await supabaseRequest('GET','members?select=id,unique_member_id,full_name,id_number,phone_number,email,role,is_active,registration_fee_paid,registration_fee_status,registration_fee_amount,savings_balance,loan_limit,loan_growth_tier,total_loans_taken,total_loans_completed,total_loans_defaulted,registration_date,created_at&id=eq.'+encodeURIComponent(targetId));
    if(profile.statusCode!==200||!profile.data||!profile.data.length) throw new Error('Member not found');
    var member=profile.data[0];
    var endpoints=[
      'transactions?select=id,type,amount,payment_method,mpesa_code,status,description,created_at&member_id=eq.'+encodeURIComponent(targetId)+'&order=created_at.desc&limit=1000',
      'loans?select=id,amount,repayment_period,interest_rate,total_repayment,status,application_date,repayment_due_date,amount_paid,is_fully_paid,created_at&member_id=eq.'+encodeURIComponent(targetId)+'&order=application_date.desc&limit=500',
      'loan_repayments?select=id,loan_id,amount,payment_method,mpesa_code,payment_date,created_at&member_id=eq.'+encodeURIComponent(targetId)+'&order=payment_date.desc&limit=1000'
    ];
    var rr=await supabaseFetchAll(endpoints);
    return {admin:admin,organization:false,member:member,transactions:Array.isArray(rr[0].data)?rr[0].data:[],loans:Array.isArray(rr[1].data)?rr[1].data:[],repayments:Array.isArray(rr[2].data)?rr[2].data:[]};
}

function setupDailySummaryTrigger(){return {success:true,message:'Use Vercel Cron for scheduled daily summaries.'};}
function setupWeeklySummaryTrigger(){return {success:true,message:'Use Vercel Cron for scheduled weekly summaries.'};}
function setupMonthlySummaryTrigger(){return {success:true,message:'Use Vercel Cron for scheduled monthly summaries.'};}
function setupOverdueLoansTrigger(){return {success:true,message:'Use Vercel Cron for overdue-loan alerts.'};}
function setupPendingApprovalsTrigger(){return {success:true,message:'Use Vercel Cron for pending-approval reminders.'};}
function initializeEmailTriggers(){return {success:true,message:'Vercel Cron replaces Apps Script triggers.'};}


async function generateReportPdf(data){
  try{
    const report=await getReportData(data||{});
    const doc=new PDFDocument({size:'A4',margin:40});
    const chunks=[]; doc.on('data',c=>chunks.push(c));
    const done=new Promise((resolve,reject)=>{doc.on('end',resolve);doc.on('error',reject);});
    doc.fontSize(20).text('SND BRIGHTLIFE CBO',{align:'center'});
    doc.moveDown(0.5).fontSize(12).text('Savings & Loans Management Report',{align:'center'});
    doc.moveDown();
    if(report.organization){
      const members=report.members||[], tx=report.transactions||[], loans=report.loans||[];
      const totalSavings=tx.filter(t=>t.type==='savings'&&t.status==='completed').reduce((a,t)=>a+numberValue(t.amount),0);
      const repayments=tx.filter(t=>t.type==='loan_repayment'&&t.status==='completed').reduce((a,t)=>a+numberValue(t.amount),0);
      const disbursed=loans.filter(l=>['active','completed','defaulted'].includes(l.status)).reduce((a,l)=>a+numberValue(l.amount),0);
      doc.fontSize(11).text(`Members: ${members.length}`);doc.text(`Savings: ${formatKes(totalSavings)}`);doc.text(`Repayments: ${formatKes(repayments)}`);doc.text(`Loans disbursed: ${formatKes(disbursed)}`);doc.moveDown();
      members.slice(0,100).forEach(m=>doc.fontSize(8).text(`${m.unique_member_id||''} | ${m.full_name||''} | ${m.is_active?'Active':'Pending'} | Savings ${formatKes(m.savings_balance)}`));
    }else{
      const m=report.member||{}; const tx=report.transactions||[], loans=report.loans||[], reps=report.repayments||[];
      doc.fontSize(13).text(`${m.full_name||'Member'} — ${m.unique_member_id||''}`);doc.moveDown();
      const savings=tx.filter(t=>t.type==='savings'&&t.status==='completed').reduce((a,t)=>a+numberValue(t.amount),0);
      const repayments=reps.reduce((a,t)=>a+numberValue(t.amount),0);
      const loaned=loans.reduce((a,t)=>a+numberValue(t.amount),0);
      doc.fontSize(10).text(`Savings balance: ${formatKes(m.savings_balance)}`);doc.text(`Total savings: ${formatKes(savings)}`);doc.text(`Loans taken: ${formatKes(loaned)}`);doc.text(`Repayments: ${formatKes(repayments)}`);doc.moveDown();
      doc.fontSize(11).text('Loan History');loans.slice(0,100).forEach(l=>doc.fontSize(8).text(`${new Date(l.application_date||l.created_at).toLocaleDateString('en-KE')} | ${formatKes(l.amount)} | ${l.status||''} | Due ${formatKes(l.total_repayment)}`));doc.moveDown();
      doc.fontSize(11).text('Recent Transactions');tx.slice(0,100).forEach(t=>doc.fontSize(8).text(`${new Date(t.created_at).toLocaleDateString('en-KE')} | ${t.type||''} | ${formatKes(t.amount)} | ${t.status||''} | ${t.mpesa_code||''}`));
    }
    doc.end(); await done; const base64=Buffer.concat(chunks).toString('base64');
    const id=report.organization?'organization':(report.member?.unique_member_id||'member');
    return {success:true,filename:`Brightlife_${id}_Report_${formatDate_(new Date(),'Africa/Nairobi','yyyyMMdd_HHmm')}.pdf`,mimeType:'application/pdf',base64};
  }catch(e){Logger.log('PDF report error: '+e.stack);return {success:false,message:e.message};}
}


const FUNCTIONS = {
  numberValue: numberValue,
  uniqueStrings: uniqueStrings,
  getCompletedSavingsMonths: getCompletedSavingsMonths,
  getLoanInterestRate: getLoanInterestRate,
  effectivePermissions_: effectivePermissions_,
  resolveMemberUuidRequired_: resolveMemberUuidRequired_,
  getActor: getActor,
  actorCan: actorCan,
  requirePermission: requirePermission,
  getAccountAccess: getAccountAccess,
  normalizeLoanMultiplier: normalizeLoanMultiplier,
  getActiveLoanCalculation: getActiveLoanCalculation,
  htmlEscape_: htmlEscape_,
  hashPassword: hashPassword,
  registerMember: registerMember,
  logoutMember: logoutMember,
  loginMember: loginMember,
  getMemberProfile: getMemberProfile,
  getMemberById: getMemberById,
  getAllMembers: getAllMembers,
  updateBiodata: updateBiodata,
  approveProfileEdit: approveProfileEdit,
  rejectProfileEdit: rejectProfileEdit,
  resetPassword: resetPassword,
  normalizeIdNumber_: normalizeIdNumber_,
  resolveMemberUuid_: resolveMemberUuid_,
  writeAuditLog: writeAuditLog,
  requireContentAdmin_: requireContentAdmin_,
  getSiteContentAdmin: getSiteContentAdmin,
  saveSiteContent: saveSiteContent,
  getPublishedSiteContent: getPublishedSiteContent,
  getGuarantorRequests: getGuarantorRequests,
  respondToGuarantorRequest: respondToGuarantorRequest,
  requestPasswordReset: requestPasswordReset,
  resetPasswordWithOtp: resetPasswordWithOtp,
  getManagementReportData: getManagementReportData,
  synchronizeMemberAccountAge: synchronizeMemberAccountAge,
  initiateKcbMpesaPayment: initiateKcbMpesaPayment,
  getKcbPaymentStatus: getKcbPaymentStatus,
  checkMpesaCode: checkMpesaCode,
  processSavings: processSavings,
  notifyAdmins: notifyAdmins,
  approveRegistrationFee: approveRegistrationFee,
  rejectRegistrationFee: rejectRegistrationFee,
  approveSavings: approveSavings,
  rejectSavings: rejectSavings,
  approveWithdrawal: approveWithdrawal,
  rejectWithdrawal: rejectWithdrawal,
  applyForLoan: applyForLoan,
  approveLoan: approveLoan,
  rejectLoan: rejectLoan,
  repayLoan: repayLoan,
  requestWithdrawal: requestWithdrawal,
  getAdminDashboard: getAdminDashboard,
  getDashboardStats: getDashboardStats,
  getLoanGrowthSettings: getLoanGrowthSettings,
  getDefaultLoanGrowthSettings: getDefaultLoanGrowthSettings,
  updateLoanGrowthSettings: updateLoanGrowthSettings,
  activateLoanGrowthMethod: activateLoanGrowthMethod,
  evaluateLoanGrowth: evaluateLoanGrowth,
  calculateDefaultLoanLimit: calculateDefaultLoanLimit,
  calculateAdvancedLoanLimit: calculateAdvancedLoanLimit,
  calculateLoanGrowthMetrics: calculateLoanGrowthMetrics,
  determineTier: determineTier,
  generateLoanGrowthMessage: generateLoanGrowthMessage,
  checkActiveLoanGrowthMethod: checkActiveLoanGrowthMethod,
  generateRecommendations: generateRecommendations,
  getLoanGrowthStatus: getLoanGrowthStatus,
  batchEvaluateLoanGrowth: batchEvaluateLoanGrowth,
  forceRefreshAdminData: forceRefreshAdminData,
  debugPendingTransactions: debugPendingTransactions,
  activateMember: activateMember,
  deactivateMember: deactivateMember,
  grantRights: grantRights,
  removeRights: removeRights,
  togglePermission: togglePermission,
  sendCustomerCareMessage: sendCustomerCareMessage,
  getMemberMessages: getMemberMessages,
  getUnreadMessages: getUnreadMessages,
  getAllCustomerMessages: getAllCustomerMessages,
  markMessagesAsRead: markMessagesAsRead,
  replyToMember: replyToMember,
  updateCustomerCareNumber: updateCustomerCareNumber,
  getSettings: getSettings,
  updateSettings: updateSettings,
  assignAdmin: assignAdmin,
  removeAdmin: removeAdmin,
  updateMemberByAdmin: updateMemberByAdmin,
  nextCdoMemberId_: nextCdoMemberId_,
  adminAddExistingMember: adminAddExistingMember,
  getMemberFinancialHistory: getMemberFinancialHistory,
  adminRecordHistoricalTransaction: adminRecordHistoricalTransaction,
  adminRecordHistoricalLoan: adminRecordHistoricalLoan,
  adminRecordHistoricalLoanRepayment: adminRecordHistoricalLoanRepayment,
  parseCsvImport_: parseCsvImport_,
  importDate_: importDate_,
  importMoney_: importMoney_,
  findLoanForImport_: findLoanForImport_,
  importOneRow_: importOneRow_,
  importDataFile: importDataFile,
  nextNumberByTable_: nextNumberByTable_,
  getProcurementAndFinance: getProcurementAndFinance,
  createProcurementRequest: createProcurementRequest,
  updateProcurementStatus: updateProcurementStatus,
  createFinanceEntry: createFinanceEntry,
  getLoanById: getLoanById,
  getAllMemberTransactions: getAllMemberTransactions,
  sendDailySummary: sendDailySummary,
  createAdminUser: createAdminUser,
  testMemberStatus: testMemberStatus,
  generateSummaryTable: generateSummaryTable,
  sendDailySummaryEmail: sendDailySummaryEmail,
  sendWeeklySummaryEmail: sendWeeklySummaryEmail,
  sendMonthlySummaryEmail: sendMonthlySummaryEmail,
  sendOverdueLoansAlert: sendOverdueLoansAlert,
  sendPendingApprovalsReminder: sendPendingApprovalsReminder,
  sendAccountActivationEmail: sendAccountActivationEmail,
  sendSavingsApprovedEmail: sendSavingsApprovedEmail,
  sendRegistrationAlert: sendRegistrationAlert,
  sendWithdrawalAlert: sendWithdrawalAlert,
  testHashFunction: testHashFunction,
  getAllTransactionsForAdmin: getAllTransactionsForAdmin,
  getAllRepaymentsForViewer: getAllRepaymentsForViewer,
  getTransactionSummaryForAdmin: getTransactionSummaryForAdmin,
  getExecutiveDashboard: getExecutiveDashboard,
  getMemberExecutiveDashboard: getMemberExecutiveDashboard,
  htmlEscapeReport: htmlEscapeReport,
  formatKes: formatKes,
  getReportData: getReportData,
  sendWhatsAppAlert,
  sendEmailNotification,
  generateReportPdf,
  setupDailySummaryTrigger,
  setupWeeklySummaryTrigger,
  setupMonthlySummaryTrigger,
  setupOverdueLoansTrigger,
  setupPendingApprovalsTrigger,
  initializeEmailTriggers,
  healthCheck
};

const PUBLIC_FUNCTIONS = new Set(['healthCheck','loginMember','registerMember','requestPasswordReset','resetPasswordWithOtp','logoutMember']);

async function healthCheck(){
  const r=await supabaseRequest('GET','members?select=id&limit=1');
  if(r.statusCode!==200)return {success:false,message:'Supabase connection failed: '+(r.data?.message||r.data?.error||'Unknown database error.')};
  return {success:true,message:'SND Brightlife Vercel backend is running.'};
}

export async function runFunction(functionName, params={}) {
  const fn=FUNCTIONS[String(functionName||'').trim()];
  if(typeof fn!=='function') throw new Error('Unknown Brightlife server function: '+functionName);
  return await fn(params||{});
}

async function handler(req,res){
  if(req.method==='OPTIONS'){res.setHeader('Access-Control-Allow-Origin','*');res.setHeader('Access-Control-Allow-Methods','POST, OPTIONS');res.setHeader('Access-Control-Allow-Headers','Content-Type, Authorization');return res.status(204).end();}
  if(req.method!=='POST')return res.status(405).json({success:false,message:'Method not allowed.'});
  try{
    const body=typeof req.body==='string'?JSON.parse(req.body):req.body||{};
    const functionName=String(body.functionName||'').trim(); const params=body.params&&typeof body.params==='object'?body.params:{};
    if(!functionName)return res.status(400).json({success:false,message:'No server function specified.'});
    const fn=FUNCTIONS[functionName]; if(typeof fn!=='function')return res.status(404).json({success:false,message:'Unknown Brightlife server function: '+functionName});
    if(!PUBLIC_FUNCTIONS.has(functionName)){
      const actorId=params.actorId||params.memberId;
      if(!actorId||!params.sessionToken)return res.status(401).json({success:false,message:'Authentication is required. Please sign in again.'});
      await validateSession_(await resolveMemberUuidRequired_(actorId,'Authorized user'),params.sessionToken);
    }
    const result=await runFunction(functionName,params);
    return res.status(result&&result.success===false?400:200).json(result??{success:true});
  }catch(e){Logger.log('Vercel API error: '+(e.stack||e));return res.status(/authentication|session|permission|inactive/i.test(e.message||'')?401:500).json({success:false,message:e.message||'Internal server error.'});}
}
export default handler;
