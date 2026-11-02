let csrfToken = "";
let currentUser = null;
const $ = s => document.querySelector(s);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
async function api(url, options={}) {
  const headers = {...(options.headers||{})};
  if (options.method && !["GET","HEAD"].includes(options.method)) headers["x-csrf-token"] = csrfToken;
  if (options.body && !(options.body instanceof FormData)) headers["Content-Type"]="application/json";
  const res = await fetch(url,{credentials:"same-origin",...options,headers});
  if (res.status===401) { showLogin(); throw new Error("Please sign in again."); }
  const ct = res.headers.get("content-type") || "";
  if (!res.ok) {
    const data = ct.includes("application/json") ? await res.json() : {error:"Request failed."};
    throw new Error(data.error || "Request failed.");
  }
  return ct.includes("application/json") ? res.json() : res;
}
async function refreshToken() { const r=await fetch("/api/csrf",{credentials:"same-origin"}); csrfToken=(await r.json()).token; }
function showLogin(){ $("#loginPanel").hidden=false; $("#appPanel").hidden=true; $("#userArea").textContent=""; }
function showApp(user){ currentUser=user; $("#loginPanel").hidden=true; $("#appPanel").hidden=false; $("#userArea").innerHTML=`<span>${esc(user.username)} · ${esc(user.role)}</span> <button id="logout" class="outline">Sign out</button>`; $("#logout").onclick=logout; loadDashboard(); loadMembers(); }
async function logout(){try{await api("/api/logout",{method:"POST"});}catch{} showLogin(); await refreshToken();}
$("#loginForm").addEventListener("submit",async e=>{e.preventDefault();$("#loginError").textContent="";const d=Object.fromEntries(new FormData(e.currentTarget));try{const r=await api("/api/login",{method:"POST",body:JSON.stringify(d)});csrfToken=r.csrfToken;showApp(r.user);}catch(err){$("#loginError").textContent=err.message;}});
async function loadDashboard(){try{const {counts,target}=await api("/api/dashboard");const active=Number(counts.active||0);const items=[["Total records",counts.total||0],["Active members",active],["To target",Math.max(0,target-active)],["Reserve pool",counts.reserve||0],["Selected",counts.selected||0]];$("#stats").innerHTML=items.map(([l,v])=>`<div class="stat"><strong>${Number(v).toLocaleString("en-AU")}</strong><span>${l}</span></div>`).join("");}catch(e){console.warn(e);}}
async function loadMembers(){try{const q=encodeURIComponent($("#search").value||"");const st=encodeURIComponent($("#statusFilter").value||"");const {members}=await api(`/api/members?q=${q}&status=${st}`);$("#memberRows").innerHTML=members.map(m=>`<tr><td>${esc(m.member_code)}</td><td>${esc(m.given_names)} ${esc(m.surname)}</td><td>${esc(m.suburb)}, ${esc(m.state)}</td><td><span class="status ${esc(m.status)}">${esc(m.status)}</span></td><td>${["active","reserve","selected","withdrawn"].includes(m.status)?`<select aria-label="Change status" data-id="${m.id}" class="changeStatus"><option selected>${esc(m.status)}</option>${["active","reserve","selected","withdrawn","pending","incomplete"].filter(x=>x!==m.status).map(x=>`<option>${x}</option>`).join("")}</select>`:"—"}</td></tr>`).join("")||'<tr><td colspan="5">No matching records.</td></tr>';document.querySelectorAll(".changeStatus").forEach(el=>el.addEventListener("change",async()=>{try{await api(`/api/members/${el.dataset.id}/status`,{method:"PATCH",body:JSON.stringify({status:el.value})});await loadDashboard();await loadMembers();}catch(e){alert(e.message);}}));}catch(e){console.warn(e);}}
$("#memberForm").addEventListener("submit",async e=>{e.preventDefault();const fd=new FormData(e.currentTarget);const d={};for(const [k,v] of fd.entries())d[k]=v;["enrolled_voter","supports_registration","not_counted_for_other_party","consent_to_membership","privacy_acknowledged"].forEach(k=>d[k]=fd.has(k));$("#memberMessage").textContent="Saving…";try{const r=await api("/api/members",{method:"POST",body:JSON.stringify(d)});$("#memberMessage").textContent=`Saved ${r.member_code} (${r.status}).`;e.currentTarget.reset();await loadDashboard();await loadMembers();}catch(err){$("#memberMessage").textContent=err.message;}});
$("#search").addEventListener("input",()=>loadMembers());$("#statusFilter").addEventListener("change",()=>loadMembers());
$("#exportBtn").addEventListener("click",async()=>{try{const res=await api("/api/export/aec.csv");const blob=await res.blob();const url=URL.createObjectURL(blob);const a=document.createElement("a");a.href=url;a.download="Australia_United_Party_AEC_members.csv";a.click();URL.revokeObjectURL(url);}catch(e){alert(e.message);}});
(async()=>{await refreshToken();try{const {user}=await api("/api/me");if(user)showApp(user);else showLogin();}catch{showLogin();}})();
