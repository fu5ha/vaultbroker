package web

import (
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"github.com/fu5ha/vaultbroker/internal/broker"
)

type indexData struct {
	Registered bool
	LoggedIn   bool
	CSRF       string
	Status     broker.Status
	Pending    []broker.Request
}

type unlockData struct {
	CSRF       string
	Error      string
	NeedsLogin bool
}

type approveData struct {
	CSRF     string
	Request  broker.Request
	Mismatch bool
}

func render(w http.ResponseWriter, tmpl *template.Template, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = tmpl.Execute(w, data)
}

// originMismatch reports whether the page origin's host matches none of
// the item's stored URIs. Bitwarden URI match rules are richer; host
// equality is the conservative check worth showing.
func originMismatch(origin string, uris []string) bool {
	page, err := url.Parse(origin)
	if err != nil || page.Host == "" || len(uris) == 0 {
		return true
	}
	for _, raw := range uris {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			u2, err2 := url.Parse("https://" + raw)
			if err2 != nil {
				continue
			}
			u = u2
		}
		if strings.EqualFold(u.Hostname(), page.Hostname()) {
			return false
		}
	}
	return true
}

const pageStyle = `<style>
body{font-family:system-ui,sans-serif;max-width:34rem;margin:2rem auto;padding:0 1rem;line-height:1.5;color:#1a1a1a}
h1{font-size:1.3rem} button{font-size:1rem;padding:.55rem 1rem;margin:.25rem .25rem .25rem 0;cursor:pointer}
input{display:block;width:100%;padding:.5rem;margin:.25rem 0 1rem;box-sizing:border-box}
.warn{background:#fdecec;border:1px solid #c0392b;padding:.75rem;border-radius:.4rem}
.ok{background:#eaf7ea;border:1px solid #2e7d32;padding:.75rem;border-radius:.4rem}
table{border-collapse:collapse} td,th{text-align:left;padding:.2rem .6rem .2rem 0;vertical-align:top}
code{word-break:break-all} .muted{color:#666}
</style>`

const passkeyJS = `<script>
function b64uToBuf(s){s=s.replace(/-/g,'+').replace(/_/g,'/');while(s.length%4)s+='=';const b=atob(s);const u=new Uint8Array(b.length);for(let i=0;i<b.length;i++)u[i]=b.charCodeAt(i);return u.buffer}
function bufToB64u(b){const u=new Uint8Array(b);let s='';for(const c of u)s+=String.fromCharCode(c);return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')}
function credJSON(c){const r={id:c.id,rawId:bufToB64u(c.rawId),type:c.type,response:{clientDataJSON:bufToB64u(c.response.clientDataJSON)}};
 if(c.response.attestationObject)r.response.attestationObject=bufToB64u(c.response.attestationObject);
 if(c.response.authenticatorData)r.response.authenticatorData=bufToB64u(c.response.authenticatorData);
 if(c.response.signature)r.response.signature=bufToB64u(c.response.signature);
 if(c.response.userHandle)r.response.userHandle=bufToB64u(c.response.userHandle);return r}
async function postJSON(url,body,headers){const r=await fetch(url,{method:'POST',headers:Object.assign({'Content-Type':'application/json'},headers||{}),body:body?JSON.stringify(body):undefined});
 const j=await r.json().catch(()=>({}));if(!r.ok)throw new Error(j.error||('HTTP '+r.status));return j}
async function createPasskey(beginURL,finishURL){const o=await postJSON(beginURL);const pk=o.publicKey;
 pk.challenge=b64uToBuf(pk.challenge);pk.user.id=b64uToBuf(pk.user.id);
 (pk.excludeCredentials||[]).forEach(c=>c.id=b64uToBuf(c.id));
 const cred=await navigator.credentials.create({publicKey:pk});return postJSON(finishURL,credJSON(cred))}
async function getPasskey(beginURL,headers){const o=await postJSON(beginURL,null,headers);const pk=o.publicKey;
 pk.challenge=b64uToBuf(pk.challenge);(pk.allowCredentials||[]).forEach(c=>c.id=b64uToBuf(c.id));
 const cred=await navigator.credentials.get({publicKey:pk});return credJSON(cred)}
function showError(el,e){el.textContent=e.message;el.style.display='block'}
</script>`

var indexTemplate = template.Must(template.New("index").Parse(`<!doctype html>
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Vaultbroker</title>` + pageStyle + `
<h1>Vaultbroker</h1>
{{if not .Registered}}
<p>No passkey is registered yet. On the broker machine, read the one-time token with
<code>sudo cat /var/lib/vaultbroker/register-token</code>, then open
<code>/register?token=...</code> on this device.</p>
{{else if not .LoggedIn}}
<p>Log in with the Vaultbroker passkey in your Bitwarden.</p>
<p class="warn" id="err" style="display:none"></p>
<button id="login">Log in with passkey</button>
` + passkeyJS + `<script>
document.getElementById('login').onclick=async()=>{try{
 const body=await getPasskey('/api/webauthn/login/begin');
 await postJSON('/api/webauthn/login/finish',body);location.reload();
}catch(e){showError(document.getElementById('err'),e)}};
</script>
{{else}}
<p>Vault: <strong>{{.Status.Vault}}</strong>{{if not .Status.Configured}} (scope pin pending){{end}}</p>
{{if eq .Status.Vault "locked"}}<p><a href="/unlock">Unlock the vault</a></p>{{end}}
<h2>Pending approvals ({{len .Pending}})</h2>
{{range .Pending}}<p><a href="/approve/{{.ID}}">{{.Fill.ItemName}}</a> <span class="muted">into session {{.Fill.Session}}, expires {{.ExpiresAt.Format "15:04:05"}}</span></p>
{{else}}<p class="muted">None.</p>{{end}}
<form method="post" action="/logout"><button type="submit">Log out</button></form>
{{end}}`))

var registerTemplate = template.Must(template.New("register").Parse(`<!doctype html>
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Register passkey</title>` + pageStyle + `
<h1>Register the Vaultbroker passkey</h1>
<p>Save the passkey into your own Bitwarden vault when prompted. This page
works once; registration closes as soon as a passkey exists.</p>
<p class="warn" id="err" style="display:none"></p>
<button id="register">Create passkey</button>
` + passkeyJS + `<script>
document.getElementById('register').onclick=async()=>{try{
 await createPasskey('/api/webauthn/register/begin?token={{.Token}}','/api/webauthn/register/finish');
 location.href='/';
}catch(e){showError(document.getElementById('err'),e)}};
</script>`))

var unlockTemplate = template.Must(template.New("unlock").Parse(`<!doctype html>
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Unlock vault</title>` + pageStyle + `
{{if .NeedsLogin}}<h1>Log in to the agent vault</h1>
{{if .Error}}<p class="warn">{{.Error}}</p>{{end}}
<p>This machine has not logged in to the agent account yet, so this first
sign-in needs the account email as well. Future restarts only ask for the
master password. Credentials go straight to the Bitwarden CLI on this machine;
the broker keeps the session token in memory only.</p>
<form method="post" action="/unlock">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<label>Agent account email<input type="email" name="email" autocomplete="username" required></label>
<label>Agent vault master password<input type="password" name="password" autocomplete="current-password" required></label>
<button type="submit">Log in</button>
</form>
{{else}}<h1>Unlock the agent vault</h1>
{{if .Error}}<p class="warn">{{.Error}}</p>{{end}}
<p>The password goes straight to the Bitwarden CLI on this machine. The broker
keeps the session token in memory only, until reboot or lock.</p>
<form method="post" action="/unlock">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<label>Agent vault master password<input type="password" name="password" autocomplete="current-password" required></label>
<button type="submit">Unlock</button>
</form>
{{end}}
<p><a href="/">Back</a></p>`))

var approveTemplate = template.Must(template.New("approve").Parse(`<!doctype html>
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Approve fill</title>` + pageStyle + `
<h1>Approve browser fill</h1>
{{with .Request}}
<table>
<tr><th>Item</th><td>{{.Fill.ItemName}} <span class="muted">({{.Fill.ItemID}})</span></td></tr>
<tr><th>Browser session</th><td>{{.Fill.Session}}</td></tr>
<tr><th>Page origin</th><td><code>{{.Fill.Origin}}</code></td></tr>
<tr><th>Item URIs</th><td>{{range .Fill.ItemURIs}}<code>{{.}}</code><br>{{else}}<span class="muted">none stored</span>{{end}}</td></tr>
<tr><th>State</th><td id="state">{{.State}}</td></tr>
<tr><th>Expires</th><td>{{.ExpiresAt.Format "15:04:05"}}</td></tr>
<tr><th>Request hash</th><td><code>{{.Hash}}</code></td></tr>
</table>
<h2>Fields</h2>
<table>{{range .Fill.Fields}}<tr><td>{{.Field}}</td><td>→</td><td><code>{{if .Selector}}{{.Selector}}{{else}}@{{.Ref}}{{end}}</code></td></tr>{{end}}</table>
{{end}}
{{if .Mismatch}}<p class="warn">Warning: the page origin host matches none of the item's stored URIs.</p>{{end}}
<p class="warn" id="err" style="display:none"></p>
<p class="ok" id="done" style="display:none"></p>
{{if eq .Request.State "pending"}}
<button id="approve">Approve (passkey tap)</button>
<button id="deny">Deny</button>
` + passkeyJS + `<script>
const csrf='{{.CSRF}}', id='{{.Request.ID}}';
const errEl=document.getElementById('err'), doneEl=document.getElementById('done');
function done(state){doneEl.textContent='Recorded: '+state;doneEl.style.display='block';document.getElementById('state').textContent=state}
document.getElementById('approve').onclick=async()=>{try{
 const body=await getPasskey('/api/webauthn/assert/begin?request='+id,{'X-CSRF':csrf});
 const r=await fetch('/approve/'+id+'/decide?decision=approve',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF':csrf},body:JSON.stringify(body)});
 const j=await r.json();if(!r.ok)throw new Error(j.error||r.status);done(j.state);
}catch(e){showError(errEl,e)}};
document.getElementById('deny').onclick=async()=>{try{
 const r=await fetch('/approve/'+id+'/decide?decision=deny',{method:'POST',headers:{'X-CSRF':csrf}});
 const j=await r.json();if(!r.ok)throw new Error(j.error||r.status);done(j.state);
}catch(e){showError(errEl,e)}};
</script>
{{end}}
<p><a href="/">Back</a></p>`))
