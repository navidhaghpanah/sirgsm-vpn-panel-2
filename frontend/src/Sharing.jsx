import React,{useEffect,useState} from 'react';
import {api,bytes,date,labels} from './api';
import {useI18n} from './i18n';

function words(lang){return lang==='fa'?{
 title:'کانفیگ‌ها و اشتراک',private:'این لینک خصوصی است؛ هرکس آن را داشته باشد می‌تواند کانفیگ‌های این کاربر را دریافت کند.',
 create:'ساخت لینک خصوصی',rotate:'تعویض لینک',revoke:'باطل کردن لینک',confirm:'لینک قبلی از کار بیفتد؟',page:'صفحهٔ اختصاصی کاربر',sub:'لینک اشتراک',copy:'کپی',copied:'کپی شد',open:'بازکردن صفحه',
 explain:'اشتراک را در Hiddify، V2Box یا برنامهٔ سازگار وارد کنید. OpenVPN و IKEv2 به‌صورت فایل جداگانه دریافت می‌شوند.',
 show:'نمایش لینک و QR',download:'دانلود',refresh:'به‌روزرسانی',bad:'لینک معتبر نیست یا باطل شده است.',inactive:'این حساب فعال نیست؛ دریافت کانفیگ متوقف است.',ready:'کانفیگ‌ها در حال آماده‌شدن هستند.',used:'مصرف مشترک',expires:'انقضا',unlimited:'بدون محدودیت',noXray:'برای این حساب فقط فایل اتصال فعال است؛ لینک اشتراک Xray ندارد.',ca:'گواهی CA',ios:'پروفایل آیفون',guide:'راهنما و رمز IKEv2',failed:'درخواست انجام نشد؛ دوباره تلاش کنید.',qr:'کد QR',close:'بستن',
 }:{title:'Configs & subscription',private:'Keep this link private. Anyone who has it can download this user’s configurations.',create:'Create private link',rotate:'Rotate link',revoke:'Revoke link',confirm:'Invalidate the previous link?',page:'Personal user page',sub:'Subscription URL',copy:'Copy',copied:'Copied',open:'Open page',explain:'Import the subscription in Hiddify, V2Box or a compatible client. OpenVPN and IKEv2 use separate downloadable files.',show:'Show link & QR',download:'Download',refresh:'Refresh',bad:'This link is invalid or has been revoked.',inactive:'This account is inactive. Configuration access is stopped.',ready:'Configurations are being prepared.',used:'Shared usage',expires:'Expiry',unlimited:'Unlimited',noXray:'This account has file-based services only; there is no Xray subscription.',ca:'CA certificate',ios:'iPhone profile',guide:'IKEv2 guide & password',failed:'Request failed. Please retry.',qr:'QR code',close:'Close'};}

export function QrImage({value}){
 const {lang}=useI18n();const l=words(lang);const [src,setSrc]=useState(''),[error,setError]=useState(false);
 useEffect(()=>{let live=true;setSrc('');setError(false);import('qrcode').then(q=>q.toDataURL(value,{width:240,margin:2,errorCorrectionLevel:'M'})).then(v=>{if(live)setSrc(v);}).catch(()=>{if(live)setError(true);});return()=>{live=false;};},[value]);
 return src?<img className="config-qr" src={src} alt={l.qr}/>:error?<p className="caption">{l.failed}</p>:null;
}

function CopyValue({value,label,qr=false}){
 const {lang}=useI18n();const l=words(lang);const [copied,setCopied]=useState(false);
 async function copy(){try{await navigator.clipboard.writeText(value);setCopied(true);}catch{setCopied(false);}}
 return <div className="share-value"><label>{label}<textarea readOnly dir="ltr" value={value} onFocus={e=>e.target.select()}/></label><button type="button" className="secondary" onClick={copy}>{copied?l.copied:l.copy}</button>{qr&&<QrImage value={value}/>}</div>;
}

export function SharePanel({user}){
 const {lang}=useI18n();const l=words(lang);const [share,setShare]=useState(null),[error,setError]=useState(''),[busy,setBusy]=useState(true);
 useEffect(()=>{let live=true;api('/users/'+user.id+'/share').then(v=>{if(live)setShare(v);}).catch(()=>{if(live)setError(l.failed);}).finally(()=>{if(live)setBusy(false);});return()=>{live=false;};},[user.id]);
 async function change(method){if(share&&!window.confirm(l.confirm))return;setBusy(true);setError('');try{const result=await api('/users/'+user.id+'/share',{method});setShare(method==='DELETE'?null:result);}catch{setError(l.failed);}finally{setBusy(false);}}
 const page=share?new URL(share.page_path,share.origin||location.origin).href:'',sub=share?new URL(share.subscription_path,share.origin||location.origin).href:'';
 const hasXray=user.protocols.some(p=>['reality','shadowsocks','trojan','vmess'].includes(p));
 return <section className="sharing"><h3>{l.title}</h3><p className="caption">{l.private}</p>{share?<><CopyValue label={l.page} value={page}/><a className="secondary" href={page} target="_blank" rel="noreferrer">{l.open}</a>{hasXray?<CopyValue label={l.sub} value={sub} qr/>:<p className="caption">{l.noXray}</p>}<div className="download-links"><button className="secondary" disabled={busy} onClick={()=>change('POST')}>{l.rotate}</button><button className="secondary danger" disabled={busy} onClick={()=>change('DELETE')}>{l.revoke}</button></div></>:<button className="primary" disabled={busy} onClick={()=>change('POST')}>{l.create}</button>}{error&&<p className="error" role="alert">{error}</p>}</section>;
}

export function ConfigLink({kind,url}){
 const {lang}=useI18n();const l=words(lang);const [value,setValue]=useState(''),[error,setError]=useState(''),[busy,setBusy]=useState(false);
 async function load(){setBusy(true);try{const r=await fetch(url,{cache:'no-store',credentials:'same-origin'});if(!r.ok)throw Error();setValue((await r.text()).trim());setError('');}catch{setError(l.failed);}finally{setBusy(false);}}
 return <div className="export-block"><h3>{kind.toUpperCase()}</h3><a className="secondary" href={url} download>{l.download}</a> <button className="secondary" disabled={busy} onClick={load}>{l.show}</button>{value&&<CopyValue value={value} label={kind.toUpperCase()} qr/>}{error&&<p role="alert" className="error">{error}</p>}</div>;
}

export function UserLanding({token}){
 const {lang,changeLang,theme,toggleTheme,t}=useI18n();const l=words(lang);const [user,setUser]=useState(null),[error,setError]=useState(''),[busy,setBusy]=useState(false);
 async function load(){setBusy(true);try{setUser(await api('/public/'+token));setError('');}catch{setUser(null);setError(l.bad);}finally{setBusy(false);}}
 useEffect(()=>{load();},[token]);
 const url=kind=>'/api/public/'+token+'/export/'+kind;
 const xray=user?.protocols.filter(p=>['reality','shadowsocks','trojan','vmess'].includes(p))||[];
 return <main className="user-landing"><header><div><h1 dir="ltr">SirGSM</h1><p>{l.page}{user&&' · '+user.name}</p></div><div className="download-links"><button className="secondary" onClick={()=>changeLang(lang==='fa'?'en':'fa')}>{lang==='fa'?'English':'فارسی'}</button><button className="secondary" onClick={toggleTheme}>{t(theme==='light'?'تیره':'روشن')}</button><button className="secondary" disabled={busy} onClick={load}>{l.refresh}</button></div></header>{error&&<p className="error" role="alert">{error}</p>}{user&&<><div className="user-summary"><strong>{t(labels[user.status])}</strong><p>{l.used}: {bytes(user.used)} / {user.quota?bytes(user.quota):l.unlimited}</p><p>{l.expires}: {date(user.expires)}</p></div>{user.status!=='active'?<p role="alert">{l.inactive}</p>:!user.ready?<p>{l.ready}</p>:<><p className="caption">{l.private}</p>{xray.length>0&&<section><h2>{l.sub}</h2><p>{l.explain}</p><CopyValue label={l.sub} value={new URL(user.subscription_path,user.origin||location.origin).href} qr/></section>}{xray.map(kind=><ConfigLink key={kind} kind={kind} url={url(kind)}/>)}{user.protocols.includes('openvpn')&&<section><h2>OpenVPN</h2><p>{t('فایل را در OpenVPN Connect وارد کنید؛ رمز جداگانه لازم نیست.')}</p><a className="primary" href={url('openvpn')} download>{l.download} OpenVPN</a></section>}{user.protocols.includes('ikev2')&&<section><h2>IKEv2</h2><p>{t('برای آیفون پروفایل و برای سایر دستگاه‌ها، راهنما و گواهی را دریافت کنید. پس از نصب، اعتماد گواهی را بررسی کنید.')}</p><div className="download-links">{[['ios',l.ios],['ikev2',l.guide],['ca',l.ca]].map(([kind,label])=><a className="secondary" key={kind} href={url(kind)} download>{label}</a>)}</div></section>}</>}</>}<footer>NH · <a href="https://sirgsm.ir" rel="noreferrer" target="_blank">sirgsm.ir</a></footer></main>;
}
