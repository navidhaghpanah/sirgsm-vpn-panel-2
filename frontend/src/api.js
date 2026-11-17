import {language,translate} from './i18n';
let csrf='';
export function setCsrf(value){csrf=value;}
export async function api(path,options={}){
  const response=await fetch('/api'+path,{...options,headers:{'Content-Type':'application/json','X-CSRF-Token':csrf,...options.headers},credentials:'same-origin'});
  if(!response.ok){
    let body;try{body=await response.json();}catch{body={};}
    const e=new Error(translate(typeof body.detail==='string'?body.detail:response.status===401?'ابتدا وارد شوید':'درخواست انجام نشد؛ اطلاعات را بررسی کنید'));e.status=response.status;throw e;
  }
  return response.json();
}
export const fa={format(value){return new Intl.NumberFormat(language()==='fa'?'fa-IR':'en-US',{maximumFractionDigits:1}).format(value);}};
export function bytes(value){if(value===0)return fa.format(0)+' GB';const unit=value>=1e9?['GB',1e9]:value>=1e6?['MB',1e6]:value>=1e3?['KB',1e3]:['B',1];return fa.format(value/unit[1])+' '+unit[0];}
export function date(value){return value?new Date(value).toLocaleDateString(language()==='fa'?'fa-IR':'en-GB',{timeZone:'Asia/Tehran'}):translate('بدون انقضا');}
export const labels={active:'فعال',disabled:'غیرفعال',expired:'منقضی',quota:'اتمام حجم'};
