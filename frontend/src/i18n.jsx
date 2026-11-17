import React,{createContext,useContext,useState} from 'react';
const dictionary={
 'منوی اصلی':'Main navigation','لینک REALITY':'REALITY link',
 'لینک پروکسی تلگرام':'Telegram proxy link','آدرس دامنه‌ای':'Domain address','آدرس IP مستقیم':'Direct IP address',
 'پروکسی تلگرام عمومی است و سهمیهٔ آن مستقل از کاربران VPN است.':'Telegram is a shared public proxy with traffic independent of VPN user quotas.',
 'دامنه و Fake TLS، IP سرور را از اپراتور پنهان نمی‌کنند.':'A domain name and Fake TLS do not conceal the server IP from the carrier.',
 'نمای کلی':'Overview','کاربران':'Users','سرویس‌ها':'Services','رویدادها':'Events',
 'مدیریت یکپارچهٔ اتصال‌ها':'One account. All your connections.',
 'افزودن کاربر':'Add user','سرور استکهلم':'SirGSM server','خروج از حساب':'Sign out',
 'کاربران فعال':'Active accounts','مصرف کل':'Total traffic','حافظه':'Memory','پردازنده':'CPU',
 'جست‌وجوی کاربر':'Search users','کاربر':'User','حجم مشترک':'Shared quota','انقضا':'Expires','وضعیت':'Status','مدیریت':'Actions',
 'فعال':'Active','متوقف':'Stopped','نصب نشده':'Not installed','غیرفعال':'Disabled','منقضی':'Expired','اتمام حجم':'Quota reached',
 'بدون محدودیت':'Unlimited','بدون انقضا':'No expiry','در حال آماده‌سازی':'Provisioning',
 'حجم و انقضا بین سرویس‌های هر کاربر مشترک است.':'Traffic quota and expiry are shared across each user’s enabled services.',
 'ورود به مدیریت اتصال‌ها':'Sign in to manage connections','نام کاربری':'Username','رمز عبور':'Password','ورود به پنل':'Sign in',
 'در حال ورود…':'Signing in…','در حال بارگذاری…':'Loading…','در حال دریافت اطلاعات سرور…':'Loading server data…',
 'ویرایش کاربر':'Edit user','دریافت کانفیگ':'Download configurations','کاربری با این نام پیدا نشد.':'No users match your search.',
 'هنوز کاربری ساخته نشده است.':'No users yet.','بستن':'Close','نام کاربر':'Username',
 'حروف انگلیسی، عدد، نقطه، خط تیره و زیرخط':'Letters, numbers, dots, hyphens and underscores.',
 'حجم مشترک (GB)':'Shared quota (GB)','صفر یعنی بدون محدودیت':'Zero means unlimited.',
 'پایان روز به وقت تهران؛ خالی یعنی بدون انقضا':'End of day in Tehran; leave empty for no expiry.',
 'سرویس‌های مجاز':'Enabled services','حساب فعال باشد':'Enable account','ذخیرهٔ کاربر':'Save user','در حال ذخیره…':'Saving…','انصراف':'Cancel',
 'صفر کردن مصرف':'Reset usage','حذف کاربر':'Delete user','مصرف این کاربر صفر شود؟':'Reset this user’s traffic usage?',
 'کاربر حذف و دسترسی او از همهٔ سرویس‌ها قطع شود؟':'Delete this user and revoke access to all services?',
 'مصرف فعلی':'Current usage','تغییر سقف حجم، مصرف قبلی را پاک نمی‌کند.':'Changing the limit does not reset existing usage.',
 'ویرایش':'Edit','کانفیگ‌های':'Configurations for',
 'این فایل‌ها خصوصی‌اند و همگی از سهمیهٔ همین حساب استفاده می‌کنند.':'These files contain private credentials and share this account’s traffic quota.',
 'کپی شد':'Copied','کپی لینک':'Copy link','دانلود لینک':'Download link','لینک را دستی کپی کنید':'Please copy the link manually.',
 'کانفیگ هنوز آماده نیست':'The configuration is not ready yet.',
 'فایل را در OpenVPN Connect وارد کنید؛ رمز جداگانه لازم نیست.':'Import into OpenVPN Connect. No username or password prompt. One simultaneous connection per certificate.',
 'دانلود فایل ovpn':'Download .ovpn','پروفایل آیفون':'iPhone profile','راهنما و رمز':'Instructions & password','گواهی CA':'CA certificate',
 'برای آیفون پروفایل و برای سایر دستگاه‌ها، راهنما و گواهی را دریافت کنید. پس از نصب، اعتماد گواهی را بررسی کنید.':'For iPhone, download the profile. For other devices, download the instructions and CA certificate. Review certificate trust before connecting.',
 'رویدادهای اخیر':'Recent events','آخرین بررسی':'Last checked','ساعت تهران':'Tehran time',
 'اطلاعات سرور به‌روز نیست؛ وضعیت دسترسی را بررسی کنید.':'Server data is stale. Check service and worker status.',
 'خطا در همگام‌سازی؛ جزئیات در رویدادها نمایش داده شده است.':'Synchronization error. Open Events for details.',
 'بازکردن منو':'Open navigation','روشن':'Light','تیره':'Dark','حساب مدیر':'Admin account',
 'تغییر اطلاعات مدیر':'Change admin credentials','رمز فعلی':'Current password','نام کاربری جدید':'New username','رمز جدید':'New password',
 'حداقل ۱۶ نویسه؛ همهٔ نشست‌ها پس از تغییر بسته می‌شوند.':'At least 16 characters. Changing credentials signs out all sessions.',
 'ذخیره و خروج':'Save & sign out','حمایت پروژه':'Project sponsor',
 'این نام قبلاً استفاده شده است':'This username is already taken.',
 'نام کاربری یا رمز اشتباه است':'Incorrect username or password.',
 'چند دقیقه بعد دوباره تلاش کنید':'Too many attempts. Try again in a few minutes.',
 'رمز فعلی اشتباه است':'Incorrect current password.',
 'ابتدا وارد شوید':'Please sign in.',
 'درخواست انجام نشد؛ اطلاعات را بررسی کنید':'Request failed. Check the submitted information.',
 'درخواست معتبر نیست':'Invalid request.',
 'این حساب فعال نیست':'This account is not active.',
 'این سرویس برای کاربر فعال نیست':'This service is not enabled for this user.',
 'کانفیگ هنوز آماده نشده؛ چند ثانیه صبر کنید':'Configuration is still being prepared. Try again shortly.',
 'IKEv2 به گواهی اعتماد و دسترسی UDP روی پورت‌های ۵۰۰ و ۴۵۰۰ نیاز دارد. فعال بودن سرویس، دسترسی از اپراتور را تضمین نمی‌کند.':'IKEv2 needs a trusted VPN certificate and UDP ports 500 and 4500. A running service does not guarantee reachability from your carrier.',
 'پروکسی تلگرام هنوز نصب نشده و در سهمیهٔ مشترک این نسخه محاسبه نمی‌شود.':'Telegram proxy is not installed and is not included in shared user quotas.',
 'شمارنده‌ها هر ۵ ثانیه بررسی می‌شوند؛ قطع دسترسی فوری و بایت‌به‌بایت نیست.':'Counters are checked every 5 seconds. Quota enforcement is not a byte-exact hard cap.',
 'تغییر کاربران ممکن است اتصال‌های REALITY را برای چند لحظه دوباره برقرار کند.':'Updating access may briefly reconnect Xray sessions.',
};
export function language(){return localStorage.getItem('sirgsm-language')||'fa';}
export function translate(text){
 if(language()!=='en')return text;
 if(dictionary[text])return dictionary[text];
 const patterns=[[/^کاربر (.+) ایجاد شد$/,'User $1 created'],[/^تنظیمات کاربر (.+) تغییر کرد$/,'User $1 updated'],[/^مصرف کاربر (.+) صفر شد$/,'Traffic usage reset for $1'],[/^کاربر (.+) حذف شد$/,'User $1 deleted']];
 for(const [pattern,replacement] of patterns)if(pattern.test(text))return text.replace(pattern,replacement);
 const events={'ورود مدیر':'Admin signed in','دسترسی سرویس‌ها با حساب‌های پنل همگام شد':'Service access synchronized with panel accounts','نام کاربری یا رمز مدیر تغییر کرد؛ نشست‌های قبلی باطل شدند':'Admin credentials changed; all sessions revoked','حساب فعلی REALITY و OpenVPN به پنل منتقل شد؛ شمارش مصرف از این لحظه آغاز می‌شود':'Existing REALITY and OpenVPN account imported; traffic metering starts now'};
 return events[text]||text;
}
const Context=createContext(null);
export function I18nProvider({children}){
 const [lang,setLang]=useState(language()),[theme,setTheme]=useState(localStorage.getItem('sirgsm-theme')||'light');
 document.documentElement.lang=lang;document.documentElement.dir=lang==='fa'?'rtl':'ltr';document.documentElement.dataset.theme=theme;
 function changeLang(value){localStorage.setItem('sirgsm-language',value);setLang(value);}
 function toggleTheme(){const next=theme==='light'?'dark':'light';localStorage.setItem('sirgsm-theme',next);setTheme(next);}
 return <Context.Provider value={{lang,theme,changeLang,toggleTheme,t:translate}}>{children}</Context.Provider>;
}
export function useI18n(){return useContext(Context);}
