# Separ interface specification

Reference: concept.png, 1536 × 1024. Built-in Image Gen concept; Persian RTL.
White (#fff) main canvas, cool gray (#f5f6f8) right rail, navy (#101b2c)
text, emerald (#008233) primary actions. No gradients or illustrative assets.
Vazirmatn 400/500/600/700, local font files. Outline Lucide icons 1.8px.
285px desktop sidebar; 32px content gutters; border-separated four-item metrics
strip; four horizontal service rows in one bordered container; user table.
10px surface radii; small form and icon controls share the same borders.

Allowed primary navigation/copy: سپر، نمای کلی، کاربران، سرویس‌ها، رویدادها،
سرور استکهلم، مدیریت یکپارچهٔ اتصال‌ها، افزودن کاربر، کاربران فعال، مصرف کل،
حافظه، پردازنده، جست‌وجوی کاربر، کاربر، حجم مشترک، انقضا، وضعیت، مدیریت،
حجم و انقضا بین سرویس‌های هر کاربر مشترک است.
Service labels REALITY / OpenVPN / IKEv2 / Telegram. Live data replaces concept
values and setup states. Added required controls: logout, last-poll timestamp,
edit/download icons (rather than opaque menu), accessible error states.

Required extensions using the same tokens: login, create/edit user modal,
configuration export modal, services notes, audit events, mobile collapsed rail.
Table remains horizontally scrollable on narrow displays. No fabricated metrics.

User-authorized changes after the concept: product renamed to SirGSM VPN Panel 2;
NH author mark and sirgsm.ir sponsor; three additional protocol rows; public
Telegram link dialog; bilingual LTR/RTL interface; light/dark themes; administrator
credential dialog. Dark tokens: #111923 canvas, #1a2431 rail/surfaces, #e4ebf4 text,
#9baabd muted, #324052 borders, #4ad58a semantic accent. These are intentional
extensions of the same original component/layout system, not concept mismatches.
