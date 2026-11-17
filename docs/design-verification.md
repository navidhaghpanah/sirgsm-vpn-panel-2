# Interface verification

Reference: [original concept](../design/concept.png), generated with the built-in
Image Gen tool at 1536 × 1024. Implementation was inspected through the in-app
browser, not a static HTML approximation. Local `view_image` inspection compared
the concept and rendered Persian desktop dashboard directly; service-page
screenshots demonstrate the same component system after user-requested additions.

Verified viewports: desktop 1536 × 1024 and mobile 390 × 844. Temporary browser
viewport overrides were reset. English/Persian direction changes, theme switches,
user form fields, actual save of a disabled test account, disabled export control,
mobile navigation and sign-out were verified. Root-authorized API/protocol tests
separately verify actual account provisioning, exports and revocation.

| Comparison | Evidence and result |
| --- | --- |
| Layout | Right-hand Persian navigation rail, left-hand English rail, content header, border-separated metrics, service rows and horizontally scrollable user table match the concept's component model. |
| Typography | Bundled Vazirmatn weights and heading/body/control hierarchy checked in desktop and mobile rendering. |
| Palette | White/cool-gray/navy/emerald light theme retained; explicit navy/gray/emerald dark tokens checked for contrast and legibility. |
| Spacing and geometry | Consistent content gutters, 10px surfaces, thin separators, aligned protocol/status/port columns and common button geometry inspected. |
| Controls and icons | Outline icon family, primary add action, edit/export controls, theme/language buttons, form validation and save/sign-out states inspected. |
| Copy and branding | Original labels retained or translated. SirGSM VPN Panel 2, NH, sirgsm.ir, additional service rows and credential/theme controls are explicit user-requested changes. |
| Responsive behavior | Stable mobile layout has no document-level horizontal overflow; user table scrolls within its own container. Initial resize-transition capture was replaced with a stable screenshot. |

Above-the-fold copy audit found no unexplained marketing sections or decorative
metrics. Actual server data replaces illustrative concept numbers. Intentional
deviations: requested branding, bilingual direction, dark theme, three extra VPN
rows, active IKEv2/Telegram states, admin controls and explicit edit/download icons.
The implementation was faithfully verified against the original visual system
with these user-authorized extensions. No material visual mismatch remains in
the checked states; exhaustive assistive-technology testing is not claimed.
