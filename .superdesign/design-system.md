# PortSpecter design system

## Product and platform
Advanced IP discovery and port scanning desktop application for network administrators. Windows, macOS and Linux. A new independent Rust scanning engine with an Iced GUI is the proposed implementation. This Superdesign HTML artifact is a visual prototype only. All displayed scan data is illustrative.

## Direction
One primary library reference: neural-noir-interface-style, adapted to the previously discussed product brief. Retain its restrained dark surfaces and Inter UI precision. Replace its marketing layout, gold, serif headings, glass effects and oversized corners with a practical graphite and turquoise desktop workspace. Do not use marketing sections, decorative network graphs, hero typography or gradients.

## Tokens
Canvas #101316, sidebar #13171B, raised surfaces #191F24, inset #0D1114, borders #2B343C. Primary text #EDF3F6, secondary #A6B3BD. Accent #43D6C5, accent hover #6BE4D6, accent selection #173833. Success #67D9A0, warning #F2C66D, error #F08080. Status must have text or icon plus color. Fonts Inter for UI, JetBrains Mono for IP addresses, ports, counters. Sizes 12, 13, 14, 16, 20, 24px. Spacing 4, 8, 12, 16, 24, 32px. Corners 6px on controls, 8px on panels. Thin separators and subtle shadows on floating menus only. No glow or blur.

## Main scanning workspace
1440x960 desktop view. Compact 200px sidebar with PortSpecter wordmark, navigation Tarama, Cihazlar, Gecmis, Profiller and bottom Ayarlar. Use correct Turkish diacritics in the actual interface: Geçmiş. Main title Ağ taraması, subtitle explaining target discovery, secondary Yeni tarama action. Target entry 192.168.1.0/24, profile Hızlı keşif, interface Wi-Fi, expandable Gelişmiş options, clear primary scan action. During active scan show Duraklat and Durdur, avoid simultaneous contradictory Başlat state. Inline progress 61%, 156/254 targets; 24 responding devices and elapsed time. Compact filters/search above table. No oversized dashboard metric cards.

Device table left, selected device detail inspector right at 340px. Columns IP adresi, Cihaz adı, Durum, Açık port, Gecikme. At least 12 varied believable rows. Selected NAS 192.168.1.12. Inspector tabs Portlar, Bilgi, Geçmiş, four observed open ports 22 SSH, 80 HTTP, 443 HTTPS, 445 SMB, observation evidence and a secondary Ayrıntılı tara action. Service labels are illustrative observations, not guaranteed port-number identification. Bottom status bar TCP connect, progress/activity and non-disruptive errors. Preserve row selection and stable ordering during incoming results.

## Behavior and states
Keyboard focus visible, controls labeled, accessible contrast intended but must be verified in implementation. Filters, selected rows, inspector tabs and pause toggle should work with mock data where practical. Data is local mock data; never initiate network scans. No fake runtime performance claims. Empty/loading/error/cancelled states will be specified after main direction review. Narrow widths collapse inspector to a detail view and retain horizontal table scrolling. Subtle 120ms hover/focus transitions; reduced motion disables transitions. No perpetual decorative animation.

## Assets
No existing logo or brand assets supplied. Use the PortSpecter text wordmark; simple consistent outline navigation icons. No external photography needed.

## Professional refinement for version 2
Preserve the selected dark graphite/turquoise direction, typography, native-desktop practicality and master-detail layout. Improve sophistication through hierarchy, alignment, meaningful controls and information design. Keep every visible feature honest as prototype functionality.

Use a compact application title bar with PortSpecter wordmark and a workspace label, plus keyboard command search. Sidebar groups navigation under Çalışma alanı and keeps a small recent sessions section, interface context and settings anchored below. Main header identifies the selected named scan Yerel ağ keşfi with subtle scan ID and timestamp. Distinguish editable next-scan configuration from the immutable active scan parameters. Use functional target and profile controls, a protocol selector TCP / UDP, port selection and Gelişmiş disclosure; opening advanced reveals labeled timeout, retry and concurrency controls. Explain unsupported advanced modes as coming later, never as currently working.

Use one compact telemetry ribbon with 24 responding devices, 38 observed open ports, 156/254 completed targets and elapsed time, an unobtrusive progress line and active/discovery phase label. These are sample values, not benchmark claims. Keep pause and stop in one consistent location. No metric card grid.

Results toolbar offers Cihazlar / Portlar view tabs, usable search, Açık portu olan and Yeni filters, column menu and CSV export of mock data if practical. Table has selectable rows, sortable IP and latency, sticky header, 36-40px rows and clear column alignment. IP sorting must be numeric, not lexical. Include host type icons, hostname, primary address, service chips, discovery evidence and last-seen information where space allows. Prioritize readable columns; horizontal scrolling is preferable to cramped text. Maintain a selected NAS row and enough varied sample devices to fill the viewport.

Inspector has a compact device identity header, hostname nas.local, observed IP and local MAC metadata marked as sample observations, then Portlar / Bilgi / Geçmiş tabs. Show port number and protocol, observed service, short evidence, timestamp and copy actions with clear labels. A contextual comparison may show one newly observed port only if an illustrative baseline timestamp is also stated. Do not equate an open port with a vulnerability or assign unexplained risk scores.

Add an expandable bottom Etkinlik panel with a few timestamped, readable mock events rather than decorative charts. Status bar shows local-only sample session state, chosen interface and TCP connect mode. All controls must have useful mock interactions or explicitly say unavailable. No inert navigation implying completed pages. Turkish copy must use correct diacritics and concise domain language. Header, toolbar and table spacing must form a consistent alignment grid. Visible keyboard focus, restrained selected backgrounds, no arbitrary new colors. Narrow layouts hide secondary metadata and collapse inspector cleanly.
