# Quantum EDR — ML Feature Requirements

**Version:** 1.0
**Author:** AI Engineer (ML Team)
**Recipient:** Karim (Sysmon + ELK Stack)
**Purpose:** تحديد الـ features المطلوبة من pipeline الـ Sysmon/Logstash لإدخالها في الـ ML models
**Time Window الافتراضي لكل الـ aggregations:** آخر 60 ثانية لكل process

---

## ملاحظات عامة قبل البدء

1. كل feature يُحسَب **per-process** (على مستوى الـ PID الواحد في نافذة زمنية)، وليس على مستوى الـ host بالكامل.
2. الـ output النهائي لكل event يجب أن يكون **JSON object** يحتوي جميع الـ features الـ 28 أدناه.
3. الـ features التي تحتاج aggregation تعتمد على **stateful processing** في Logstash — هذا يستلزم `aggregate` filter مع `task_id` مبني على `ProcessId`.
4. الـ Sysmon config يجب أن يُفعِّل Event IDs: **1, 3, 5, 7, 11, 12, 13, 14, 22** على الأقل.

---

## Category 1 — Process Tree Features

| # | Feature Name | Description | Sysmon Event ID | Logstash Transformation | Example Value | ML Importance |
|---|---|---|---|---|---|---|
| 1 | `process_depth` | عمق الـ process في شجرة العمليات (كم parent فوقه) | **Event 1** — `ParentProcessId` chain | تتبع recursive chain من PID → ParentPID حتى PID 4 (System). العمق = عدد الخطوات | `int`, [1–15], مثال: `4` | **Critical** |
| 2 | `child_process_count` | عدد العمليات التي أطلقها هذا الـ process خلال الـ time window | **Event 1** — group by `ParentProcessId` | `aggregate` filter: count Events where `ParentProcessId == current PID` خلال 60s | `int`, [0–∞], مثال: `7` | **High** |
| 3 | `has_orphan_parent` | هل أبو العملية مات قبل ما تولد هي؟ (مؤشر process injection) | **Event 1** + **Event 5** | Cross-reference: هل `ParentProcessId` موجود في active process list وقت Event 1؟ | `int` (0 أو 1), مثال: `1` | **High** |
| 4 | `sibling_process_count` | عدد العمليات التي لها نفس الـ parent (إخوة) | **Event 1** — group by `ParentProcessId` | `aggregate` filter: count distinct PIDs sharing same `ParentProcessId` خلال 60s | `int`, [0–∞], مثال: `12` | **Medium** |

---

## Category 2 — Command Line Entropy

| # | Feature Name | Description | Sysmon Event ID | Logstash Transformation | Example Value | ML Importance |
|---|---|---|---|---|---|---|
| 5 | `cmdline_length` | طول سلسلة الـ command line | **Event 1** — `CommandLine` | `field_length` أو Ruby: `event.get('CommandLine')&.length \|\| 0` | `int`, [0–32768], مثال: `847` | **High** |
| 6 | `cmdline_entropy` | Shannon entropy لنص الـ command line (كشف التشفير والـ obfuscation) | **Event 1** — `CommandLine` | Ruby filter: حساب `H = -Σ p(c)×log2(p(c))` على character frequencies | `float`, [0.0–5.5], مثال: `4.73` لـ base64 | **Critical** |
| 7 | `has_encoded_powershell` | وجود `-EncodedCommand` أو `-enc` أو `-e` في الـ command line | **Event 1** — `CommandLine` | `grok` أو `mutate gsub` + `if` condition: regex match على `(?i)-e(nc(odedcommand)?)?` | `int` (0 أو 1), مثال: `1` | **Critical** |
| 8 | `cmdline_special_char_ratio` | نسبة الأحرف الخاصة (`^`, `` ` ``, `%`, `\|`, `&`) إلى إجمالي الأحرف | **Event 1** — `CommandLine` | Ruby: `special_chars.count / cmdline.length.to_f` | `float`, [0.0–1.0], مثال: `0.34` | **Medium** |

---

## Category 3 — Time-Based Features

| # | Feature Name | Description | Sysmon Event ID | Logstash Transformation | Example Value | ML Importance |
|---|---|---|---|---|---|---|
| 9 | `spawn_hour_of_day` | الساعة التي تولّد فيها الـ process (0–23) | **Event 1** — `@timestamp` | `date` filter → Ruby: `event.get('@timestamp').time.hour` | `int`, [0–23], مثال: `3` | **Medium** |
| 10 | `is_outside_business_hours` | هل الـ process اشتغل خارج ساعات العمل (قبل 8 أو بعد 18)؟ | **Event 1** — `@timestamp` | Ruby: `hour = ...; event.set(..., (hour < 8 \|\| hour >= 18) ? 1 : 0)` | `int` (0 أو 1), مثال: `1` | **Medium** |
| 11 | `process_lifetime_seconds` | كم ثانية عاش الـ process (من spawn حتى terminate) | **Event 1** + **Event 5** | `aggregate` filter: `task_id => ProcessId`، يحسب الفرق بين `@timestamp` للـ Event 5 والـ Event 1 | `float`, [0.0–∞], مثال: `0.43` (عملية سريعة مشبوهة) | **High** |
| 12 | `child_spawn_rate_per_minute` | معدل إطلاق العمليات الفرعية في الدقيقة | **Event 1** — group by `ParentProcessId` | `aggregate` filter: count children / elapsed_time_minutes خلال 60s | `float`, [0.0–∞], مثال: `18.0` | **High** |
| 13 | `inter_spawn_interval_ms` | متوسط الوقت بين كل child process launch والذي يليه | **Event 1** — ordered by timestamp per parent | Ruby: حساب average time diff بين consecutive Events لنفس `ParentProcessId` | `float`, [0.0–∞ ms], مثال: `50.0` (rapid spawning مشبوه) | **Medium** |

---

## Category 4 — Registry Modification Patterns

| # | Feature Name | Description | Sysmon Event ID | Logstash Transformation | Example Value | ML Importance |
|---|---|---|---|---|---|---|
| 14 | `registry_write_count` | إجمالي عمليات الكتابة على الـ registry خلال الـ time window | **Event 13** — group by `ProcessId` | `aggregate` filter: count Events 13 per PID خلال 60s | `int`, [0–∞], مثال: `47` | **High** |
| 15 | `registry_autorun_key_writes` | عدد الكتابات على مفاتيح الـ persistence الشهيرة (`Run`, `RunOnce`, `Winlogon`, `Services`) | **Event 13** — `TargetObject` | Regex match: `HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run` وما يشابهها. Count per PID | `int`, [0–∞], مثال: `2` | **Critical** |
| 16 | `registry_delete_count` | عدد عمليات حذف مفاتيح الـ registry | **Event 12** — filter `EventType == DeleteKey` | `aggregate` filter: count Event 12 DeleteKey per PID خلال 60s | `int`, [0–∞], مثال: `9` | **Medium** |
| 17 | `registry_security_key_modification` | هل عدّل الـ process مفاتيح حساسة (LSA، SAM، Security)؟ | **Event 13** — `TargetObject` | Regex match على `HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa` و `HKLM\\SAM` | `int` (0 أو 1), مثال: `1` | **Critical** |

---

## Category 5 — DLL Load Sequences

> **تنبيه لـ Karim:** يتطلب تفعيل **Event ID 7** في Sysmon config. يُنتج حجم بيانات كبير — يُنصح بفلترة العمليات الموثوقة (System32 DLLs من مسارات system) قبل الإرسال لـ Logstash.

| # | Feature Name | Description | Sysmon Event ID | Logstash Transformation | Example Value | ML Importance |
|---|---|---|---|---|---|---|
| 18 | `unsigned_dll_count` | عدد الـ DLLs غير الموقّعة التي حمّلها الـ process | **Event 7** — `Signed == false` | `aggregate` filter: count Events 7 where `Signed == "false"` per PID خلال 60s | `int`, [0–∞], مثال: `3` | **Critical** |
| 19 | `dll_from_suspicious_path` | عدد الـ DLLs المحمَّلة من مسارات مشبوهة (Temp، AppData، Downloads، Desktop) | **Event 7** — `ImageLoaded` | Grok/Mutate: استخرج المسار، check إذا يبدأ بـ `%TEMP%`, `%APPDATA%`, `%USERPROFILE%\\Downloads` | `int`, [0–∞], مثال: `2` | **Critical** |
| 20 | `dll_load_rate_per_second` | معدل تحميل الـ DLLs في الثانية | **Event 7** — group by `ProcessId` | `aggregate`: count / elapsed_seconds خلال 60s | `float`, [0.0–∞], مثال: `12.5` | **Medium** |
| 21 | `system_dll_name_from_wrong_path` | DLL باسم system DLL (مثل `kernel32.dll`) لكن من مسار غير `System32` (DLL Hijacking) | **Event 7** — `ImageLoaded` | Ruby: استخرج filename، تحقق إذا هو في قائمة system DLLs الشهيرة، وتأكد أن المسار يحتوي `system32`. إذا الاسم system لكن المسار غير ذلك → 1 | `int` (0 أو 1), مثال: `1` | **Critical** |

---

## Category 6 — Network Connection Patterns

| # | Feature Name | Description | Sysmon Event ID | Logstash Transformation | Example Value | ML Importance |
|---|---|---|---|---|---|---|
| 22 | `total_network_connections` | إجمالي الاتصالات الصادرة خلال الـ time window | **Event 3** — group by `ProcessId` | `aggregate` filter: count Events 3 per PID خلال 60s | `int`, [0–∞], مثال: `87` | **High** |
| 23 | `unique_destination_ips` | عدد IPs مختلفة تم الاتصال بها | **Event 3** — `DestinationIp` | `aggregate`: collect set of `DestinationIp` per PID → cardinality | `int`, [0–∞], مثال: `34` | **High** |
| 24 | `suspicious_port_connections` | عدد الاتصالات على منافذ مشبوهة (4444، 1337، 9999، 6666، 31337) | **Event 3** — `DestinationPort` | Translate filter أو Ruby: count Events 3 where `DestinationPort in [4444, 1337, 9999, 6666, 31337]` per PID | `int`, [0–∞], مثال: `1` | **Critical** |
| 25 | `external_ip_connection_ratio` | نسبة الاتصالات بـ IPs خارجية (non-RFC1918) | **Event 3** — `DestinationIp` | CIDR filter: عدّ IPs التي لا تقع في `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` ÷ total | `float`, [0.0–1.0], مثال: `0.92` | **High** |
| 26 | `dns_query_count` | عدد DNS queries خلال الـ time window | **Event 22** — group by `ProcessId` | `aggregate` filter: count Events 22 per PID خلال 60s | `int`, [0–∞], مثال: `23` | **Medium** |
| 27 | `dns_query_entropy` | Shannon entropy لأسماء الـ DNS queries (كشف DGA — Domain Generation Algorithms) | **Event 22** — `QueryName` | Ruby: خذ كل `QueryName` لنفس الـ PID، احسب entropy على characters لكل domain label | `float`, [0.0–5.0], مثال: `4.8` (DGA مشبوه) | **Critical** |
| 28 | `connection_rate_per_minute` | معدل الاتصالات الجديدة في الدقيقة | **Event 3** — group by `ProcessId` | `aggregate`: count / elapsed_minutes خلال 60s | `float`, [0.0–∞], مثال: `142.0` | **High** |

---

## ملاحظات تقنية مهمة (Flags)

**للـ Logstash:**
- الـ `aggregate` filter يحتاج `task_id` مبني على `[ProcessId]` وليس `[hostname]` + `[ProcessId]` لأن الـ PID يُعاد استخدامه بعد انتهاء الـ process.
- Shannon entropy يحتاج **Ruby filter** — لا يوجد built-in في Logstash لحسابها.
- `process_lifetime_seconds` يُكتب فقط بعد استقبال **Event 5** للـ process. إذا لم يصل Event 5 خلال الـ timeout (120s مثلاً)، اعتبر الـ process لا يزال شغالاً وأرسل القيمة الحالية.

**للـ Sysmon Config:**
- Event ID 7 (DLL Load) يُنتج ضجة عالية جداً — يُنصح بفلترة `System32` و `SysWOW64` من المصدر في Sysmon config قبل الإرسال.
- Event ID 22 (DNS) يتطلب تفعيله صراحةً في Sysmon config، ليس مُفعَّلاً بالإعداد الافتراضي.

**حدود Sysmon — ما لا يمكن الحصول عليه:**
- **حجم البيانات المُرسَلة** (bytes sent/received): Event 3 لا يحتوي هذه المعلومة. يحتاج network capture منفصل (Zeek/Wireshark) — خارج scope المشروع الحالي.
- **محتوى الـ network payload**: خارج نطاق Sysmon بالكامل.

---

## ملخص الـ Features حسب الأولوية

| الأولوية | Features |
|---|---|
| **Critical (9)** | `cmdline_entropy`, `has_encoded_powershell`, `registry_autorun_key_writes`, `registry_security_key_modification`, `unsigned_dll_count`, `dll_from_suspicious_path`, `system_dll_name_from_wrong_path`, `suspicious_port_connections`, `dns_query_entropy` |
| **High (10)** | `process_depth`, `child_process_count`, `has_orphan_parent`, `cmdline_length`, `process_lifetime_seconds`, `child_spawn_rate_per_minute`, `registry_write_count`, `total_network_connections`, `unique_destination_ips`, `external_ip_connection_ratio` |
| **Medium (7)** | `sibling_process_count`, `cmdline_special_char_ratio`, `spawn_hour_of_day`, `is_outside_business_hours`, `inter_spawn_interval_ms`, `registry_delete_count`, `dll_load_rate_per_second`, `dns_query_count` |
| **Low (2)** | `connection_rate_per_minute` (مكرر جزئياً مع total_connections)، `process_lifetime_seconds` إذا Event 5 غير موثوق |

---

## Minimum Viable Feature Set — Phase 1 (13 features)

إذا كان الوقت ضيقاً، هذه الـ 13 feature تكفي لـ production-quality model:

`process_depth`, `child_process_count`, `has_orphan_parent`,
`cmdline_length`, `cmdline_entropy`, `has_encoded_powershell`,
`process_lifetime_seconds`, `registry_autorun_key_writes`, `registry_security_key_modification`,
`unsigned_dll_count`, `dll_from_suspicious_path`,
`total_network_connections`, `unique_destination_ips`
