# Why `zk-threat-exchange` Merits Support / لماذا يستحق مشروع `zk-threat-exchange` الدعم

**Author / Maintainer — Ciprian Ștefan Pleșca**
**Organization / المؤسسة — AgentFlow Enterprise**
**Contact / التواصل:** [contact@agentflow-enterprise.com](mailto:contact@agentflow-enterprise.com)
**Support the project / لدعم المشروع:** [paypal.me/agentflowenterprise](https://paypal.me/agentflowenterprise)

---

## English

### 1. What is being funded

`zk-threat-exchange` is a research-and-engineering scaffold that integrates four normally separate disciplines into a single, working, end-to-end system: applied cryptography (a Schnorr identification protocol made non-interactive via the Fiat–Shamir heuristic), numerical/probabilistic inference (tensor scoring of attack vectors, Bayesian-style posterior risk updates), metaprogramming (detection rules represented as homoiconic S-expressions that rewrite themselves under a validated backtest gate), and distributed-systems engineering (gossip propagation, role-based API access, usage metering). The core protocol — `core-node`, `heuristics-engine`, and `rule-mutator` — is released under the MIT license and is committed to remaining open-source in perpetuity. A donation supports the maintenance of that commitment, not a paywall around it.

### 2. Why this is a legitimate case for donation rather than obligation

A donation is warranted, not owed. The project makes no claim on the donor beyond the honest description of what exists and what it costs to keep existing. Three considerations support the case:

1. **The core artifact is genuinely given away.** The cryptographic module, the inference engine, and the rule-mutation engine are functional, tested, and free to use, fork, and redeploy under MIT terms — including by organizations that never contribute a cent. A donation, in this structure, is not payment for access; it is voluntary support for continued stewardship of something already received.

2. **The stated limitations are costly to close, and closing them benefits everyone using the open core.** The project's own documentation is explicit that the demonstration-grade cryptographic group (a 31-bit Mersenne prime), the HMAC-only authentication layer, and the in-process gossip channel are not production-ready. Migrating to a cryptographically sized group or a zk-SNARK circuit, commissioning an independent security audit, and integrating a real peer-to-peer transport are precisely the kind of unglamorous, unpaid engineering work that donations are suited to fund — work that does not produce a new feature to market, but produces the trustworthiness the whole system is supposed to provide.

3. **Interdisciplinary maintenance has a real, ongoing cost.** Keeping four language ecosystems (Rust, Julia, Scheme, Go) simultaneously correct, tested, and mutually consistent — as the CI matrix and the contribution rules requiring paired documentation and regression-tested rule mutations demonstrate — is a maintenance burden considerably larger than a single-language project of comparable size.

### 3. What a donation plausibly supports

| Category | Why it matters here |
|---|---|
| Independent security audit | Explicitly identified in the project's own security policy as the prerequisite before any real-world SOC deployment |
| Migration to production-grade cryptographic parameters | Required to move beyond the documented demo-scale group toward a cryptographically sound commitment scheme |
| Real peer-to-peer transport integration | Required to move the gossip layer beyond an in-process simulation toward an actual multi-host network |
| Continued interdisciplinary maintenance | Sustains correctness across four language ecosystems and the CI/testing discipline that keeps the open core trustworthy |
| Documentation upkeep | Keeps the architectural and cryptographic reasoning legible to new contributors and auditors alike |

### 4. What a donation is not

It is not a purchase of proprietary functionality — the enterprise dashboard, SSO/RBAC, and SOC connectors are a separate, clearly delineated commercial layer, and the open core does not depend on donations to remain free. It is not a guarantee of a specific roadmap or timeline. It is, transparently, discretionary support for a maintainer keeping a genuinely open, interdisciplinary, security-relevant project alive and honestly documented, including honestly documenting what is *not yet* safe to rely on.

---

## العربية

### ١. ما الذي يجري دعمه بالتحديد

مشروع `zk-threat-exchange` هو نموذج هندسي وبحثي يدمج أربعة تخصصات منفصلة عادةً في نظام واحد متكامل وعملي من البداية إلى النهاية: التشفير التطبيقي (بروتوكول تعريف Schnorr مُحوَّل إلى صيغة غير تفاعلية عبر مبدأ Fiat–Shamir)، والاستدلال العددي/الاحتمالي (تقييم متجهات الهجوم كموترات (tensors) وتحديث المخاطر اللاحقة بأسلوب بايزي)، والبرمجة الفوقية (قواعد الكشف المُمثَّلة كتعبيرات-S متجانسة الشكل قادرة على إعادة كتابة نفسها ضمن بوابة تحقق واختبار رجعي)، وهندسة الأنظمة الموزعة (نشر إشاعي (gossip)، تحكم بالوصول قائم على الأدوار، وقياس الاستخدام). النواة الأساسية للمشروع — `core-node` و`heuristics-engine` و`rule-mutator` — مرخّصة بموجب رخصة MIT، والتزام صريح بأن تبقى مفتوحة المصدر إلى الأبد. التبرع يدعم استمرارية هذا الالتزام، وليس وسيلة لتقييده أو فرض رسوم عليه.

### ٢. لماذا هذه دعوة مشروعة للتبرع وليست التزامًا مفروضًا

التبرع أمر مُستحسَن، لا واجب. لا يطالب المشروع المتبرع بأي شيء يتجاوز الوصف الصادق لما هو موجود وتكلفة الحفاظ عليه. ثلاثة اعتبارات تدعم هذه الدعوة:

١. **العنصر الجوهري مُقدَّم مجانًا فعليًا.** الوحدة التشفيرية، ومحرك الاستدلال، ومحرك تحوير القواعد كلها عناصر عاملة ومُختبَرة ومتاحة للاستخدام والتفريع (fork) وإعادة النشر بموجب شروط MIT — حتى من قِبل جهات لم تساهم قط بأي مبلغ. التبرع، في هذا السياق، ليس ثمنًا للوصول، بل دعمٌ طوعي لاستمرار العناية بشيء تم استلامه بالفعل.

٢. **القيود المُعلَنة مكلفة الإغلاق، وإغلاقها يفيد كل مستخدمي النواة المفتوحة.** توثيق المشروع نفسه صريح في أن المجموعة التشفيرية بمستوى العرض التوضيحي (عدد ميرسين الأولي بطول ٣١ بت)، وطبقة المصادقة القائمة فقط على HMAC، وقناة النشر الإشاعي داخل العملية، جميعها ليست جاهزة للإنتاج. الانتقال إلى مجموعة ذات حجم تشفيري مناسب أو دائرة zk-SNARK، وتكليف تدقيق أمني مستقل، ودمج طبقة نقل نظير-إلى-نظير حقيقية — كل هذا عمل هندسي غير براق وغير مدفوع الأجر عادةً، وهو بالضبط النوع من العمل الذي تُخصَّص التبرعات لتمويله؛ عمل لا ينتج ميزة جديدة تُسوَّق، بل ينتج الموثوقية التي من المفترض أن يوفرها النظام بأكمله.

٣. **للصيانة متعددة التخصصات تكلفة حقيقية ومستمرة.** الحفاظ على أربع بيئات لغوية (Rust وJulia وScheme وGo) صحيحة ومُختبَرة ومتسقة فيما بينها في آن واحد — كما تُظهر مصفوفة التكامل المستمر (CI) وقواعد المساهمة التي تشترط توثيقًا مقترنًا واختبارات رجعية لتحويرات القواعد — يمثّل عبء صيانة أكبر بكثير من مشروع بلغة واحدة بحجم مماثل.

### ٣. ما الذي يدعمه التبرع على نحو معقول

| الفئة | لماذا هي مهمة هنا |
|---|---|
| تدقيق أمني مستقل | مُحدَّد صراحةً في سياسة الأمان الخاصة بالمشروع كشرط مسبق قبل أي نشر فعلي في مركز عمليات أمنية (SOC) |
| الانتقال إلى معايير تشفيرية بمستوى الإنتاج | ضروري لتجاوز المجموعة التوضيحية الحالية نحو مخطط التزام (commitment) سليم تشفيريًا |
| دمج طبقة نقل نظير-إلى-نظير حقيقية | ضروري لنقل طبقة النشر الإشاعي من محاكاة داخل العملية إلى شبكة فعلية متعددة المضيفين |
| استمرارية الصيانة متعددة التخصصات | تحافظ على الصحة عبر أربع بيئات لغوية وعلى انضباط الاختبار/التكامل المستمر الذي يُبقي النواة المفتوحة جديرة بالثقة |
| صيانة التوثيق | تُبقي المنطق المعماري والتشفيري مفهومًا للمساهمين الجدد والمدققين على حد سواء |

### ٤. ما لا يمثله التبرع

التبرع ليس شراءً لوظائف احتكارية — فلوحة التحكم الخاصة بالمؤسسات، والدخول الموحد/التحكم بالوصول القائم على الأدوار، وموصلات مراكز العمليات الأمنية تشكّل طبقة تجارية منفصلة ومحددة بوضوح، والنواة المفتوحة لا تعتمد على التبرعات لتبقى مجانية. كما أنه ليس ضمانًا لخارطة طريق أو جدول زمني محدد. إنه، بكل شفافية، دعمٌ تقديري لصيانة قائم بمشروع مفتوح المصدر فعليًا، متعدد التخصصات، ذو صلة أمنية، وللحفاظ على توثيقه بأمانة — بما في ذلك التوثيق الصادق لما لا يزال *غير آمن* للاعتماد عليه بعد.

---

*This document accompanies the project wiki (see [Home](Home), [Security & Limitations](Security-Limitations)) and reflects only what is documented elsewhere in the repository; it makes no claims beyond that record. / يرافق هذا المستند ويكي المشروع (انظر [الصفحة الرئيسية](Home) و[الأمان والقيود](Security-Limitations)) ولا يعكس سوى ما هو موثّق بالفعل في مكان آخر من المستودع، ولا يقدّم أي ادعاءات تتجاوز ذلك.*
