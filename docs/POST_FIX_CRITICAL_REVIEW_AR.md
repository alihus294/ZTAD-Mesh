# النقد الصريح بعد إصلاح ZTAD Mesh 4.2.0

## ما أُصلح فعليًا

- توحيد Version إلى 4.2.0 وإلغاء الادعاءات غير المرتبطة بحزمة فعلية.
- إضافة Skill مستقلة لـMulti-model mesh مع استدعاء صريح فقط.
- جعل Repository index عقدة حتمية تسبق النماذج.
- ربط DAG بنتائج Hash-addressed bounded artifacts بين العقد.
- عزل كل Writer في Worktree ونطاق مستقل، وتسلسل الكتابات المتداخلة.
- دمج Patches في Candidate commit واحد، ثم تشغيل Machine checks قبل Review.
- إعادة تصنيف Risk من Actual diff قبل السماح بالمراجعة.
- عزل Provider وBenchmark artifacts خارج Worktree وتنظيف المؤقت منها.
- رفض stale/replayed result paths.
- جعل Provider preference ترجيحًا، مع Fallback مؤهل.
- ربط Benchmark بالـCatalog hash والـSuite hash ودمج القياس مع Prior بدل استبداله من عينة واحدة.
- التحقق الصارم من Catalog values.
- ربط Approval بسجل Model run حقيقي، لا Session ID حر.
- إضافة Attempt fingerprints وProgress invariants.
- إضافة Quarantine reactivation بتغيير غير قابل لإعادة التشغيل.
- نقل مسؤولية الاستمرار من Stop hook إلى Durable scheduler/service.
- إضافة فحص AST يمنع تكرار Functions/Methods وDuplicate literal keys.
- تصحيح PR creation flow وتخفيض Host acceptance عندما لا يوجد إثبات منصة.
- إعادة كتابة الوثائق لتفصل بين Local implementation وTarget-host enforcement.

## ما زال غير مثالي — ولا يجب إخفاؤه

1. **لا يوجد ضمان مطلق:** النظام لا يستطيع إنجاز مهمة مستحيلة أو العمل عند توقف كل Providers وغياب كل Credentials.
2. **Single-host durability:** SQLite مناسبة لجهاز واحد؛ التوزيع الحقيقي بين عدة Hosts يحتاج Backend معاملاتيًا مشتركًا أو Workflow engine دائمًا.
3. **Restart خارجي:** `mesh-service` لا يعيد تشغيل نفسه بعد Crash أو Reboot؛ يلزم Windows Service أو systemd أو Supervisor خارجي.
4. **Generic providers:** أمنها يعتمد على Command template وSandbox الخاص بالـHost؛ ZTAD لا يصنع Isolation kernel-level بنفسه.
5. **Repository index محافظ وليس كاملًا:** Reflection وRuntime discovery وGenerated code وExternal event flows قد تحتاج Scout expansion أو أدوات لغة متخصصة.
6. **Model benchmarks محلية ومحدودة:** لا تثبت الذكاء العام، وقد تتقادم بعد تحديث Model أو Prompt أو Toolchain.
7. **Hosted Git/CI/CD:** لا تصبح محكومة حتى تُفحص Rulesets والChecks والEnvironments وOIDC وArtifacts على الحساب الحقيقي.
8. **Production rollout:** Progressive delivery controller يحتاج Adapter ومقاييس فعلية واختبار Rollback على منصة الهدف.
9. **Cost explosion ممكن:** Maximum useful parallelism يقلل الهدر، لكنه لا يلغي ارتفاع التكلفة في R3/R4؛ Budget policy يجب ضبطها للمشروع.
10. **False confidence من كثرة المراجعين:** سبعة Review dimensions لا تعني صحة؛ Decision لا يصبح نافذًا إلا مع الأدلة والController.
11. **Windows acceptance ما زال مطلوبًا:** الاختبارات Cross-platform لا تعوض تشغيل Native PowerShell/Codex/Git على جهاز المستخدم.
12. **Hooks ليست Security boundary وحيدة:** يمكن أن تتغير قدرة Host أو تُرفض Hooks؛ CI وSandbox وRepository rules تبقى الضبط الأعلى.

## الحكم بعد الإصلاح

```text
OFFLINE_DISTRIBUTION_ACCEPTED_WITH_TARGET_HOST_ACCEPTANCE_REQUIRED
```

النسخة تستحق الاستخدام كمنظومة Local governed mesh بعد نجاح Host acceptance وDry-run. لا تستحق بعد صلاحيات Merge/Production قبل إثبات المنصة الخارجية.

## التقييم الصريح

| المجال | التقييم |
|---|---:|
| بنية Local control plane | 9/10 |
| منع Loop وScope drift | 9/10 |
| توزيع النماذج والتوازي المفيد | 8.5/10 |
| صدق الأدلة وربط الهوية | 9/10 |
| استمرارية Host واحد | 8.5/10 |
| Multi-host HA | 3/10 |
| Hosted CI/CD الجاهز دون إعداد | 4/10 |
| Production autonomy قبل Host acceptance | NO-GO |
| Production autonomy بعد قبول المنصة واختبارات Canary/Rollback | CONDITIONAL-GO |

هذه ليست «المهارة المثالية المطلقة». هي أقوى نسخة عملية يمكن الدفاع عن ادعاءاتها محليًا، مع حدود معلنة بدل ضمانات زائفة.

## نتيجة الاختبارات النهائية بعد الإصلاح

- 223/223 اختبارًا محليًا ناجحًا.
- 44/44 تقييمًا وظيفيًا وعدائيًا Offline.
- 43,000 حالة Fuzz دون خطأ غير متحكم به.
- 320 كتابة متزامنة للسجل عبر خمس جولات 64 Writer.
- 14/14 طفرة حرجة مختارة تم قتلها؛ النسبة تخص هذه المجموعة فقط.
- تغطية Branch-aware: 80% إجمالًا و75% للنواة البرمجية.

## القيد الأكثر أهمية

بيئة البناء شغلت `cryptography 46.0.4`، بينما الإصدار يشترط `>=48.0.1,<51`. تعذر تنزيل البيئة المستهدفة بسبب فشل DNS. لذلك لا يجوز تفعيل التوقيع الحاكم قبل إعادة اختبارات التوقيع على جهاز الهدف بالإصدار المطلوب. هذا قيد إصدار حقيقي، لا ملاحظة تجميلية.
