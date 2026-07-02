// Build-time LeakSanitizer off-switch (fleet convention, SPEC §6.2 item 15).
//
// -fsanitize=address always bundles LeakSanitizer, and there is no flag that drops only LSan. Leaks
// are not the defect class these targets are fuzzed for, and a leak-dominated defect count is
// inflated, not a finding (PR #1746). LSan consults this hook at exit, so only leak detection is
// skipped; ASan's memory-error checks and UBSan stay fully active. build.sh compiles it once with
// $SANITIZER_FLAGS $DEBUG_FLAGS and links it into both libFuzzer targets and both -standalone
// reproducers. (The test.sh oracle, mayhem-tests/roundtrip_test, does not link it: it keeps LSan on,
// which can only make the oracle stricter.)
extern "C" int __lsan_is_turned_off() { return 1; }
