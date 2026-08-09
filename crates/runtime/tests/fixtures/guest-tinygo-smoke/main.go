// Minimal TinyGo smoke fixture for MODULE-001-AC-03's "Go/TinyGo guests load
// with experimental flag (smoke test only)" clause. The fixture does NOT
// implement advance-host world exports — the AC's "smoke test only" wording
// means byte-loadable via ComponentRuntime::load_component; no instantiate,
// no call.
package main

func main() {}
