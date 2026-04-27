module github.com/anarki/samizdat-ios/mobile

go 1.25.5

// Vendored copy of the live samizdat client/server module from llm2's
// audit-p0-fixes branch. Replace points at ./upstream-samizdat so we always
// stay in sync with what the production server actually serves (BBCR + the
// current auth_extension flow).
replace github.com/getlantern/samizdat => ./upstream-samizdat

require (
	github.com/getlantern/samizdat v0.0.0-00010101000000-000000000000
	golang.org/x/mobile v0.0.0-20260410095206-2cfb76559b7b
	gvisor.dev/gvisor v0.0.0-20260325202830-7644cf3a343c
)

require (
	github.com/andybalholm/brotli v1.1.0 // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	github.com/refraction-networking/utls v1.8.2 // indirect
	golang.org/x/crypto v0.50.0 // indirect
	golang.org/x/exp v0.0.0-20231110203233-9a3e6036ecaa // indirect
	golang.org/x/mod v0.35.0 // indirect
	golang.org/x/net v0.53.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.43.0 // indirect
	golang.org/x/text v0.36.0 // indirect
	golang.org/x/time v0.12.0 // indirect
	golang.org/x/tools v0.44.0 // indirect
)
