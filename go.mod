module github.com/incubits/deter-guard

go 1.25

// No `require` block, and that's the point: the guard uses only the Go standard library.
// ed25519, JSON, HTTP and TLS are all in there. A tool whose job is to sit in front of a
// supply-chain problem shouldn't have a dependency tree of its own to worry about.
