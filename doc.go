// Package jwt provides a small HS256 JWT helper with config injection (no viper).
//
// Design constraints:
//   - Callers inject Config; the library does not read environment variables or config files.
//   - NewClient returns Client (client_iface.go) for mocks; ConfigDefault() supplies an empty Config (Secret required).
//   - No package-level singletons; construct a Client per process or scope via NewClient.
//   - Custom claim types belong in the application layer, not in this library.
package jwt
