package main

// Root certificates for a system that has none of its own (AgentDevice#264): a cloud computer on an image without a CA
// bundle (the stock ubuntu, debian and alpine images ship without one), where the client could otherwise never verify
// NetBird's or the issuer's TLS. Go's own fallback (golang.org/x/crypto/x509roots/fallback, Mozilla's root set) is used
// by crypto/x509 only when the system's roots are missing; a system with its own trust store keeps using it.
import _ "golang.org/x/crypto/x509roots/fallback"
