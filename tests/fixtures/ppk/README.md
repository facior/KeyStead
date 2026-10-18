Test key files in PuTTY `.ppk` format (synthetic, public test keys – never use them for anything).

Source: SSHJ v0.40.0 test resources (Apache-2.0), as frozen in the keyguard-app SSH import corpus
(`common/src/desktopTest/resources/ssh-import-corpus/ppk`). Expected public keys come from that corpus'
`public-key-goldens.tsv`, which was checked with OpenSSH `ssh-keygen`.

Passphrases: `v2-ed25519-aes256-cbc` → `123456`; `v3-rsa-argon2*-aes256-cbc` → `changeit`.
