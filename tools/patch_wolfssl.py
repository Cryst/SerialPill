# Run from CMakeLists.txt after project(): appends SerialPill settings to the wolfSSL Espressif template
# (managed component). On ESP32-C3 the template disables RSA, which SerialPill needs for its
# RSA-2048 SSH host key and for ssh-rsa / rsa-sha2-* client keys. Idempotent.
import os

MARK = "/* ---- SerialPill overrides ---- */"
OVERRIDES = MARK + """
#undef  WOLFSSH_NO_RSA
#undef  RSA_LOW_MEM
#undef  WOLFSSL_KEY_GEN
#define WOLFSSL_KEY_GEN           /* RSA-2048 host key generated on first boot */
#undef  WC_RSA_BLINDING
#define WC_RSA_BLINDING
#undef  HAVE_DH
#define HAVE_DH                   /* diffie-hellman-group14-sha256 for older clients */
#undef  WOLFSSL_WOLFSSH
#define WOLFSSL_WOLFSSH
#define WOLFSSH_NO_SFTP
#define WOLFSSH_NO_SCP
#define WOLFSSH_NO_AGENT
#undef  WOLFSSH_TEST_SERVER
#undef  WOLFSSH_TEST_THREADING
#undef  DEFAULT_WINDOW_SZ
#define DEFAULT_WINDOW_SZ 8192
/* ssh-ed25519 user keys */
#define HAVE_ED25519
#define HAVE_ED25519_KEY_IMPORT
#define HAVE_ED25519_KEY_EXPORT
#define WOLFSSL_ED25519_STREAMING_VERIFY
/* aes*-ctr for older clients (PuTTY < 0.76, paramiko) */
#define WOLFSSL_AES_COUNTER
#define WOLFSSL_AES_DIRECT
"""


def patch(project_dir):
    path = os.path.join(project_dir, "managed_components", "wolfssl__wolfssl", "include", "user_settings.h")
    if not os.path.exists(path):
        raise SystemExit("wolfSSL component missing: " + path)
    with open(path, encoding="utf-8") as f:
        src = f.read()
    new = src.split("\n" + MARK)[0] + "\n" + OVERRIDES
    if new == src:
        return True
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(new)
    print("SerialPill: patched wolfSSL user_settings.h")
    return True


def patch_wolfssh(project_dir):  # noqa: E302
    # pty-req with an empty terminal-modes list (paramiko/Netmiko) makes wolfSSH call malloc(0),
    # which returns NULL on ESP-IDF and kills the channel. Allocate at least one byte.
    path = os.path.join(project_dir, "managed_components", "wolfssl__wolfssh", "src", "internal.c")
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as f:
        src = f.read()
    fixes = [
        ("WMALLOC(modesSz,", "WMALLOC(modesSz ? modesSz : 1,"),
        # GetStringRef rejected an empty string as the last field of a packet (idx == len)
        ("        if (*idx < len && *strSz <= len - *idx) {\n            *str = buf + *idx;",
         "        if (*idx <= len && *strSz <= len - *idx) {\n            *str = buf + *idx;"),
    ]
    patched = src
    for old, new in fixes:
        patched = patched.replace(old, new)
    if patched != src:
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(patched)
        print("SerialPill: patched wolfSSH (empty pty modes)")


try:
    Import("env")  # noqa: F821  (PlatformIO/SCons)
    patch(env.subst("$PROJECT_DIR"))  # noqa: F821
    patch_wolfssh(env.subst("$PROJECT_DIR"))  # noqa: F821
except NameError:
    import sys
    patch(sys.argv[1] if len(sys.argv) > 1 else ".")
    patch_wolfssh(sys.argv[1] if len(sys.argv) > 1 else ".")
