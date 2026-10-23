#!/usr/bin/env python3
import argparse
import base64
import hashlib
import json
import logging
import os
import re
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request
from multiprocessing.pool import ThreadPool
from pathlib import Path
from queue import Empty, Queue
from threading import Thread

log = logging.getLogger("emudhra")
URL = "https://emudhra.we-have-a-problem.com/impacted-intermediates.json"
FETCH_TIMEOUT = 5

# Source: https://emudhra.we-have-a-problem.com/impacted-intermediates.json
# Snapshot: 2026-10-21; JSON SHA256: f67b3abe9b4879f4e91874ed041beccd71257f1db41c588c724ccf12aa90c59e
IMPACTED = [
    {
        "name": "EM DV TLS CA - G3B",
        "sha256": [
            "42c4accd12c4f59597925e1a08a7a90102608543809308d50ec427e118ba1493",
            "45a883f349aedfd5f3a649b5498ffb121712ba8b448f3f2a91dbc5a766fcddbe",
        ],
        "spki": "ebed6475c2c2d80fcb199f3fe8dd6e6b3ce60b77eb15d4e42c3dec0c6f5b5105",
        "ski": "e21e2fe71c19390e554b62c120245735248a2514",
        "subject": "303f310b3009060355040613024e4c31133011060355040a0c0a654d7564687261204256311b301906035504030c12454d20445620544c53204341202d20473342",
    },
    {
        "name": "EM OV TLS CA - G3B",
        "sha256": [
            "98b896625c0c230adeec3eb2cf6aad5001ecf9156a68644e82374ce5833bc25b",
            "5f1ded4dd590af74631290cf073b122a2aac6a1fa479778a0bd43579bd832699",
        ],
        "spki": "43bffa19d6ef651451f6841e019931e96f6f2eaeff28ab4b6f1ce4576de2717b",
        "ski": "9bd86551afe7e72c37ad08ee6919d9bf3784ae0a",
        "subject": "303f310b3009060355040613024e4c31133011060355040a0c0a654d7564687261204256311b301906035504030c12454d204f5620544c53204341202d20473342",
    },
    {
        "name": "EM EV TLS CA - G3B",
        "sha256": [
            "e7568fe6e12331f4fd7de61da4c7559d0f8eb192a218d4741a3ba75184333838",
            "579480aea166290bd3c643589e795fc0d0e54e86505d180f1dff99efd3199512",
        ],
        "spki": "e0254c7fcdc265e2f0f8a428dabb75ab4ae039b4872d62f5ee57f0877d5a8a41",
        "ski": "3edc20d9894698877b873fd88147b25c15d84706",
        "subject": "303f310b3009060355040613024e4c31133011060355040a0c0a654d7564687261204256311b301906035504030c12454d20455620544c53204341202d20473342",
    },
    {
        "name": "EM DV TLS CA - G3C",
        "sha256": [
            "0164d7ceae5bb909c272af151ff44b1177ae9b47d9424b94f1d9558c30934d19",
            "62b7f9868263f72f6911fc78ceaf72c1979158b7368bf648683bb2aa39b02e72",
        ],
        "spki": "49dd353dc2b919a3770645117d0e60c16115e7d1bc259eefe734b00ea434fe5f",
        "ski": "ae7e105c3c2996c1a847270559f1e03dd4e50af3",
        "subject": "3040310b300906035504061302555331143012060355040a0c0b654d756468726120496e63311b301906035504030c12454d20445620544c53204341202d20473343",
    },
    {
        "name": "EM OV TLS CA - G3C",
        "sha256": [
            "cb6e15165ac802e9b3f993f16c25d41f4e81c21ebde71ae1b012ac00bf9c7c3f",
            "7485b51c0ed192878fa1d2f948fb529ae1842cc5086c4b67f7be5b2039de9489",
        ],
        "spki": "63ecefee431d49523bc1136c4e72d0206a477086caf606cd5cf025686c109cf8",
        "ski": "34eaea0cebc90adaf9d0c5e2ed9b78c9879e1b6c",
        "subject": "3040310b300906035504061302555331143012060355040a0c0b654d756468726120496e63311b301906035504030c12454d204f5620544c53204341202d20473343",
    },
    {
        "name": "EM EV TLS CA - G3C",
        "sha256": [
            "432ec25f0d28de9006d97bf752f17bbb2cd41f669933fcb072d9a1148d0261f3",
            "fd9d5c2dbbd4995ab69b8d50c439d9527b00529199c2fd01b2174eb58f07021f",
        ],
        "spki": "5c0660a2b164910d8ff589c18e14552e9e0ec237dcefe2cb736d41a4811f81a0",
        "ski": "a6255e80a94db7f3967c1bc791df92bcee4beb5f",
        "subject": "3040310b300906035504061302555331143012060355040a0c0b654d756468726120496e63311b301906035504030c12454d20455620544c53204341202d20473343",
    },
    {
        "name": "EM OV CS CA - G3B",
        "sha256": [
            "9e39de2881273acc225a149c72ba3e0f51424963669ab633ee1dc7df5db067b4",
            "a496e23ac0cab8155fc9b117b97eae368efcbb9041aec8804d5a308d2d01c2d8",
        ],
        "spki": "ec4ffa1ad0ac88081314b7aaffef6a91f97cd57291bb5ba686c5415f5eb4f6b6",
        "ski": "79fae8eccfdb0d758da458d69fb6eddc7c49dee6",
        "subject": "303e310b3009060355040613024e4c31133011060355040a0c0a654d7564687261204256311a301806035504030c11454d204f56204353204341202d20473342",
    },
    {
        "name": "EM OV CS CA - G3C",
        "sha256": [
            "4b2460a466f95fd40113bcdcca2ceb29b3b093921de45474da7df48874c630b1",
            "84112972b8e59d14560ae7e7119654474aad119990cf3722bfc1e3b91615e1fd",
        ],
        "spki": "92c063d67e8f14db71d288e11266ffdaf69cbf115f7bab14f3bc2f68d25e0e30",
        "ski": "ee6f73298d6fbfa7b31bc39534f61556447866b7",
        "subject": "303f310b300906035504061302555331143012060355040a0c0b654d756468726120496e63311a301806035504030c11454d204f56204353204341202d20473343",
    },
]
LIMIT = 16 * 1024 * 1024
PEM = re.compile(
    rb"-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----", re.S
)
SUFFIXES = {".pem", ".crt", ".cer", ".der"}
UNSUPPORTED = {".p7b", ".p7c", ".p12", ".pfx", ".jks", ".keystore"}


def tlvs(data):
    """Read bounded DER tag/length/value fields; reject indefinite lengths."""
    pos = 0
    while pos < len(data):
        start = pos
        if pos + 2 > len(data):
            raise ValueError("truncated DER header")
        tag, size = data[pos : pos + 2]
        pos += 2
        if tag & 31 == 31:
            raise ValueError("unsupported DER tag")
        if size & 128:
            count = size & 127
            if not 1 <= count <= 4 or pos + count > len(data):
                raise ValueError("invalid DER length")
            size = int.from_bytes(data[pos : pos + count], "big")
            pos += count
        end = pos + size
        if end > len(data):
            raise ValueError("truncated DER value")
        yield tag, data[start:end], data[pos:end]
        pos = end


def unwrap(data, tag):
    fields = list(tlvs(data))
    if len(fields) != 1 or fields[0][0] != tag:
        raise ValueError("unexpected DER structure")
    return fields[0][2]


def common_name(subject):
    names = []
    codecs = {
        0x0C: "utf-8",
        0x13: "ascii",
        0x16: "ascii",
        0x1E: "utf-16-be",
        0x1C: "utf-32-be",
    }
    for tag, _, rdn in tlvs(unwrap(subject, 0x30)):
        if tag != 0x31:
            raise ValueError("invalid subject RDN")
        for tag, _, attribute in tlvs(rdn):
            fields = list(tlvs(attribute))
            if tag != 0x30 or len(fields) != 2 or fields[0][0] != 6:
                raise ValueError("invalid subject attribute")
            if fields[0][2] == b"\x55\x04\x03":  # commonName
                string_tag, _, value = fields[1]
                # Preserve unsupported legacy string encodings as hex.
                names.append(
                    value.decode(codecs[string_tag])
                    if string_tag in codecs
                    else "#" + value.hex()
                )
    return " / ".join(names) if names else "(absent)"


def certificate(der):
    fields = list(tlvs(unwrap(der, 0x30)))
    if [f[0] for f in fields] != [0x30, 0x30, 0x03]:
        raise ValueError("not an X.509 certificate")
    tbs = list(tlvs(fields[0][2]))
    if tbs and tbs[0][0] == 0xA0:
        tbs = tbs[1:]
    if [f[0] for f in tbs[:6]] != [0x02, 0x30, 0x30, 0x30, 0x30, 0x30]:
        raise ValueError("invalid TBSCertificate")
    result = {
        "cn": common_name(tbs[4][1]),
        "sha256": hashlib.sha256(der).hexdigest(),
        "spki": hashlib.sha256(tbs[5][1]).hexdigest(),
        "issuer": tbs[2][1],
        "subject": tbs[4][1],
        "aki": None,
        "ski": None,
    }
    for tag, _, value in tbs[6:]:
        if tag != 0xA3:
            continue
        for ext_tag, _, ext_value in tlvs(unwrap(value, 0x30)):
            ext = list(tlvs(ext_value))
            if (
                ext_tag != 0x30
                or len(ext) not in (2, 3)
                or ext[0][0] != 6
                or ext[-1][0] != 4
            ):
                raise ValueError("invalid certificate extension")
            oid, value = ext[0][2], ext[-1][2]
            if oid == b"\x55\x1d\x0e":  # SubjectKeyIdentifier
                result["ski"] = unwrap(value, 4)
            elif oid == b"\x55\x1d\x23":  # AuthorityKeyIdentifier
                for key_tag, _, key_value in tlvs(unwrap(value, 0x30)):
                    if key_tag == 0x80:
                        result["aki"] = key_value
    return result


def certificates(data):
    blocks = PEM.findall(data)
    if data.count(b"-----BEGIN CERTIFICATE-----") != len(blocks):
        raise ValueError("incomplete PEM certificate")
    if blocks:
        for block in blocks:
            yield base64.b64decode(re.sub(rb"\s+", b"", block), validate=True)
    elif data.startswith(b"\x30"):
        yield data
    elif b"PRIVATE KEY-----" not in data and b"PUBLIC KEY-----" not in data:
        raise ValueError("no PEM/DER certificate found")


def read_limited(stream):
    data = stream.read(LIMIT + 1)
    if len(data) > LIMIT:
        raise ValueError("file exceeds 16 MiB limit")
    return data


def fetch_reference():
    # A socket timeout alone does not bound DNS or the total response time.
    result = Queue(maxsize=1)

    def fetch():
        try:
            with urllib.request.urlopen(URL, timeout=FETCH_TIMEOUT) as stream:
                result.put((read_limited(stream), None))
        except Exception as exc:
            result.put((None, exc))

    Thread(target=fetch, daemon=True).start()
    try:
        data, error = result.get(timeout=FETCH_TIMEOUT)
    except Empty:
        raise TimeoutError("reference download exceeded 5 seconds") from None
    if error is not None:
        raise error
    return data


def load_reference(online):
    rows = IMPACTED
    if online:
        data = fetch_reference()
        source = json.loads(data)
        if not isinstance(source, list) or not source:
            raise ValueError("reference must be a nonempty JSON array")
        rows = []
        for row in source:
            blocks = list(certificates(row["pem"].encode("ascii")))
            if len(blocks) != 1:
                raise ValueError("reference entry must contain one certificate")
            cert = certificate(blocks[0])
            if cert["sha256"] != row["sha256"].lower():
                raise ValueError("reference PEM and SHA256 disagree")
            rows.append(
                {
                    "name": row["name"],
                    "sha256": [cert["sha256"]],
                    "spki": cert["spki"],
                    "ski": (cert["ski"] or b"").hex(),
                    "subject": cert["subject"].hex(),
                }
            )
        log.info("Online reference: JSON SHA256=%s", hashlib.sha256(data).hexdigest())
    else:
        log.info("Using embedded incident identifiers from 2026-10-21 (offline)")
    return (
        (
            "certificate SHA256",
            "sha256",
            {sha: r["name"] for r in rows for sha in r["sha256"]},
        ),
        ("SPKI SHA256", "spki", {r["spki"]: r["name"] for r in rows}),
        (
            "issuer DER",
            "issuer",
            {bytes.fromhex(r["subject"]): r["name"] for r in rows},
        ),
        (
            "issuer key ID",
            "aki",
            {bytes.fromhex(r["ski"]): r["name"] for r in rows if r["ski"]},
        ),
    )


def default_paths():
    defaults = ssl.get_default_verify_paths()
    paths = [
        defaults.cafile,
        defaults.capath,
        "/etc/ssl/certs",
        "/etc/pki/tls/certs",
        "/etc/pki/ca-trust/extracted/pem",
        "/usr/share/ca-certificates",
        "/usr/local/share/ca-certificates",
    ]
    return list(dict.fromkeys(Path(p) for p in paths if p and Path(p).exists()))


def candidates(paths, error):
    for path in paths:
        if path.is_dir():
            for directory, _, names in os.walk(path, onerror=error):
                for name in sorted(names):
                    item = Path(directory) / name
                    if item.suffix.lower() in SUFFIXES | UNSUPPORTED or re.fullmatch(
                        r"[0-9a-fA-F]{8}\.\d+", name
                    ):
                        yield item
        else:
            yield path


def certificate_jobs(paths, error):
    seen = set()
    for path in candidates(paths, error):
        try:
            info = path.stat()
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("not a regular file")
            inode = (info.st_dev, info.st_ino)
            if inode in seen:
                continue
            seen.add(inode)
            if path.suffix.lower() in UNSUPPORTED:
                raise ValueError("unsupported certificate store; export to PEM")
            with path.open("rb") as stream:
                data = read_limited(stream)
            for index, der in enumerate(certificates(data), 1):
                yield path, index, der
        except (OSError, ValueError) as exc:
            error("{}: {}".format(path, exc))


def parse_job(job):
    path, index, der = job
    try:
        cert = certificate(der)
    except ValueError as exc:
        return path, index, None, str(exc)
    log.info(
        "Parsed CN=%r SHA256=%s file=%s certificate=#%d",
        cert["cn"],
        cert["sha256"],
        path,
        index,
    )
    return path, index, cert, None


def scan_local(args):
    try:
        refs = load_reference(args.online)
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        log.error("Cannot load reference: %s", exc)
        return 2

    errors = []

    def error(message):
        errors.append(str(message))
        log.error("%s", message)

    paths = args.paths or ([args.cafile] if args.cafile else default_paths())
    log.info("Paths: %s", ", ".join(map(str, paths)) or "(none)")
    scanned = 0
    with ThreadPool(args.workers) as pool:
        for path, index, cert, failure in pool.imap_unordered(
            parse_job, certificate_jobs(paths, error)
        ):
            if failure is not None:
                error("{} certificate #{}: {}".format(path, index, failure))
                continue
            scanned += 1
            hits = [
                "{}: {}".format(lookup[cert[key]], label)
                for label, key, lookup in refs
                if cert[key] in lookup
            ]
            if hits:
                log.error(
                    "MATCH CN=%r SHA256=%s file=%s certificate=#%d reasons=%r",
                    cert["cn"],
                    cert["sha256"],
                    path,
                    index,
                    hits,
                )
                return 1
    if not scanned:
        error("no certificates checked")
    log.info("Checked: %d; matched: 0; errors: %d", scanned, len(errors))
    return 2 if errors else 0


HOSTS = tuple(
    f"{kind}-{generation}{cross_sign}-emudhra.we-have-a-problem.com"
    for kind in ("dv", "ov", "ev")
    for generation in ("g3b", "g3c")
    for cross_sign in ("", "-aaa")
)
CHAIN_PEM = re.compile(
    r"-----BEGIN CERTIFICATE-----\s*.*?\s*-----END CERTIFICATE-----", re.S
)
VERIFY_ERROR = re.compile(r"^error (\d+) at \d+ depth lookup:", re.M)
# Missing issuer, self-signed chain, untrusted or explicitly rejected CA.
TRUST_ERRORS = {2, 19, 20, 21, 27, 28}


class TrustChecker:
    def __init__(self, executable="openssl", cafile=None):
        self.executable = executable
        self.trust_args = []
        version = self.run("version")
        if version.returncode or not version.stdout.startswith("OpenSSL "):
            raise ValueError("OpenSSL required: " + version.stdout.strip())
        self.version = version.stdout.strip()

        if cafile is not None:
            self.trust_args = ["-CAfile", str(cafile.resolve()), "-no-CApath"]
            # OpenSSL 1.1.1 has no CAstore; 3.x+ must disable it as well.
            if "-no-CAstore" in self.run("verify", "-help").stdout:
                self.trust_args.append("-no-CAstore")

    def run(self, *args, data=None):
        return subprocess.run(
            [self.executable, *args],
            check=False,
            input=data,
            stdin=subprocess.DEVNULL if data is None else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=10,
            env={**os.environ, "LC_ALL": "C"},
        )

    def check_dates(self, path):
        """Check every supplied certificate, even if chain building fails early."""
        data = path.read_text(encoding="ascii")
        blocks = CHAIN_PEM.findall(data)
        if not blocks or CHAIN_PEM.sub("", data).strip():
            raise ValueError(f"{path}: invalid PEM certificate bundle")

        now = time.time()
        for index, block in enumerate(blocks, 1):
            result = self.run("x509", "-noout", "-dates", data=block)
            if result.returncode:
                raise ValueError(result.stdout.strip())
            dates = dict(line.split("=", 1) for line in result.stdout.splitlines())
            start = ssl.cert_time_to_seconds(dates["notBefore"])
            end = ssl.cert_time_to_seconds(dates["notAfter"])
            if not start <= now <= end:
                raise ValueError(
                    f"{path.name} certificate #{index}: outside validity period "
                    f"({dates['notBefore']} .. {dates['notAfter']}); refresh fixtures"
                )

    def verify(self, path, hostname=None):
        self.check_dates(path)
        # A root used as the control is not itself a TLS server certificate.
        purpose = "sslserver" if hostname is not None else "any"
        args = ["verify", "-show_chain", "-purpose", purpose, *self.trust_args]
        if hostname is not None:
            # Only CAfile/CApath/CAstore supply trust. These intermediates do not.
            args.extend(["-verify_hostname", hostname, "-untrusted", str(path)])
        result = self.run(*args, str(path))
        if result.returncode == 0:
            return "ACCEPTED", result.stdout.strip()

        errors = {int(code) for code in VERIFY_ERROR.findall(result.stdout)}
        if result.returncode == 2 and errors and errors <= TRUST_ERRORS:
            return "UNTRUSTED", result.stdout.strip()
        return "UNKNOWN", result.stdout.strip()


def check_safely(checker, path, hostname=None):
    try:
        return checker.verify(path, hostname)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        return "UNKNOWN", str(exc)


def check_tls_trust(args):
    accepted = 0
    unknown = False
    try:
        checker = TrustChecker(args.openssl, args.cafile)
        log.info("TLS checker: %s", checker.version)
        log.info("TLS store: %s", args.cafile or "OpenSSL defaults")
        for name in ("SSL_CERT_FILE", "SSL_CERT_DIR"):
            if name in os.environ:
                log.info(
                    "%s=%s%s",
                    name,
                    os.environ[name],
                    " (ignored by --cafile)" if args.cafile else "",
                )
        with tempfile.TemporaryDirectory(prefix="emudhra-check-") as temporary:
            directory = Path(temporary)
            for name, pem in CERTIFICATES.items():
                (directory / name).write_text(pem, encoding="ascii")
            control_path = (
                args.control.resolve() if args.control else directory / "control.pem"
            )
            control, detail = check_safely(checker, control_path)
            unknown = control != "ACCEPTED"
            if unknown:
                log.error("TLS control: FAILED\n%s", detail)
            else:
                log.info("TLS control: OK")
            for hostname in HOSTS:
                status, detail = check_safely(
                    checker, directory / (hostname + ".pem"), hostname
                )
                if status == "ACCEPTED":
                    accepted += 1
                    log.error("TLS ACCEPTED: %s\n%s", hostname, detail)
                elif status == "UNTRUSTED":
                    log.info("TLS UNTRUSTED: %s", hostname)
                else:
                    unknown = True
                    log.error("TLS UNKNOWN: %s\n%s", hostname, detail)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        unknown = True
        log.error("TLS check incomplete: %s", exc)
    if accepted:
        log.error(
            "TLS UNSAFE: %d/%d test chains accepted; incomplete=%s",
            accepted,
            len(HOSTS),
            unknown,
        )
        return 1
    if unknown:
        log.error("TLS INCONCLUSIVE: control failed or checks could not complete")
        return 2
    log.info("TLS BLOCKED: all %d test chains untrusted; control OK", len(HOSTS))
    return 0


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "paths",
        nargs="*",
        type=Path,
        help="local scan only; default: --cafile or existing system CA paths",
    )
    parser.add_argument(
        "--online",
        action="store_true",
        help="fetch current incident identifiers (5-second total timeout); fixtures stay embedded",
    )
    parser.add_argument(
        "--workers", type=int, default=4, help="certificate parser threads (default: 4)"
    )
    parser.add_argument(
        "--openssl", default="openssl", help="OpenSSL executable (1.1.1+)"
    )
    parser.add_argument(
        "--cafile", type=Path, help="use only this PEM bundle for TLS trust"
    )
    parser.add_argument(
        "--control",
        type=Path,
        help="known trusted control certificate; default: ISRG Root X1",
    )
    args = parser.parse_args()
    if args.workers < 1:
        parser.error("--workers must be positive")
    trust_code = check_tls_trust(args)
    scan_code = scan_local(args)
    if 1 in (trust_code, scan_code):
        log.error("UNSAFE: accepted TLS test chain or local incident match")
        return 1
    if 2 in (trust_code, scan_code):
        log.error("INCONCLUSIVE: at least one check is incomplete")
        return 2
    log.info("PASS: no local matches; all TLS test chains untrusted; control OK")
    return 0


CERTIFICATES = {
    "dv-g3b-aaa-emudhra.we-have-a-problem.com.pem": """-----BEGIN CERTIFICATE-----
MIICQDCCAcagAwIBAgIUU3mgjls/8ZJ8upmukdlSQR1IF/UwCgYIKoZIzj0EAwIw
PzELMAkGA1UEBhMCTkwxEzARBgNVBAoMCmVNdWRocmEgQlYxGzAZBgNVBAMMEkVN
IERWIFRMUyBDQSAtIEczQjAeFw0yNjEwMjAwMjIyNDFaFw0yNzA1MDMwMjI3NDFa
MDMxMTAvBgNVBAMMKGR2LWczYi1hYWEtZW11ZGhyYS53ZS1oYXZlLWEtcHJvYmxl
bS5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATK3sfcOxxtM2Vdq9Qbw/GR
NsHlJcnqINEInXO3fkWhw/FYT80hkqGk0jSN/EKib3YZJsr5GyfkYcpEiA2rwMgm
o4GrMIGoMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoG
CCsGAQUFBwMBMDMGA1UdEQQsMCqCKGR2LWczYi1hYWEtZW11ZGhyYS53ZS1oYXZl
LWEtcHJvYmxlbS5jb20wHQYDVR0OBBYEFDggfJFz1eeToKmzFBSYkMCvpAu0MB8G
A1UdIwQYMBaAFOIeL+ccGTkOVUtiwSAkVzUkiiUUMAoGCCqGSM49BAMCA2gAMGUC
MDqDDOt7K313QIH0rhn/ZKnzFu8+/9W8OlTuFtDfVCTRDfRmqdyfsCfLsEk7xqHq
uQIxAJqyLERABmU98U46OCuT5bp5h0ytuSEIGM7orTpKci5S1u1B/AOmwv162U7R
TcVPHA==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDzjCCAragAwIBAgIRAKAk/fS6Zlx4XOSgIEg4WLcwDQYJKoZIhvcNAQELBQAw
ezELMAkGA1UEBhMCR0IxGzAZBgNVBAgMEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G
A1UEBwwHU2FsZm9yZDEaMBgGA1UECgwRQ29tb2RvIENBIExpbWl0ZWQxITAfBgNV
BAMMGEFBQSBDZXJ0aWZpY2F0ZSBTZXJ2aWNlczAeFw0yNTA1MTQwMDAwMDBaFw0y
ODEyMzEyMzU5NTlaMD8xCzAJBgNVBAYTAk5MMRMwEQYDVQQKDAplTXVkaHJhIEJW
MRswGQYDVQQDDBJFTSBEViBUTFMgQ0EgLSBHM0IwdjAQBgcqhkjOPQIBBgUrgQQA
IgNiAATnntnASpdzxHNeUREdqFrCvV5kqzdLgOEsvCA47B5PDjuBL8mFnh5nr7BO
L4vJf3SFumWqkR7opORbYtXMA9Vr5nizw4y03JN8okYOI4RTyJKTXSnUT5HhVga2
PM7atGijggE1MIIBMTAfBgNVHSMEGDAWgBSgEQojPpbxB+zirynvgqV/0DCktDAd
BgNVHQ4EFgQU4h4v5xwZOQ5VS2LBICRXNSSKJRQwDgYDVR0PAQH/BAQDAgEGMBIG
A1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMC
MDEGA1UdIAQqMCgwCAYGZ4EMAQIBMA0GCysGAQQBg44hAQABMA0GCysGAQQBg44h
AQJkMEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwuY29tb2RvY2EuY29tL0FB
QUNlcnRpZmljYXRlU2VydmljZXMuY3JsMDQGCCsGAQUFBwEBBCgwJjAkBggrBgEF
BQcwAYYYaHR0cDovL29jc3AuY29tb2RvY2EuY29tMA0GCSqGSIb3DQEBCwUAA4IB
AQBzQ1IoqpdotM6gFrR4Q3YrKifOLeaj5XXunldpVE/vZn2TxC2y0s8oYiLR5ICE
wqVXSB7N6BM1Mp+Nif7Jbhb2IswAfSR4Iik8+B0iRmi7lYoNlycCgHjmsjOmZaxM
QkPmjXAJbG5f4V41OsvJZmS7lI3r0IuvEDVX3GAZ13on6IImSs9ybNpHQ7NCqkMQ
7wH4uAO1dtpFycgJSdHaCOhHjrox2BTYGLdpUrYwY3EOAjlZ8UGgsxs7mG+xquMl
bN1LFURwfnkVMP3T/DBIZ/ys2+lNFyxK3FlArrV4/000uTnVB1lO8oGORYdXoT5V
GUyRCEIDhF5TBUuKF4E3kf1h
-----END CERTIFICATE-----
""",
    "dv-g3b-emudhra.we-have-a-problem.com.pem": """-----BEGIN CERTIFICATE-----
MIICOTCCAb6gAwIBAgIUY1R/PHrtXShV0uhLJ5EyjsHvMi0wCgYIKoZIzj0EAwIw
PzELMAkGA1UEBhMCTkwxEzARBgNVBAoMCmVNdWRocmEgQlYxGzAZBgNVBAMMEkVN
IERWIFRMUyBDQSAtIEczQjAeFw0yNjEwMjAwMDU5MzZaFw0yNzA1MDMwMTA0MzZa
MC8xLTArBgNVBAMMJGR2LWczYi1lbXVkaHJhLndlLWhhdmUtYS1wcm9ibGVtLmNv
bTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABFpE24ACBFHQLzpg+7D767thJ3+Q
NIoJJugUMT/OftEz6G6uDdxlS+9VfXYBDglHjJirjEPFNglOGJoQNQuiz7Gjgacw
gaQwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYB
BQUHAwEwLwYDVR0RBCgwJoIkZHYtZzNiLWVtdWRocmEud2UtaGF2ZS1hLXByb2Js
ZW0uY29tMB0GA1UdDgQWBBT4r5v4etYNuG21BqBqs273OkcHiDAfBgNVHSMEGDAW
gBTiHi/nHBk5DlVLYsEgJFc1JIolFDAKBggqhkjOPQQDAgNpADBmAjEAlxNF+/8l
APpgibawACy15yn5bcvTksz2Zw0R9z9nUK9e3MSSk+hXagg7LVb7V4NtAjEA4qyR
laFPkaokrnTjqQieq8CgDQ6tIz3FjBvj3D7vkhKXHaml6zD2zT5ih2Y+lD2h
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDaDCCAu6gAwIBAgIQAKSu5njyM2K0wORgt3LyFDAKBggqhkjOPQQDAzBWMQsw
CQYDVQQGEwJJTjElMCMGA1UECgwcZU11ZGhyYSBUZWNobm9sb2dpZXMgTGltaXRl
ZDEgMB4GA1UEAwwXZW1TaWduIFJvb3QgVExTIENBIC0gRzMwHhcNMjUwNDMwMTU1
NDA4WhcNNDAwNDI4MTgzMDAwWjA/MQswCQYDVQQGEwJOTDETMBEGA1UECgwKZU11
ZGhyYSBCVjEbMBkGA1UEAwwSRU0gRFYgVExTIENBIC0gRzNCMHYwEAYHKoZIzj0C
AQYFK4EEACIDYgAE557ZwEqXc8RzXlERHahawr1eZKs3S4DhLLwgOOweTw47gS/J
hZ4eZ6+wTi+LyX90hbplqpEe6KTkW2LVzAPVa+Z4s8OMtNyTfKJGDiOEU8iSk10p
1E+R4VYGtjzO2rRoo4IBljCCAZIwHwYDVR0jBBgwFoAU4TqrIXzx401UrtRyt/2L
WUIgkFQwHQYDVR0OBBYEFOIeL+ccGTkOVUtiwSAkVzUkiiUUMB0GA1UdJQQWMBQG
CCsGAQUFBwMBBggrBgEFBQcDAjBdBgNVHSAEVjBUMDkGCysGAQQBg44hAQABMCow
KAYIKwYBBQUHAgEWHGh0dHA6Ly9yZXBvc2l0b3J5LmVtc2lnbi5jb20wDQYLKwYB
BAGDjiEBAmQwCAYGZ4EMAQIBMHUGCCsGAQUFBwEBBGkwZzAkBggrBgEFBQcwAYYY
aHR0cDovL29jc3AtYi5lbXNpZ24uY29tMD8GCCsGAQUFBzAChjNodHRwOi8vcmVw
b3NpdG9yeS5lbXNpZ24uY29tL2NlcnRzL0VNRFZUTFNDQUczQi5wN2MwNwYDVR0f
BDAwLjAsoCqgKIYmaHR0cDovL2NybC5lbXNpZ24uY29tLz9yb290dGxzY2FnMy5j
cmwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwCgYIKoZIzj0E
AwMDaAAwZQIwLmsGXi6oFMJ2klkcEMXMug6gvxQWZWkewiDWVzQyl2L6z6DuQfPO
Ibh1grvdULDCAjEAxZvLlxUavG69J6wnSjC8XBbqNIQsJ6CE2QdNOe84Ptxb6VG8
gt2TlfJbHii+KNvK
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDdDCCAvmgAwIBAgIQAJYaPvsTWVdu0EAFtGhKWzAKBggqhkjOPQQDAzBrMQsw
CQYDVQQGEwJJTjETMBEGA1UECxMKZW1TaWduIFBLSTElMCMGA1UEChMcZU11ZGhy
YSBUZWNobm9sb2dpZXMgTGltaXRlZDEgMB4GA1UEAxMXZW1TaWduIEVDQyBSb290
IENBIC0gRzMwHhcNMjQwNzExMTU0MzM2WhcNMzkwNzA5MTgzMDAwWjBWMQswCQYD
VQQGEwJJTjElMCMGA1UECgwcZU11ZGhyYSBUZWNobm9sb2dpZXMgTGltaXRlZDEg
MB4GA1UEAwwXZW1TaWduIFJvb3QgVExTIENBIC0gRzMwdjAQBgcqhkjOPQIBBgUr
gQQAIgNiAARfD9w/q1cWxL6D9bMGH6CQ4u+gAV6GN9s+PwQx9Bl4hC+0iU8QOk8m
WO/RwXQy10DCSxT8vSIJClHKp+Ao4qJKdYeV0SwZ7LMQziyLfxIUOY6Grja/sQFw
LKYf8EdDXAyjggF1MIIBcTAfBgNVHSMEGDAWgBR8XQKEE9TMipuBzhccLikenEhj
QjAdBgNVHQ4EFgQU4TqrIXzx401UrtRyt/2LWUIgkFQwHQYDVR0lBBYwFAYIKwYB
BQUHAwEGCCsGAQUFBwMCMD0GA1UdIAQ2MDQwMgYEVR0gADAqMCgGCCsGAQUFBwIB
FhxodHRwOi8vcmVwb3NpdG9yeS5lbXNpZ24uY29tMHgGCCsGAQUFBwEBBGwwajAi
BggrBgEFBQcwAYYWaHR0cDovL29jc3AuZW1zaWduLmNvbTBEBggrBgEFBQcwAoY4
aHR0cDovL3JlcG9zaXRvcnkuZW1zaWduLmNvbS9jZXJ0cy9lbVNpZ25FQ0NSb290
Q0FHMy5jcnQwMwYDVR0fBCwwKjAooCagJIYiaHR0cDovL2NybC5lbXNpZ24uY29t
P1Jvb3RDQUczLmNybDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIB
ATAKBggqhkjOPQQDAwNpADBmAjEAt9CIpRGp46QHQYDUBnLKw+vvK0/h9vmilEAg
TroUl/anH4x2rXHqiCtBTBfgKDegAjEA8WpG1LTZdAIL0FSYqxXeREaeTSxEofM0
1jJH3jGvCXC79LU9UPJ2o3TU+UIj2gMV
-----END CERTIFICATE-----
""",
    "dv-g3c-aaa-emudhra.we-have-a-problem.com.pem": """-----BEGIN CERTIFICATE-----
MIICQjCCAcegAwIBAgIUMH3z62Z6agEULBZqrfhpw9/ZpCAwCgYIKoZIzj0EAwIw
QDELMAkGA1UEBhMCVVMxFDASBgNVBAoMC2VNdWRocmEgSW5jMRswGQYDVQQDDBJF
TSBEViBUTFMgQ0EgLSBHM0MwHhcNMjYxMDIwMDIyMjQxWhcNMjcwNTAzMDIyNzQx
WjAzMTEwLwYDVQQDDChkdi1nM2MtYWFhLWVtdWRocmEud2UtaGF2ZS1hLXByb2Js
ZW0uY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAMPpHsQqEqIerrj/durO
EN7gkUVJSVgIPN6+VJ2sEGXDyqXAN1fnNzGuASP/4WEr0RIhht3cYvuUYp2SYofr
w6OBqzCBqDAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAK
BggrBgEFBQcDATAzBgNVHREELDAqgihkdi1nM2MtYWFhLWVtdWRocmEud2UtaGF2
ZS1hLXByb2JsZW0uY29tMB0GA1UdDgQWBBT8CNQz4OLVnIwrQYZBF+++9jTCvzAf
BgNVHSMEGDAWgBSufhBcPCmWwahHJwVZ8eA91OUK8zAKBggqhkjOPQQDAgNpADBm
AjEAp3ZLdfBvKcZxgR2p8LZaxWzP6uB7zU/EZ9BA49Ds2P5ByYkRodwK5qcwt4J/
VL/vAjEAnnxrcrDX7SzoJxuho604GBh6eyBLJLCdmcy+qb+LA3u5oxP/OjAzCA4x
v1kw6Tm4
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDzzCCAregAwIBAgIRAJHzR/Glt9OZYrleDuTimdEwDQYJKoZIhvcNAQELBQAw
ezELMAkGA1UEBhMCR0IxGzAZBgNVBAgMEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G
A1UEBwwHU2FsZm9yZDEaMBgGA1UECgwRQ29tb2RvIENBIExpbWl0ZWQxITAfBgNV
BAMMGEFBQSBDZXJ0aWZpY2F0ZSBTZXJ2aWNlczAeFw0yNTA1MTQwMDAwMDBaFw0y
ODEyMzEyMzU5NTlaMEAxCzAJBgNVBAYTAlVTMRQwEgYDVQQKDAtlTXVkaHJhIElu
YzEbMBkGA1UEAwwSRU0gRFYgVExTIENBIC0gRzNDMHYwEAYHKoZIzj0CAQYFK4EE
ACIDYgAEOnp4YsjETTJN3WkDOmeCwO/u/kBV5ooSP6A3G6O9kZRRTuFypDPjYw8C
vRiAN9nlFJ+bd9uUooHfmHsv6oiLdL3+j9pMEJnubKGVZv4+8OX2sJpVbMyLpQVh
3xsqRB0Bo4IBNTCCATEwHwYDVR0jBBgwFoAUoBEKIz6W8Qfs4q8p74Klf9AwpLQw
HQYDVR0OBBYEFK5+EFw8KZbBqEcnBVnx4D3U5QrzMA4GA1UdDwEB/wQEAwIBBjAS
BgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcD
AjAxBgNVHSAEKjAoMAgGBmeBDAECATANBgsrBgEEAYOOIQEAATANBgsrBgEEAYOO
IQECZDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsLmNvbW9kb2NhLmNvbS9B
QUFDZXJ0aWZpY2F0ZVNlcnZpY2VzLmNybDA0BggrBgEFBQcBAQQoMCYwJAYIKwYB
BQUHMAGGGGh0dHA6Ly9vY3NwLmNvbW9kb2NhLmNvbTANBgkqhkiG9w0BAQsFAAOC
AQEAr7b6Mx11TIJgVzHt6EH5qGNWeiiqoMrp8E5/k8s+jvupx1n083pZ5XOzUzND
wEUe0W4C4FIGUHNQ4XDwqOw0yK42xqm2dvCKgsko2UvDlT0haZVtTCeWMQOe5J/J
ziaMfZwsZNfZ3aaI6XPtWDZtwY8AaNfyaeCpbtm5GcGnyNWk4jSNpbtpo6NjfXuP
CFOm3rTjJ4zytP7Tso6iMm0L01cYFOlTmoPv4515R2r3SPnKDtijoB/D/vgxzojv
DafgyG9afX8+laO9NbMMz4sqC1vZx3984i/sBNFiugm3Vvdq5OdJRjuGC1QILIs6
dg/K3i8VQqRpbfaM9kIlMzZ3dQ==
-----END CERTIFICATE-----
""",
    "dv-g3c-emudhra.we-have-a-problem.com.pem": """-----BEGIN CERTIFICATE-----
MIICODCCAb+gAwIBAgIUbWvtwSNK/Qro223vAqyz323+VBAwCgYIKoZIzj0EAwIw
QDELMAkGA1UEBhMCVVMxFDASBgNVBAoMC2VNdWRocmEgSW5jMRswGQYDVQQDDBJF
TSBEViBUTFMgQ0EgLSBHM0MwHhcNMjYxMDIwMDA1OTM2WhcNMjcwNTAzMDEwNDM2
WjAvMS0wKwYDVQQDDCRkdi1nM2MtZW11ZGhyYS53ZS1oYXZlLWEtcHJvYmxlbS5j
b20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAScdBQpNUOOCcag6YEVFccNRSFe
UIl02iH53vDfoWPJFS005WzqF3CPDclB/kygP2gWF4pg/r5gPYdnI3/6Vdzro4Gn
MIGkMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsG
AQUFBwMBMC8GA1UdEQQoMCaCJGR2LWczYy1lbXVkaHJhLndlLWhhdmUtYS1wcm9i
bGVtLmNvbTAdBgNVHQ4EFgQUBj2yGO/TzDOE/u/6QeUvcW8y1iMwHwYDVR0jBBgw
FoAUrn4QXDwplsGoRycFWfHgPdTlCvMwCgYIKoZIzj0EAwIDZwAwZAIwBQOOQqG9
ccdzM/7XIlXLtota1esALaLmgEN/ZweosBIvk4xabHcERZInWVIwO45NAjBos8Ue
NwDe1X3ahdK2lkxqBEoBMtUHJN18TnJKs2nK1gmXpMbmY5oKnAQQgCEZPA4=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDaDCCAu6gAwIBAgIPWIsuPCu4zaE+GhIJJUMhMAoGCCqGSM49BAMDMFYxCzAJ
BgNVBAYTAklOMSUwIwYDVQQKDBxlTXVkaHJhIFRlY2hub2xvZ2llcyBMaW1pdGVk
MSAwHgYDVQQDDBdlbVNpZ24gUm9vdCBUTFMgQ0EgLSBHMzAeFw0yNTA0MzAxNTM1
MDlaFw00MDA0MjgxODMwMDBaMEAxCzAJBgNVBAYTAlVTMRQwEgYDVQQKDAtlTXVk
aHJhIEluYzEbMBkGA1UEAwwSRU0gRFYgVExTIENBIC0gRzNDMHYwEAYHKoZIzj0C
AQYFK4EEACIDYgAEOnp4YsjETTJN3WkDOmeCwO/u/kBV5ooSP6A3G6O9kZRRTuFy
pDPjYw8CvRiAN9nlFJ+bd9uUooHfmHsv6oiLdL3+j9pMEJnubKGVZv4+8OX2sJpV
bMyLpQVh3xsqRB0Bo4IBljCCAZIwHwYDVR0jBBgwFoAU4TqrIXzx401UrtRyt/2L
WUIgkFQwHQYDVR0OBBYEFK5+EFw8KZbBqEcnBVnx4D3U5QrzMB0GA1UdJQQWMBQG
CCsGAQUFBwMBBggrBgEFBQcDAjBdBgNVHSAEVjBUMDkGCysGAQQBg44hAQABMCow
KAYIKwYBBQUHAgEWHGh0dHA6Ly9yZXBvc2l0b3J5LmVtc2lnbi5jb20wDQYLKwYB
BAGDjiEBAmQwCAYGZ4EMAQIBMHUGCCsGAQUFBwEBBGkwZzAkBggrBgEFBQcwAYYY
aHR0cDovL29jc3AtYy5lbXNpZ24uY29tMD8GCCsGAQUFBzAChjNodHRwOi8vcmVw
b3NpdG9yeS5lbXNpZ24uY29tL2NlcnRzL0VNRFZUTFNDQUczQy5wN2MwNwYDVR0f
BDAwLjAsoCqgKIYmaHR0cDovL2NybC5lbXNpZ24uY29tLz9yb290dGxzY2FnMy5j
cmwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwCgYIKoZIzj0E
AwMDaAAwZQIxAMEN2HWMocbuWdy1d33pH6JpMvP/V/DIS5PtZbv1Q7TXEbxrcyxg
yuddOJscYDJJlAIwB4sH1BpbScDzkdD4tJBSwrG/1Mx82vb8YaySehNuu1+1oXNd
AEKwaJ0mVzScy2+6
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDdDCCAvmgAwIBAgIQAJYaPvsTWVdu0EAFtGhKWzAKBggqhkjOPQQDAzBrMQsw
CQYDVQQGEwJJTjETMBEGA1UECxMKZW1TaWduIFBLSTElMCMGA1UEChMcZU11ZGhy
YSBUZWNobm9sb2dpZXMgTGltaXRlZDEgMB4GA1UEAxMXZW1TaWduIEVDQyBSb290
IENBIC0gRzMwHhcNMjQwNzExMTU0MzM2WhcNMzkwNzA5MTgzMDAwWjBWMQswCQYD
VQQGEwJJTjElMCMGA1UECgwcZU11ZGhyYSBUZWNobm9sb2dpZXMgTGltaXRlZDEg
MB4GA1UEAwwXZW1TaWduIFJvb3QgVExTIENBIC0gRzMwdjAQBgcqhkjOPQIBBgUr
gQQAIgNiAARfD9w/q1cWxL6D9bMGH6CQ4u+gAV6GN9s+PwQx9Bl4hC+0iU8QOk8m
WO/RwXQy10DCSxT8vSIJClHKp+Ao4qJKdYeV0SwZ7LMQziyLfxIUOY6Grja/sQFw
LKYf8EdDXAyjggF1MIIBcTAfBgNVHSMEGDAWgBR8XQKEE9TMipuBzhccLikenEhj
QjAdBgNVHQ4EFgQU4TqrIXzx401UrtRyt/2LWUIgkFQwHQYDVR0lBBYwFAYIKwYB
BQUHAwEGCCsGAQUFBwMCMD0GA1UdIAQ2MDQwMgYEVR0gADAqMCgGCCsGAQUFBwIB
FhxodHRwOi8vcmVwb3NpdG9yeS5lbXNpZ24uY29tMHgGCCsGAQUFBwEBBGwwajAi
BggrBgEFBQcwAYYWaHR0cDovL29jc3AuZW1zaWduLmNvbTBEBggrBgEFBQcwAoY4
aHR0cDovL3JlcG9zaXRvcnkuZW1zaWduLmNvbS9jZXJ0cy9lbVNpZ25FQ0NSb290
Q0FHMy5jcnQwMwYDVR0fBCwwKjAooCagJIYiaHR0cDovL2NybC5lbXNpZ24uY29t
P1Jvb3RDQUczLmNybDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIB
ATAKBggqhkjOPQQDAwNpADBmAjEAt9CIpRGp46QHQYDUBnLKw+vvK0/h9vmilEAg
TroUl/anH4x2rXHqiCtBTBfgKDegAjEA8WpG1LTZdAIL0FSYqxXeREaeTSxEofM0
1jJH3jGvCXC79LU9UPJ2o3TU+UIj2gMV
-----END CERTIFICATE-----
""",
    "ev-g3b-aaa-emudhra.we-have-a-problem.com.pem": """-----BEGIN CERTIFICATE-----
MIICQDCCAcagAwIBAgIUUYu3O8bpN1GPvCIHqWpT/FYUNDowCgYIKoZIzj0EAwIw
PzELMAkGA1UEBhMCTkwxEzARBgNVBAoMCmVNdWRocmEgQlYxGzAZBgNVBAMMEkVN
IEVWIFRMUyBDQSAtIEczQjAeFw0yNjEwMjAwMjIyNDFaFw0yNzA1MDMwMjI3NDFa
MDMxMTAvBgNVBAMMKGV2LWczYi1hYWEtZW11ZGhyYS53ZS1oYXZlLWEtcHJvYmxl
bS5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASjDLpnVdmvXM6R3UB2o42a
1GnrYfxRXo7UII36mBl9mIS7p9MkAryhPdxitFHkgTrrbypVtzpydNtJIGGGXUwE
o4GrMIGoMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoG
CCsGAQUFBwMBMDMGA1UdEQQsMCqCKGV2LWczYi1hYWEtZW11ZGhyYS53ZS1oYXZl
LWEtcHJvYmxlbS5jb20wHQYDVR0OBBYEFEVBY1ecTN9bLMDl4ifdnN2WZL+WMB8G
A1UdIwQYMBaAFD7cINmJRpiHe4c/2IFHslwV2EcGMAoGCCqGSM49BAMCA2gAMGUC
MQCyvr9gktgmtsuTuFleFV+YExNNKLf3GZieuUprQcERrzh798oYKavTqZeYf9Kz
RhECMCVs1B7KPh7/lgHRly14Z8RJA8ApR7e2cRREW5uPKFOSDlZ/RIezxsfEzsQ4
lAODeA==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDzTCCArWgAwIBAgIRANj4aF5PK9nYJAKoWhwetzEwDQYJKoZIhvcNAQELBQAw
ezELMAkGA1UEBhMCR0IxGzAZBgNVBAgMEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G
A1UEBwwHU2FsZm9yZDEaMBgGA1UECgwRQ29tb2RvIENBIExpbWl0ZWQxITAfBgNV
BAMMGEFBQSBDZXJ0aWZpY2F0ZSBTZXJ2aWNlczAeFw0yNTA1MTQwMDAwMDBaFw0y
ODEyMzEyMzU5NTlaMD8xCzAJBgNVBAYTAk5MMRMwEQYDVQQKDAplTXVkaHJhIEJW
MRswGQYDVQQDDBJFTSBFViBUTFMgQ0EgLSBHM0IwdjAQBgcqhkjOPQIBBgUrgQQA
IgNiAAQl26haZNOX2gsQUunqVG5Ie+/qnJ2daKDF6tz+73Wmm7XW/AH0K/vKbrQL
zWTAdn42/9Bdl6gTxaoMbJUw55z18IZkaPE4BkIKpchRhAseJSVA55DktlTDhS7W
SvHoZX2jggE0MIIBMDAfBgNVHSMEGDAWgBSgEQojPpbxB+zirynvgqV/0DCktDAd
BgNVHQ4EFgQUPtwg2YlGmId7hz/YgUeyXBXYRwYwDgYDVR0PAQH/BAQDAgEGMBIG
A1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMC
MDAGA1UdIAQpMCcwBwYFZ4EMAQEwDQYLKwYBBAGDjiEBAAEwDQYLKwYBBAGDjiEB
AngwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybC5jb21vZG9jYS5jb20vQUFB
Q2VydGlmaWNhdGVTZXJ2aWNlcy5jcmwwNAYIKwYBBQUHAQEEKDAmMCQGCCsGAQUF
BzABhhhodHRwOi8vb2NzcC5jb21vZG9jYS5jb20wDQYJKoZIhvcNAQELBQADggEB
AJNFuAFW9Gnw/8+kCO4KIlZdnM1Sh2u+8cK0EYAHhXpb5FlGvYkcARigo5oS7VoM
7FOYlTueV6yICZKNAYawZPJPhNCGK+rp3cQBEz6d0n8OZEYZov9lb3ll8ORgSDuf
FVIW6Gagg/UnOamLBTOR8eD5V73SCme/B2cHUDw+m5E8cc+0Ujzz3Cn3ex5JrhXk
2T3s8PoVzEmhTgGboFfcWO1EYhPPrYwdxPYRQIXAXUXhLEOVNL9ASbZJLFI8E1IM
m7NwxVN2s38jWpaCUaaF0tg7hfiy7oe13rzJfHsdqldJVTTUTPWVx8TC4ju0VLet
bAlwhwFT6AP8uIVMGUHNw24=
-----END CERTIFICATE-----
""",
    "ev-g3b-emudhra.we-have-a-problem.com.pem": """-----BEGIN CERTIFICATE-----
MIICNzCCAb6gAwIBAgIUPfthO0PYGAYKs9lQ4gp1IOkOr2MwCgYIKoZIzj0EAwIw
PzELMAkGA1UEBhMCTkwxEzARBgNVBAoMCmVNdWRocmEgQlYxGzAZBgNVBAMMEkVN
IEVWIFRMUyBDQSAtIEczQjAeFw0yNjEwMjAwMDU5MzZaFw0yNzA1MDMwMTA0MzZa
MC8xLTArBgNVBAMMJGV2LWczYi1lbXVkaHJhLndlLWhhdmUtYS1wcm9ibGVtLmNv
bTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABPZPwlA3io/AX/pMwu0dNl9WMxrr
C9j/xMLHgG72cWVzoX62REmvp9zyXQ04kHP9/sW6KnCcm5ZZ5i4YoJbDPASjgacw
gaQwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYB
BQUHAwEwLwYDVR0RBCgwJoIkZXYtZzNiLWVtdWRocmEud2UtaGF2ZS1hLXByb2Js
ZW0uY29tMB0GA1UdDgQWBBSvX4QR4ERW5uNUaMq0yYzXCZf0ZjAfBgNVHSMEGDAW
gBQ+3CDZiUaYh3uHP9iBR7JcFdhHBjAKBggqhkjOPQQDAgNnADBkAjACy/uJR01M
/O9IEZyRHX1LSU28bmg542K0IX9jDRTrZXUqkDWfiZIL7xfnrRrBpHoCMFbBIaOa
WwWtFtDg9ZqQvktsWS950u5qfW1sChgWNya/E3IMKFgtoHm2xrZsmfwLSQ==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDaDCCAu2gAwIBAgIQAMfEHv6S2CXwXq6EGkqCwTAKBggqhkjOPQQDAzBWMQsw
CQYDVQQGEwJJTjElMCMGA1UECgwcZU11ZGhyYSBUZWNobm9sb2dpZXMgTGltaXRl
ZDEgMB4GA1UEAwwXZW1TaWduIFJvb3QgVExTIENBIC0gRzMwHhcNMjUwNDMwMTYw
MzMxWhcNNDAwNDI4MTgzMDAwWjA/MQswCQYDVQQGEwJOTDETMBEGA1UECgwKZU11
ZGhyYSBCVjEbMBkGA1UEAwwSRU0gRVYgVExTIENBIC0gRzNCMHYwEAYHKoZIzj0C
AQYFK4EEACIDYgAEJduoWmTTl9oLEFLp6lRuSHvv6pydnWigxerc/u91ppu11vwB
9Cv7ym60C81kwHZ+Nv/QXZeoE8WqDGyVMOec9fCGZGjxOAZCCqXIUYQLHiUlQOeQ
5LZUw4Uu1krx6GV9o4IBlTCCAZEwHwYDVR0jBBgwFoAU4TqrIXzx401UrtRyt/2L
WUIgkFQwHQYDVR0OBBYEFD7cINmJRpiHe4c/2IFHslwV2EcGMB0GA1UdJQQWMBQG
CCsGAQUFBwMBBggrBgEFBQcDAjBcBgNVHSAEVTBTMDkGCysGAQQBg44hAQABMCow
KAYIKwYBBQUHAgEWHGh0dHA6Ly9yZXBvc2l0b3J5LmVtc2lnbi5jb20wDQYLKwYB
BAGDjiEBAngwBwYFZ4EMAQEwdQYIKwYBBQUHAQEEaTBnMCQGCCsGAQUFBzABhhho
dHRwOi8vb2NzcC1iLmVtc2lnbi5jb20wPwYIKwYBBQUHMAKGM2h0dHA6Ly9yZXBv
c2l0b3J5LmVtc2lnbi5jb20vY2VydHMvRU1FVlRMU0NBRzNCLnA3YzA3BgNVHR8E
MDAuMCygKqAohiZodHRwOi8vY3JsLmVtc2lnbi5jb20vP3Jvb3R0bHNjYWczLmNy
bDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADAKBggqhkjOPQQD
AwNpADBmAjEA9Jq999oaOUKhFwopw33iCmt0OHIn3gjT43GfuOHR/YckXdwoNdDA
lIEhz0NgRO3/AjEAvY/a3OMvktIZLYjn+WLKmp0QhrIMV+e6EpS7j4GVeOKouNp6
MN/P+ByGeiRMghzB
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDdDCCAvmgAwIBAgIQAJYaPvsTWVdu0EAFtGhKWzAKBggqhkjOPQQDAzBrMQsw
CQYDVQQGEwJJTjETMBEGA1UECxMKZW1TaWduIFBLSTElMCMGA1UEChMcZU11ZGhy
YSBUZWNobm9sb2dpZXMgTGltaXRlZDEgMB4GA1UEAxMXZW1TaWduIEVDQyBSb290
IENBIC0gRzMwHhcNMjQwNzExMTU0MzM2WhcNMzkwNzA5MTgzMDAwWjBWMQswCQYD
VQQGEwJJTjElMCMGA1UECgwcZU11ZGhyYSBUZWNobm9sb2dpZXMgTGltaXRlZDEg
MB4GA1UEAwwXZW1TaWduIFJvb3QgVExTIENBIC0gRzMwdjAQBgcqhkjOPQIBBgUr
gQQAIgNiAARfD9w/q1cWxL6D9bMGH6CQ4u+gAV6GN9s+PwQx9Bl4hC+0iU8QOk8m
WO/RwXQy10DCSxT8vSIJClHKp+Ao4qJKdYeV0SwZ7LMQziyLfxIUOY6Grja/sQFw
LKYf8EdDXAyjggF1MIIBcTAfBgNVHSMEGDAWgBR8XQKEE9TMipuBzhccLikenEhj
QjAdBgNVHQ4EFgQU4TqrIXzx401UrtRyt/2LWUIgkFQwHQYDVR0lBBYwFAYIKwYB
BQUHAwEGCCsGAQUFBwMCMD0GA1UdIAQ2MDQwMgYEVR0gADAqMCgGCCsGAQUFBwIB
FhxodHRwOi8vcmVwb3NpdG9yeS5lbXNpZ24uY29tMHgGCCsGAQUFBwEBBGwwajAi
BggrBgEFBQcwAYYWaHR0cDovL29jc3AuZW1zaWduLmNvbTBEBggrBgEFBQcwAoY4
aHR0cDovL3JlcG9zaXRvcnkuZW1zaWduLmNvbS9jZXJ0cy9lbVNpZ25FQ0NSb290
Q0FHMy5jcnQwMwYDVR0fBCwwKjAooCagJIYiaHR0cDovL2NybC5lbXNpZ24uY29t
P1Jvb3RDQUczLmNybDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIB
ATAKBggqhkjOPQQDAwNpADBmAjEAt9CIpRGp46QHQYDUBnLKw+vvK0/h9vmilEAg
TroUl/anH4x2rXHqiCtBTBfgKDegAjEA8WpG1LTZdAIL0FSYqxXeREaeTSxEofM0
1jJH3jGvCXC79LU9UPJ2o3TU+UIj2gMV
-----END CERTIFICATE-----
""",
    "ev-g3c-aaa-emudhra.we-have-a-problem.com.pem": """-----BEGIN CERTIFICATE-----
MIICQDCCAcegAwIBAgIUTMUrGzSU+0BySFdrN3ALZq9Spv8wCgYIKoZIzj0EAwIw
QDELMAkGA1UEBhMCVVMxFDASBgNVBAoMC2VNdWRocmEgSW5jMRswGQYDVQQDDBJF
TSBFViBUTFMgQ0EgLSBHM0MwHhcNMjYxMDIwMDIyMjQyWhcNMjcwNTAzMDIyNzQy
WjAzMTEwLwYDVQQDDChldi1nM2MtYWFhLWVtdWRocmEud2UtaGF2ZS1hLXByb2Js
ZW0uY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEglClDbotLFFeY9SpryT4
k958tvriY2DDnaPsmjQaecRhB6+L/8hLw6FMt+HT8SLvjIZnFY+AH92cBjedcNST
AKOBqzCBqDAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAK
BggrBgEFBQcDATAzBgNVHREELDAqgihldi1nM2MtYWFhLWVtdWRocmEud2UtaGF2
ZS1hLXByb2JsZW0uY29tMB0GA1UdDgQWBBSVtGbn6xUT1iosUeaGA15Nq640aTAf
BgNVHSMEGDAWgBSmJV6AqU2385Z8G8eR35K87kvrXzAKBggqhkjOPQQDAgNnADBk
AjAg7b5bIK9X50QEX0U6G8fQh12BnFQ079Iluzd0Y2TJWCjtVXZi3nOciM8RzNKM
tZECMCBf0JOyMt8RNS93Wj8kYbWkCtoKoUrqx7G3JTfGReKci+DdTvkF8/3F6doi
9KB22Q==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDzTCCArWgAwIBAgIQBfB4dS3s56G7hZXTAxZxcTANBgkqhkiG9w0BAQsFADB7
MQswCQYDVQQGEwJHQjEbMBkGA1UECAwSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYD
VQQHDAdTYWxmb3JkMRowGAYDVQQKDBFDb21vZG8gQ0EgTGltaXRlZDEhMB8GA1UE
AwwYQUFBIENlcnRpZmljYXRlIFNlcnZpY2VzMB4XDTI1MDUxNDAwMDAwMFoXDTI4
MTIzMTIzNTk1OVowQDELMAkGA1UEBhMCVVMxFDASBgNVBAoMC2VNdWRocmEgSW5j
MRswGQYDVQQDDBJFTSBFViBUTFMgQ0EgLSBHM0MwdjAQBgcqhkjOPQIBBgUrgQQA
IgNiAAQtVugppvuCxkpGl9lgr5UekGeukfkm00MG2kioqut4abamfm0nQm4EQqoD
s24ZiN/2NlFO4c8H9bpLP/KgZkWufTHVhmrTGqPSRusLMXfumct1ZsUWznSAimaP
kfDEf8qjggE0MIIBMDAfBgNVHSMEGDAWgBSgEQojPpbxB+zirynvgqV/0DCktDAd
BgNVHQ4EFgQUpiVegKlNt/OWfBvHkd+SvO5L618wDgYDVR0PAQH/BAQDAgEGMBIG
A1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMC
MDAGA1UdIAQpMCcwBwYFZ4EMAQEwDQYLKwYBBAGDjiEBAAEwDQYLKwYBBAGDjiEB
AngwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybC5jb21vZG9jYS5jb20vQUFB
Q2VydGlmaWNhdGVTZXJ2aWNlcy5jcmwwNAYIKwYBBQUHAQEEKDAmMCQGCCsGAQUF
BzABhhhodHRwOi8vb2NzcC5jb21vZG9jYS5jb20wDQYJKoZIhvcNAQELBQADggEB
AIFfHiaMSjnrdZygRYV4ekRBmG7ybcFk4hGQWMMyMFi0cAEk2+dGfz5bl8IaIbLq
z+uVJzhOgVEX7WqIfgbWfFsfPYHYjPHBmy7SlZ3BwA86IQ6qF/etpX2/qL9A5yRN
N3nVowUpaqV6H3aCpkAh3wR2ZNkvAbLDvPz3J0l+sEWjWv+ZISOV4R+hXDTdPXV0
1lKxnbwqEsdo/sE2QkCDKwFrZh/0uKjWspydJj+jSaDLTrGNx50Dgmn7VEcD1ZI5
FXjknVUiO25YlmS1dtVZSBbyUKSjlrP/yDwPcZunoAsmCAAtCKsFLviLaymzvsKI
eSSDGxpSySp2VCxompGDk8g=
-----END CERTIFICATE-----
""",
    "ev-g3c-emudhra.we-have-a-problem.com.pem": """-----BEGIN CERTIFICATE-----
MIICOTCCAb+gAwIBAgIUOcw5N4XGLiB/3GvB05bJuGoZPR0wCgYIKoZIzj0EAwIw
QDELMAkGA1UEBhMCVVMxFDASBgNVBAoMC2VNdWRocmEgSW5jMRswGQYDVQQDDBJF
TSBFViBUTFMgQ0EgLSBHM0MwHhcNMjYxMDIwMDA1OTM3WhcNMjcwNTAzMDEwNDM3
WjAvMS0wKwYDVQQDDCRldi1nM2MtZW11ZGhyYS53ZS1oYXZlLWEtcHJvYmxlbS5j
b20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQo7U02MAUO8EEMomXwIl+kSQzm
b+nvXKIZ/hC4rZ1GpXchv4SzTrV1SB/Qg+pD6OBEXbBBnPmQNkePNQTlujqRo4Gn
MIGkMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsG
AQUFBwMBMC8GA1UdEQQoMCaCJGV2LWczYy1lbXVkaHJhLndlLWhhdmUtYS1wcm9i
bGVtLmNvbTAdBgNVHQ4EFgQUqxe+7qS+MxNyioJZhQsL5MEEw6swHwYDVR0jBBgw
FoAUpiVegKlNt/OWfBvHkd+SvO5L618wCgYIKoZIzj0EAwIDaAAwZQIwC/CxSIov
wcar3sV98B8cL+QuR2kkJdLdXsFKzg/HDSJ1MOjqTGm924LB6r9nl0f7AjEAzcwr
WQOYY9eycqIz+LG2daYS6LOctj+CjoAk/CLugWPxGxp4Aerfau2P1z1h5jAA
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDaDCCAu6gAwIBAgIQAIAJkopkEHYBrwX6LxnxCTAKBggqhkjOPQQDAzBWMQsw
CQYDVQQGEwJJTjElMCMGA1UECgwcZU11ZGhyYSBUZWNobm9sb2dpZXMgTGltaXRl
ZDEgMB4GA1UEAwwXZW1TaWduIFJvb3QgVExTIENBIC0gRzMwHhcNMjUwNDMwMTUz
OTMxWhcNNDAwNDI4MTgzMDAwWjBAMQswCQYDVQQGEwJVUzEUMBIGA1UECgwLZU11
ZGhyYSBJbmMxGzAZBgNVBAMMEkVNIEVWIFRMUyBDQSAtIEczQzB2MBAGByqGSM49
AgEGBSuBBAAiA2IABC1W6Cmm+4LGSkaX2WCvlR6QZ66R+SbTQwbaSKiq63hptqZ+
bSdCbgRCqgOzbhmI3/Y2UU7hzwf1uks/8qBmRa59MdWGatMao9JG6wsxd+6Zy3Vm
xRbOdICKZo+R8MR/yqOCAZUwggGRMB8GA1UdIwQYMBaAFOE6qyF88eNNVK7Ucrf9
i1lCIJBUMB0GA1UdDgQWBBSmJV6AqU2385Z8G8eR35K87kvrXzAdBgNVHSUEFjAU
BggrBgEFBQcDAQYIKwYBBQUHAwIwXAYDVR0gBFUwUzA5BgsrBgEEAYOOIQEAATAq
MCgGCCsGAQUFBwIBFhxodHRwOi8vcmVwb3NpdG9yeS5lbXNpZ24uY29tMA0GCysG
AQQBg44hAQJ4MAcGBWeBDAEBMHUGCCsGAQUFBwEBBGkwZzAkBggrBgEFBQcwAYYY
aHR0cDovL29jc3AtYy5lbXNpZ24uY29tMD8GCCsGAQUFBzAChjNodHRwOi8vcmVw
b3NpdG9yeS5lbXNpZ24uY29tL2NlcnRzL0VNRVZUTFNDQUczQy5wN2MwNwYDVR0f
BDAwLjAsoCqgKIYmaHR0cDovL2NybC5lbXNpZ24uY29tLz9yb290dGxzY2FnMy5j
cmwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwCgYIKoZIzj0E
AwMDaAAwZQIwBy1wTnzH4lXDTy2PD91ysLjvnlVN3JbJmc1BIMEU8TOLkYVHibMc
9HeyonikFSfmAjEA6uE3QRxlrZTz/1/lXPTEMUhoauAtycagtlNFp79kjhvNa2/f
Aal1GNxsOutLnr0Y
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDdDCCAvmgAwIBAgIQAJYaPvsTWVdu0EAFtGhKWzAKBggqhkjOPQQDAzBrMQsw
CQYDVQQGEwJJTjETMBEGA1UECxMKZW1TaWduIFBLSTElMCMGA1UEChMcZU11ZGhy
YSBUZWNobm9sb2dpZXMgTGltaXRlZDEgMB4GA1UEAxMXZW1TaWduIEVDQyBSb290
IENBIC0gRzMwHhcNMjQwNzExMTU0MzM2WhcNMzkwNzA5MTgzMDAwWjBWMQswCQYD
VQQGEwJJTjElMCMGA1UECgwcZU11ZGhyYSBUZWNobm9sb2dpZXMgTGltaXRlZDEg
MB4GA1UEAwwXZW1TaWduIFJvb3QgVExTIENBIC0gRzMwdjAQBgcqhkjOPQIBBgUr
gQQAIgNiAARfD9w/q1cWxL6D9bMGH6CQ4u+gAV6GN9s+PwQx9Bl4hC+0iU8QOk8m
WO/RwXQy10DCSxT8vSIJClHKp+Ao4qJKdYeV0SwZ7LMQziyLfxIUOY6Grja/sQFw
LKYf8EdDXAyjggF1MIIBcTAfBgNVHSMEGDAWgBR8XQKEE9TMipuBzhccLikenEhj
QjAdBgNVHQ4EFgQU4TqrIXzx401UrtRyt/2LWUIgkFQwHQYDVR0lBBYwFAYIKwYB
BQUHAwEGCCsGAQUFBwMCMD0GA1UdIAQ2MDQwMgYEVR0gADAqMCgGCCsGAQUFBwIB
FhxodHRwOi8vcmVwb3NpdG9yeS5lbXNpZ24uY29tMHgGCCsGAQUFBwEBBGwwajAi
BggrBgEFBQcwAYYWaHR0cDovL29jc3AuZW1zaWduLmNvbTBEBggrBgEFBQcwAoY4
aHR0cDovL3JlcG9zaXRvcnkuZW1zaWduLmNvbS9jZXJ0cy9lbVNpZ25FQ0NSb290
Q0FHMy5jcnQwMwYDVR0fBCwwKjAooCagJIYiaHR0cDovL2NybC5lbXNpZ24uY29t
P1Jvb3RDQUczLmNybDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIB
ATAKBggqhkjOPQQDAwNpADBmAjEAt9CIpRGp46QHQYDUBnLKw+vvK0/h9vmilEAg
TroUl/anH4x2rXHqiCtBTBfgKDegAjEA8WpG1LTZdAIL0FSYqxXeREaeTSxEofM0
1jJH3jGvCXC79LU9UPJ2o3TU+UIj2gMV
-----END CERTIFICATE-----
""",
    "ov-g3b-aaa-emudhra.we-have-a-problem.com.pem": """-----BEGIN CERTIFICATE-----
MIICPzCCAcagAwIBAgIUH0gWfBRnOiSjcduti/cukjDGAjIwCgYIKoZIzj0EAwIw
PzELMAkGA1UEBhMCTkwxEzARBgNVBAoMCmVNdWRocmEgQlYxGzAZBgNVBAMMEkVN
IE9WIFRMUyBDQSAtIEczQjAeFw0yNjEwMjAwMjIyNDJaFw0yNzA1MDMwMjI3NDJa
MDMxMTAvBgNVBAMMKG92LWczYi1hYWEtZW11ZGhyYS53ZS1oYXZlLWEtcHJvYmxl
bS5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ3EfjVE+6fUm9gr7UoUv6N
YPttIdILR9OMZnAdTj+RWT1Z4fp7dpC5mat1gbIo4J6EDelcOQQz5/oGeB3gFJKw
o4GrMIGoMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoG
CCsGAQUFBwMBMDMGA1UdEQQsMCqCKG92LWczYi1hYWEtZW11ZGhyYS53ZS1oYXZl
LWEtcHJvYmxlbS5jb20wHQYDVR0OBBYEFKzQPp6gTBOWb0TBxZbkL5zsQn3oMB8G
A1UdIwQYMBaAFJvYZVGv5+csN60I7mkZ2b83hK4KMAoGCCqGSM49BAMCA2cAMGQC
MARKrRRBEWY2Ix1d80DGUvC7bWENP1Q9pf6BOGF4+84UiwV5+nAuht/+hdpAanWB
sQIwJF2dW8tpPN6lTm1kDerzG6yJAJOz4drotaTthMF2+efuv5W2FL7Dr8qZSd1z
201o
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDzjCCAragAwIBAgIRAOlCI73pL5FOWrmsq/2sNxAwDQYJKoZIhvcNAQELBQAw
ezELMAkGA1UEBhMCR0IxGzAZBgNVBAgMEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G
A1UEBwwHU2FsZm9yZDEaMBgGA1UECgwRQ29tb2RvIENBIExpbWl0ZWQxITAfBgNV
BAMMGEFBQSBDZXJ0aWZpY2F0ZSBTZXJ2aWNlczAeFw0yNTA1MTQwMDAwMDBaFw0y
ODEyMzEyMzU5NTlaMD8xCzAJBgNVBAYTAk5MMRMwEQYDVQQKDAplTXVkaHJhIEJW
MRswGQYDVQQDDBJFTSBPViBUTFMgQ0EgLSBHM0IwdjAQBgcqhkjOPQIBBgUrgQQA
IgNiAARziXqg6zz9yosSQC/68KvE4SErr43ud4rJ7i1tuD+sKAxeBWOK56Ks1xwy
Ko42HN659pxDArndjXPRzGyqsswK7k4hbOl53VGKSvS2JuVoTN1lgDftDIVOTMEv
TPhkbQ2jggE1MIIBMTAfBgNVHSMEGDAWgBSgEQojPpbxB+zirynvgqV/0DCktDAd
BgNVHQ4EFgQUm9hlUa/n5yw3rQjuaRnZvzeErgowDgYDVR0PAQH/BAQDAgEGMBIG
A1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMC
MDEGA1UdIAQqMCgwCAYGZ4EMAQICMA0GCysGAQQBg44hAQABMA0GCysGAQQBg44h
AQJuMEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwuY29tb2RvY2EuY29tL0FB
QUNlcnRpZmljYXRlU2VydmljZXMuY3JsMDQGCCsGAQUFBwEBBCgwJjAkBggrBgEF
BQcwAYYYaHR0cDovL29jc3AuY29tb2RvY2EuY29tMA0GCSqGSIb3DQEBCwUAA4IB
AQALRoOSvkzRa+tN5Rje9W5GiXd/qsicd9N6Gnh0SWC7VyWH+HycIqAnFCMYZznj
CeGusomFYHE42SHWr85JDIbgzy6y3dO4i9n9w0Bx7yrXWBbDzFS8VgA3+EY4Cg7y
mtoC3RPOJVtaXXPZ+68X804g1Mj+3vCSHj2lNPVgco0OzSIOJ/KMg1R9MLBkiKzb
bERAGZHejY0HBhYd76IINZN8z6bBNah2UdFYxsOisLynPQUkol6gRLum024/FzVl
CCDfnUusrkr+mAfPAvD/Vb8bhpA7jYtepuU+2mIdShj5lLlvAwZphn+ypWycuo2x
0k9mldz2dqI9nhCiY+TTIOOR
-----END CERTIFICATE-----
""",
    "ov-g3b-emudhra.we-have-a-problem.com.pem": """-----BEGIN CERTIFICATE-----
MIICODCCAb6gAwIBAgIUPXjC97k7buQHZ7p5ehDU8QNyrR4wCgYIKoZIzj0EAwIw
PzELMAkGA1UEBhMCTkwxEzARBgNVBAoMCmVNdWRocmEgQlYxGzAZBgNVBAMMEkVN
IE9WIFRMUyBDQSAtIEczQjAeFw0yNjEwMjAwMDU5MzdaFw0yNzA1MDMwMTA0Mzda
MC8xLTArBgNVBAMMJG92LWczYi1lbXVkaHJhLndlLWhhdmUtYS1wcm9ibGVtLmNv
bTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABA1haD+95Albk0UN6YtDCPpqevTv
YUmEhsIVpb/hnhsbBlH0yLthSE2JLH14ywiQJXttoc/pDWC9eoICW6CJXL2jgacw
gaQwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYB
BQUHAwEwLwYDVR0RBCgwJoIkb3YtZzNiLWVtdWRocmEud2UtaGF2ZS1hLXByb2Js
ZW0uY29tMB0GA1UdDgQWBBQUhzc4s202Hn62G0srmgguYdY2MTAfBgNVHSMEGDAW
gBSb2GVRr+fnLDetCO5pGdm/N4SuCjAKBggqhkjOPQQDAgNoADBlAjEAoJ6d4zzA
xE349yGHHrwKZpVCC/HBFutcOpOfzQoe8ikbmaaBTdtKai5TEllwt3dBAjBeHGiX
VheDhJfewbei99cw1MfYB5tPwdfuY5pe1MJz0Tg9zJ4JgxBvF6LTT0OOXZ4=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDZjCCAu2gAwIBAgIPbK2jZ/scEACIEg6iAtVoMAoGCCqGSM49BAMDMFYxCzAJ
BgNVBAYTAklOMSUwIwYDVQQKDBxlTXVkaHJhIFRlY2hub2xvZ2llcyBMaW1pdGVk
MSAwHgYDVQQDDBdlbVNpZ24gUm9vdCBUTFMgQ0EgLSBHMzAeFw0yNTA0MzAxNjAw
MTJaFw00MDA0MjgxODMwMDBaMD8xCzAJBgNVBAYTAk5MMRMwEQYDVQQKDAplTXVk
aHJhIEJWMRswGQYDVQQDDBJFTSBPViBUTFMgQ0EgLSBHM0IwdjAQBgcqhkjOPQIB
BgUrgQQAIgNiAARziXqg6zz9yosSQC/68KvE4SErr43ud4rJ7i1tuD+sKAxeBWOK
56Ks1xwyKo42HN659pxDArndjXPRzGyqsswK7k4hbOl53VGKSvS2JuVoTN1lgDft
DIVOTMEvTPhkbQ2jggGWMIIBkjAfBgNVHSMEGDAWgBThOqshfPHjTVSu1HK3/YtZ
QiCQVDAdBgNVHQ4EFgQUm9hlUa/n5yw3rQjuaRnZvzeErgowHQYDVR0lBBYwFAYI
KwYBBQUHAwEGCCsGAQUFBwMCMF0GA1UdIARWMFQwOQYLKwYBBAGDjiEBAAEwKjAo
BggrBgEFBQcCARYcaHR0cDovL3JlcG9zaXRvcnkuZW1zaWduLmNvbTANBgsrBgEE
AYOOIQECbjAIBgZngQwBAgIwdQYIKwYBBQUHAQEEaTBnMCQGCCsGAQUFBzABhhho
dHRwOi8vb2NzcC1iLmVtc2lnbi5jb20wPwYIKwYBBQUHMAKGM2h0dHA6Ly9yZXBv
c2l0b3J5LmVtc2lnbi5jb20vY2VydHMvRU1PVlRMU0NBRzNCLnA3YzA3BgNVHR8E
MDAuMCygKqAohiZodHRwOi8vY3JsLmVtc2lnbi5jb20vP3Jvb3R0bHNjYWczLmNy
bDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADAKBggqhkjOPQQD
AwNnADBkAjBAk+5BizdJhrED3wb7F2Gm7bWI60dlNd075nghT2TrR4NWKZtJZcbc
28xxIY/NONICMF6mPdsjosaqmvEMWqKcBh4vsIvXSKnQj5o8zrFB4oKS+accjYTe
8Dz3bQjauvy9uw==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDdDCCAvmgAwIBAgIQAJYaPvsTWVdu0EAFtGhKWzAKBggqhkjOPQQDAzBrMQsw
CQYDVQQGEwJJTjETMBEGA1UECxMKZW1TaWduIFBLSTElMCMGA1UEChMcZU11ZGhy
YSBUZWNobm9sb2dpZXMgTGltaXRlZDEgMB4GA1UEAxMXZW1TaWduIEVDQyBSb290
IENBIC0gRzMwHhcNMjQwNzExMTU0MzM2WhcNMzkwNzA5MTgzMDAwWjBWMQswCQYD
VQQGEwJJTjElMCMGA1UECgwcZU11ZGhyYSBUZWNobm9sb2dpZXMgTGltaXRlZDEg
MB4GA1UEAwwXZW1TaWduIFJvb3QgVExTIENBIC0gRzMwdjAQBgcqhkjOPQIBBgUr
gQQAIgNiAARfD9w/q1cWxL6D9bMGH6CQ4u+gAV6GN9s+PwQx9Bl4hC+0iU8QOk8m
WO/RwXQy10DCSxT8vSIJClHKp+Ao4qJKdYeV0SwZ7LMQziyLfxIUOY6Grja/sQFw
LKYf8EdDXAyjggF1MIIBcTAfBgNVHSMEGDAWgBR8XQKEE9TMipuBzhccLikenEhj
QjAdBgNVHQ4EFgQU4TqrIXzx401UrtRyt/2LWUIgkFQwHQYDVR0lBBYwFAYIKwYB
BQUHAwEGCCsGAQUFBwMCMD0GA1UdIAQ2MDQwMgYEVR0gADAqMCgGCCsGAQUFBwIB
FhxodHRwOi8vcmVwb3NpdG9yeS5lbXNpZ24uY29tMHgGCCsGAQUFBwEBBGwwajAi
BggrBgEFBQcwAYYWaHR0cDovL29jc3AuZW1zaWduLmNvbTBEBggrBgEFBQcwAoY4
aHR0cDovL3JlcG9zaXRvcnkuZW1zaWduLmNvbS9jZXJ0cy9lbVNpZ25FQ0NSb290
Q0FHMy5jcnQwMwYDVR0fBCwwKjAooCagJIYiaHR0cDovL2NybC5lbXNpZ24uY29t
P1Jvb3RDQUczLmNybDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIB
ATAKBggqhkjOPQQDAwNpADBmAjEAt9CIpRGp46QHQYDUBnLKw+vvK0/h9vmilEAg
TroUl/anH4x2rXHqiCtBTBfgKDegAjEA8WpG1LTZdAIL0FSYqxXeREaeTSxEofM0
1jJH3jGvCXC79LU9UPJ2o3TU+UIj2gMV
-----END CERTIFICATE-----
""",
    "ov-g3c-aaa-emudhra.we-have-a-problem.com.pem": """-----BEGIN CERTIFICATE-----
MIICQTCCAcegAwIBAgIULuWnWW6kFV6QZxp2ls8r18NCjXkwCgYIKoZIzj0EAwIw
QDELMAkGA1UEBhMCVVMxFDASBgNVBAoMC2VNdWRocmEgSW5jMRswGQYDVQQDDBJF
TSBPViBUTFMgQ0EgLSBHM0MwHhcNMjYxMDIwMDIyMjQyWhcNMjcwNTAzMDIyNzQy
WjAzMTEwLwYDVQQDDChvdi1nM2MtYWFhLWVtdWRocmEud2UtaGF2ZS1hLXByb2Js
ZW0uY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEb7+5g2YHNYwH2eQERrZc
TmVuf/RmvzsGGMSwXmZke6vn35Ut5HME7UOOU3Muy+BSfjfpo6fjL5KOs3Ndz67d
OKOBqzCBqDAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAK
BggrBgEFBQcDATAzBgNVHREELDAqgihvdi1nM2MtYWFhLWVtdWRocmEud2UtaGF2
ZS1hLXByb2JsZW0uY29tMB0GA1UdDgQWBBQ7oBzq3jpTuvntbIkzMV12Ps3O0TAf
BgNVHSMEGDAWgBQ06uoM68kK2vnQxeLtm3jJh54bbDAKBggqhkjOPQQDAgNoADBl
AjEA/Y7AZ4M2MYbN5Od9tREaUfFjZKoOjczfIKPjKNMjtGxTdL9WUXvAT4QDgktn
/IJdAjAbORTkAXD5hggyG6K7p0MBz3lFZJb2l/LndZlrttJWBLP8QGrc44hrZZtK
Iq0d1dE=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDzzCCAregAwIBAgIRAI1aSBGTnvRH13ERzdmEmukwDQYJKoZIhvcNAQELBQAw
ezELMAkGA1UEBhMCR0IxGzAZBgNVBAgMEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G
A1UEBwwHU2FsZm9yZDEaMBgGA1UECgwRQ29tb2RvIENBIExpbWl0ZWQxITAfBgNV
BAMMGEFBQSBDZXJ0aWZpY2F0ZSBTZXJ2aWNlczAeFw0yNTA1MTQwMDAwMDBaFw0y
ODEyMzEyMzU5NTlaMEAxCzAJBgNVBAYTAlVTMRQwEgYDVQQKDAtlTXVkaHJhIElu
YzEbMBkGA1UEAwwSRU0gT1YgVExTIENBIC0gRzNDMHYwEAYHKoZIzj0CAQYFK4EE
ACIDYgAEE4JRzVKskpjByKrZdzId65fnCb0LTKCspV3IrVHc/J0ViaFZfjpRIOHv
1jHGPhg1ysrimGmmLhYx6KKBgatWYW3EXZGKvAnzqw5jz3kqpNztc4e+N7ulaVSf
HAKycO1no4IBNTCCATEwHwYDVR0jBBgwFoAUoBEKIz6W8Qfs4q8p74Klf9AwpLQw
HQYDVR0OBBYEFDTq6gzryQra+dDF4u2beMmHnhtsMA4GA1UdDwEB/wQEAwIBBjAS
BgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcD
AjAxBgNVHSAEKjAoMAgGBmeBDAECAjANBgsrBgEEAYOOIQEAATANBgsrBgEEAYOO
IQECbjBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsLmNvbW9kb2NhLmNvbS9B
QUFDZXJ0aWZpY2F0ZVNlcnZpY2VzLmNybDA0BggrBgEFBQcBAQQoMCYwJAYIKwYB
BQUHMAGGGGh0dHA6Ly9vY3NwLmNvbW9kb2NhLmNvbTANBgkqhkiG9w0BAQsFAAOC
AQEAHlbhZpjhkPEAQVhPHRtBDaHqiisVD20pQ1TUeSx3l62Qe7NQ0b7vWQy7DN0i
KOu7BGpP5EnIjvXbz9FhpfPJ4FhKEt3tQ51rqXz2oD8vRaryvExWPobDUz3j7HN6
OzBsVMIe3PD7AAkpky0x8zMSi/ep5R9OMzybmNptbtppyuB5ytgq+h7lQdRIP+CQ
TaJX3qTgfMqzntYre5GljmEB5hU2/rSn8zoSU2APkJidlZFpghtgbD4I2VRHZvCw
FFr/SrFM9pwrgbJNZ1MtyTSVgI5NlNb0aMfLR+/r6jJt3ROeY2yh2QQ2dx+Yqgdb
uL5ChFWOQU+ErSDnUq7yr+pjBQ==
-----END CERTIFICATE-----
""",
    "ov-g3c-emudhra.we-have-a-problem.com.pem": """-----BEGIN CERTIFICATE-----
MIICOTCCAb+gAwIBAgIUXcJ4+VeNEICJ9JbBANtIyfP96EowCgYIKoZIzj0EAwIw
QDELMAkGA1UEBhMCVVMxFDASBgNVBAoMC2VNdWRocmEgSW5jMRswGQYDVQQDDBJF
TSBPViBUTFMgQ0EgLSBHM0MwHhcNMjYxMDIwMDA1OTM3WhcNMjcwNTAzMDEwNDM3
WjAvMS0wKwYDVQQDDCRvdi1nM2MtZW11ZGhyYS53ZS1oYXZlLWEtcHJvYmxlbS5j
b20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATLEvRHdoPc0Z9ovgqlYmoKTHPU
Apwd6lAp0ou1G63SzuESyBzIW6Tl64CsKzlV9ggkZjX+L9/tOx97/1wmSTYvo4Gn
MIGkMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsG
AQUFBwMBMC8GA1UdEQQoMCaCJG92LWczYy1lbXVkaHJhLndlLWhhdmUtYS1wcm9i
bGVtLmNvbTAdBgNVHQ4EFgQUrytBb+px+b58Df+d5vP8GpTW+/wwHwYDVR0jBBgw
FoAUNOrqDOvJCtr50MXi7Zt4yYeeG2wwCgYIKoZIzj0EAwIDaAAwZQIwNdoOUOKz
MLV1OFEoMjBeUqvkQAwsajvVWu0A23qyyvYlosyMp8aFv0gxURW6Yj6DAjEAhe0z
kOQmmqb0eyhjh7weF4fHtwMtLi4jNFA6M/EfPTfkqE91MN9fSin5uhua5xhk
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDaDCCAu6gAwIBAgIPKWkmwiejoVJjkrGUgqUEMAoGCCqGSM49BAMDMFYxCzAJ
BgNVBAYTAklOMSUwIwYDVQQKDBxlTXVkaHJhIFRlY2hub2xvZ2llcyBMaW1pdGVk
MSAwHgYDVQQDDBdlbVNpZ24gUm9vdCBUTFMgQ0EgLSBHMzAeFw0yNTA0MzAxNTM3
NDFaFw00MDA0MjgxODMwMDBaMEAxCzAJBgNVBAYTAlVTMRQwEgYDVQQKDAtlTXVk
aHJhIEluYzEbMBkGA1UEAwwSRU0gT1YgVExTIENBIC0gRzNDMHYwEAYHKoZIzj0C
AQYFK4EEACIDYgAEE4JRzVKskpjByKrZdzId65fnCb0LTKCspV3IrVHc/J0ViaFZ
fjpRIOHv1jHGPhg1ysrimGmmLhYx6KKBgatWYW3EXZGKvAnzqw5jz3kqpNztc4e+
N7ulaVSfHAKycO1no4IBljCCAZIwHwYDVR0jBBgwFoAU4TqrIXzx401UrtRyt/2L
WUIgkFQwHQYDVR0OBBYEFDTq6gzryQra+dDF4u2beMmHnhtsMB0GA1UdJQQWMBQG
CCsGAQUFBwMBBggrBgEFBQcDAjBdBgNVHSAEVjBUMDkGCysGAQQBg44hAQABMCow
KAYIKwYBBQUHAgEWHGh0dHA6Ly9yZXBvc2l0b3J5LmVtc2lnbi5jb20wDQYLKwYB
BAGDjiEBAm4wCAYGZ4EMAQICMHUGCCsGAQUFBwEBBGkwZzAkBggrBgEFBQcwAYYY
aHR0cDovL29jc3AtYy5lbXNpZ24uY29tMD8GCCsGAQUFBzAChjNodHRwOi8vcmVw
b3NpdG9yeS5lbXNpZ24uY29tL2NlcnRzL0VNT1ZUTFNDQUczQy5wN2MwNwYDVR0f
BDAwLjAsoCqgKIYmaHR0cDovL2NybC5lbXNpZ24uY29tLz9yb290dGxzY2FnMy5j
cmwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwCgYIKoZIzj0E
AwMDaAAwZQIxAMSZt2xsPeumRdeSMSQ3CbzIZeQ/q7GDCWfeE1Pq+mhgA6gRM44c
NVF3xJ+wsxJk+wIwFJbaDMokD8Ei6eNOiA8yUMYvfzQyngmrhZQMdPCK1SewrR79
4rSb9vGqxZzelQth
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDdDCCAvmgAwIBAgIQAJYaPvsTWVdu0EAFtGhKWzAKBggqhkjOPQQDAzBrMQsw
CQYDVQQGEwJJTjETMBEGA1UECxMKZW1TaWduIFBLSTElMCMGA1UEChMcZU11ZGhy
YSBUZWNobm9sb2dpZXMgTGltaXRlZDEgMB4GA1UEAxMXZW1TaWduIEVDQyBSb290
IENBIC0gRzMwHhcNMjQwNzExMTU0MzM2WhcNMzkwNzA5MTgzMDAwWjBWMQswCQYD
VQQGEwJJTjElMCMGA1UECgwcZU11ZGhyYSBUZWNobm9sb2dpZXMgTGltaXRlZDEg
MB4GA1UEAwwXZW1TaWduIFJvb3QgVExTIENBIC0gRzMwdjAQBgcqhkjOPQIBBgUr
gQQAIgNiAARfD9w/q1cWxL6D9bMGH6CQ4u+gAV6GN9s+PwQx9Bl4hC+0iU8QOk8m
WO/RwXQy10DCSxT8vSIJClHKp+Ao4qJKdYeV0SwZ7LMQziyLfxIUOY6Grja/sQFw
LKYf8EdDXAyjggF1MIIBcTAfBgNVHSMEGDAWgBR8XQKEE9TMipuBzhccLikenEhj
QjAdBgNVHQ4EFgQU4TqrIXzx401UrtRyt/2LWUIgkFQwHQYDVR0lBBYwFAYIKwYB
BQUHAwEGCCsGAQUFBwMCMD0GA1UdIAQ2MDQwMgYEVR0gADAqMCgGCCsGAQUFBwIB
FhxodHRwOi8vcmVwb3NpdG9yeS5lbXNpZ24uY29tMHgGCCsGAQUFBwEBBGwwajAi
BggrBgEFBQcwAYYWaHR0cDovL29jc3AuZW1zaWduLmNvbTBEBggrBgEFBQcwAoY4
aHR0cDovL3JlcG9zaXRvcnkuZW1zaWduLmNvbS9jZXJ0cy9lbVNpZ25FQ0NSb290
Q0FHMy5jcnQwMwYDVR0fBCwwKjAooCagJIYiaHR0cDovL2NybC5lbXNpZ24uY29t
P1Jvb3RDQUczLmNybDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIB
ATAKBggqhkjOPQQDAwNpADBmAjEAt9CIpRGp46QHQYDUBnLKw+vvK0/h9vmilEAg
TroUl/anH4x2rXHqiCtBTBfgKDegAjEA8WpG1LTZdAIL0FSYqxXeREaeTSxEofM0
1jJH3jGvCXC79LU9UPJ2o3TU+UIj2gMV
-----END CERTIFICATE-----
""",
    "control.pem": """-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4
WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY
MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc
h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+
0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U
A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW
T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH
B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC
B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv
KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn
OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn
jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw
qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI
rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq
hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL
ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ
3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK
NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5
ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur
TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC
jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc
oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq
4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA
mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d
emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=
-----END CERTIFICATE-----
""",
}

if __name__ == "__main__":
    sys.exit(main())
