#!/usr/bin/env python3
"""fast_adversarial.py SRC DST VARIANT

Writes a variant of the dataset SRC to DST that breaks one thing the fast path
relies on. Files that do not change are symlinked. `list` prints the variants.
"""
import os
import sys
from collections import Counter

HDR = {"events": 7, "clicks": 4, "links": 2}


def unq(f):
    return f[1:-1] if len(f) >= 2 and f[0] == '"' and f[-1] == '"' else f


def rows(path, n):
    """(line, fields or None) for every data line; fields are unquoted."""
    with open(path, newline="") as fh:
        lines = fh.read().split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    head, body = lines[0], lines[1:]
    out = []
    for ln in body:
        f = ln.split(",")
        out.append([ln, [unq(x) for x in f] if len(f) == n and ln.count('"') % 2 == 0 else None])
    return head, out


def write(path, head, lines):
    if os.path.islink(path) or os.path.exists(path):
        os.remove(path)
    with open(path, "w", newline="") as fh:
        fh.write(head + "\n")
        for ln in lines:
            fh.write(ln + "\n")


def files(src, kind):
    d = os.path.join(src, kind)
    return sorted(f for f in os.listdir(d) if f.endswith(".csv"))


def busiest(src, kind="events", col=1):
    c = Counter()
    for f in files(src, kind):
        _, rs = rows(os.path.join(src, kind, f), HDR[kind])
        for _, fl in rs:
            if fl and fl[col] and fl[col][0] == "u" and fl[col].islower():
                c[fl[col]] += 1
    return [u for u, _ in c.most_common(400)]


def rewrite(src, dst, kind, fn):
    """fn(file index, row index, fields) -> new fields, or None to keep the line."""
    for fi, f in enumerate(files(src, kind)):
        head, rs = rows(os.path.join(src, kind, f), HDR[kind])
        out, changed = [], False
        for ri, (ln, fl) in enumerate(rs):
            new = fn(fi, ri, fl) if fl else None
            if new is None:
                out.append(ln)
            else:
                changed = True
                out.append(",".join(new))
        if changed:
            write(os.path.join(dst, kind, f), head, out)


def add(dst, kind, name, head, lines):
    write(os.path.join(dst, kind, name), head, lines)


EV_HEAD = "event_id,user_id,ts,ingest_ts,event_type,product_id,price_cents"
LK_HEAD = "user_id_a,user_id_b"


def largest(src, kind):
    fs = files(src, kind)
    return max(range(len(fs)), key=lambda i: os.path.getsize(os.path.join(src, kind, fs[i])))


def v_upper_one_file(src, dst):
    big = largest(src, "events")
    rewrite(src, dst, "events", lambda fi, ri, f: [f[0].upper()] + f[1:] if fi == big else None)


def v_upper_some(src, dst):
    rewrite(src, dst, "events", lambda fi, ri, f: [f[0].upper()] + f[1:] if ri % 40 == 7 else None)


def v_fake_ids_decimal(src, dst):
    big = largest(src, "events")
    rewrite(src, dst, "events", lambda fi, ri, f: ["e%d" % (ri * 3)] + f[1:] if fi == big and ri >= 20 and ri % 4 == 1 and ri < 12000 else None)


def v_fake_ids_other(src, dst):
    big = largest(src, "events")
    rewrite(src, dst, "events", lambda fi, ri, f: ["x%07d" % ri] + f[1:] if fi == big and ri >= 20 and ri % 4 == 1 and ri < 12000 else None)


def v_swap_users(src, dst):
    a, b = busiest(src)[:2]
    sw = {a: b, b: a}
    rewrite(src, dst, "events", lambda fi, ri, f: [f[0], sw[f[1]]] + f[2:] if f[1] in sw and ri % 2 == 0 else None)
    rewrite(src, dst, "clicks", lambda fi, ri, f: [f[0], sw[f[1]]] + f[2:] if f[1] in sw and ri % 2 == 1 else None)


def v_swap_small_users(src, dst):
    us = busiest(src)
    a, b = us[min(200, len(us) - 2)], us[min(201, len(us) - 1)]
    sw = {a: b, b: a}
    rewrite(src, dst, "events", lambda fi, ri, f: [f[0], sw[f[1]]] + f[2:] if f[1] in sw and ri % 2 == 0 else None)


def v_reverse_ts(src, dst):
    for who in (2, 150):
        base = dst if who != 2 else src
        us = busiest(src)
        a = us[min(who, len(us) - 1)]
        seen = []
        for f in files(base, "events"):
            _, rs = rows(os.path.join(base, "events", f), 7)
            seen += [fl[2] for _, fl in rs if fl and fl[1] == a]
        seen.reverse()
        it = iter(seen)

        def fn(fi, ri, f):
            if f[1] != a:
                return None
            return f[:2] + [next(it)] + f[3:]

        rewrite(base, dst, "events", fn)


def v_link_two_users(src, dst):
    us = busiest(src)
    add(dst, "links", "zz-extra.csv", LK_HEAD, ["%s,%s" % (us[10], us[11]), "%s,%s" % (us[30], us[31]), "%s,%s" % (us[31], us[32]), '"%s",%s' % (us[0], us[50])])


def v_link_upper(src, dst):
    us = busiest(src)
    add(dst, "links", "zz-extra.csv", LK_HEAD, [
        "%s,%s" % (us[12].upper(), us[12]),
        "%s,U_new_id" % us[13],
        "%s,uzzzzzzzzzzzzzzzz" % us[14],
        "0first,%s" % us[15],
        "%s,%s" % (us[1], us[1].upper()),
        "%s,an id with spaces and more than ten bytes" % us[16],
    ])


def v_dup_other_user_wins(src, dst):
    us = busiest(src)
    a, b = us[5], us[6]
    extra, used = [], set()
    for f in files(src, "events"):
        _, rs = rows(os.path.join(src, "events", f), 7)
        for _, fl in rs:
            # one copy per event: copies with equal ingest_ts must be identical
            if fl and fl[1] == a and len(extra) < 200 and fl[0] not in used:
                used.add(fl[0])
                who = b if len(extra) % 2 == 0 else "newuser%d" % (len(extra) % 5)
                extra.append(",".join([fl[0], who, fl[2], "2000-01-01T00:00:00Z"] + fl[4:]))
    add(dst, "events", "zz-extra.csv", EV_HEAD, extra)


def v_dup_dead_wins(src, dst):
    extra, used = [], set()
    for f in files(src, "events")[:6]:
        _, rs = rows(os.path.join(src, "events", f), 7)
        for ri, (_, fl) in enumerate(rs):
            if fl and ri % 25 == 3 and fl[0] not in used:
                used.add(fl[0])
                kind = ri % 3
                if kind == 0:
                    extra.append(",".join([fl[0], fl[1], "not a time", "2000-01-01T00:00:00Z"] + fl[4:]))
                elif kind == 1:
                    extra.append(",".join([fl[0], "", fl[2], "2000-01-01T00:00:00Z"] + fl[4:]))
                else:
                    extra.append(",".join([fl[0], fl[1], fl[2], "2000-01-01T00:00:00Z", "refund"] + fl[5:]))
    add(dst, "events", "zz-extra.csv", EV_HEAD, extra)


def v_long_ids(src, dst):
    a = busiest(src)[3]

    def ev(fi, ri, f):
        if ri % 50 == 9:
            return [f[0] + "_longsuffix_xyz"] + f[1:]
        if ri % 70 == 11:
            return [f[0], "user-with-a-very-long-id-%d" % (ri % 9)] + f[2:]
        if ri % 90 == 13:
            return [f[0], f[1] + " "] + f[2:]
        return None

    rewrite(src, dst, "events", ev)
    rewrite(src, dst, "clicks", lambda fi, ri, f: [f[0] + "_0123456789abcdef"] + f[1:] if f[1] == a and ri % 3 == 0 else None)


def v_early_ingest(src, dst):
    # a different second per row: copies with equal ingest_ts must be identical
    def fn(fi, ri, f):
        if ri % 30 != 5:
            return None
        n = fi * 40000 + ri // 30
        return f[:3] + ["2001-%02d-%02dT%02d:%02d:%02dZ" % (1 + n // 2419200 % 12, 1 + n // 86400 % 28, n // 3600 % 24, n // 60 % 60, n % 60)] + f[4:]

    rewrite(src, dst, "events", fn)


def v_drop_link_files(src, dst):
    for i, f in enumerate(files(src, "links")):
        if i % 2 == 0:
            os.remove(os.path.join(dst, "links", f))


def v_no_links(src, dst):
    for f in files(src, "links"):
        os.remove(os.path.join(dst, "links", f))


def v_click_upper(src, dst):
    us = set(busiest(src)[:8])
    rewrite(src, dst, "clicks", lambda fi, ri, f: [f[0], f[1].upper()] + f[2:] if f[1] in us and ri % 2 == 0 else None)
    one = sorted(us)[0]
    add(dst, "links", "zz-extra.csv", LK_HEAD, ["%s,%s" % (one.upper(), one)])


def v_same_user_everywhere(src, dst):
    a = busiest(src)[0]
    rewrite(src, dst, "events", lambda fi, ri, f: [f[0], a] + f[2:] if ri % 3 == 0 and f[1] else None)


def v_shuffled_users(src, dst):
    us = busiest(src)[:64]
    rewrite(src, dst, "events", lambda fi, ri, f: [f[0], us[(ri * 7 + fi) % 64]] + f[2:] if f[1] and ri % 2 == 0 else None)


VARIANTS = {k[2:]: v for k, v in list(globals().items()) if k.startswith("v_")}


def main():
    if len(sys.argv) == 2 and sys.argv[1] == "list":
        print(" ".join(VARIANTS))
        return
    src, dst, var = sys.argv[1:4]
    src = os.path.abspath(src)
    os.makedirs(dst)
    for name in os.listdir(src):
        p = os.path.join(src, name)
        if os.path.isdir(p):
            os.makedirs(os.path.join(dst, name))
            for f in os.listdir(p):
                os.symlink(os.path.join(p, f), os.path.join(dst, name, f))
        else:
            os.symlink(p, os.path.join(dst, name))
    VARIANTS[var](src, dst)


if __name__ == "__main__":
    main()
