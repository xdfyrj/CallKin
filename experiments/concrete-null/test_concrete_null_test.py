"""Concrete Null Test의 byte-identical 반례를 고정하는 회귀 테스트.

논문 3.3절이 주장하는 두 대응쌍을 검증한다.

    largest::<u8>  / largest_u8    78 bytes  fdbf50b9...
    largest::<i32> / largest_i32  166 bytes  2917f606...

이 주장은 보고서에서 가장 강한 결론(함수 바이트만 보는 판정기는 generic
원본을 원리적으로 판정할 수 없다)의 유일한 근거다. 지금까지 수동 검증값이었고
자동 검사로 고정되어 있지 않았다. 툴체인이 바뀌면 조용히 거짓이 될 수 있으므로
여기에 못 박는다.

검증 방식:
  1. 심볼이 남아 있는 O3 바이너리에서 함수 이름과 extent를 읽는다
  2. 같은 주소 범위를 strip된 O3S 바이너리에서 잘라낸다
  3. 두 쌍이 바이트 단위로 같은지, 그리고 공표한 SHA-256과 맞는지 확인한다

표준 라이브러리만 사용한다. nm, radare2, pyelftools 모두 필요 없다.

실행:
    python test_concrete_null_test.py       # 단독
    pytest test_concrete_null_test.py       # pytest 사용 시
"""

import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parent
GENERIC_O3 = ROOT / "artifacts" / "O3" / "func_largest" / "func_largest.bin"
GENERIC_O3S = ROOT / "artifacts" / "O3S" / "func_largest" / "func_largest.bin"
CONCRETE_O3 = ROOT / "artifacts" / "concrete" / "O3" / "func_largest" / "func_largest.bin"
CONCRETE_O3S = ROOT / "artifacts" / "concrete" / "O3S" / "func_largest" / "func_largest.bin"

# 논문 3.3절 표에 실린 값. rustc 1.93.1, LLVM 21.1.8,
# x86_64-unknown-linux-gnu, O3 후 strip --strip-all, 네 함수 모두 #[inline(never)].
PUBLISHED = {
    78: "fdbf50b9d3efe56d20c2d0392f780e73b179cc7d88255321138c887cbe563b40",
    166: "2917f606eb112548c2579d32c9b851e07b9a3cd16480ac04d5b1b5df2f2e9e9d",
}

# 각 쌍은 (generic 쪽 심볼 조각, concrete 쪽 심볼 조각, 기대 크기).
# Rust 해시 접미사는 컴파일마다 바뀔 수 있으므로 부분 문자열로 찾는다.
PAIRS = [
    ("7largest17he401f58e", "10largest_u817", 78),
    ("7largest17h6ae1ca31", "11largest_i3217", 166),
]

STT_FUNC = 2
SHT_SYMTAB = 2
SHT_NOBITS = 8


def _sections(data):
    if data[:4] != b"\x7fELF" or data[4] != 2:
        raise ValueError("64-bit little-endian ELF가 아니다")
    (e_shoff,) = struct.unpack_from("<Q", data, 0x28)
    e_shentsize, e_shnum, _ = struct.unpack_from("<HHH", data, 0x3A)
    keys = "name typ flags addr off size link info align entsize".split()
    return [
        dict(zip(keys, struct.unpack_from("<IIQQQQIIQQ", data, e_shoff + i * e_shentsize)))
        for i in range(e_shnum)
    ]


def _cstr(data, base, offset):
    end = data.index(b"\0", base + offset)
    return data[base + offset : end].decode("utf-8", "replace")


def function_symbols(path):
    """{심볼 이름: (가상 주소, 크기)} 를 돌려준다."""
    data = path.read_bytes()
    sections = _sections(data)
    out = {}
    for sec in sections:
        if sec["typ"] != SHT_SYMTAB:
            continue
        strtab = sections[sec["link"]]
        for i in range(sec["size"] // sec["entsize"]):
            off = sec["off"] + i * sec["entsize"]
            st_name, st_info, _, _, st_value, st_size = struct.unpack_from("<IBBHQQ", data, off)
            if st_name and (st_info & 0xF) == STT_FUNC:
                out[_cstr(data, strtab["off"], st_name)] = (st_value, st_size)
    return out


def read_at_vaddr(path, vaddr, size):
    """가상 주소 범위를 파일에서 잘라낸다."""
    data = path.read_bytes()
    for sec in _sections(data):
        if sec["typ"] == SHT_NOBITS:
            continue
        if sec["addr"] <= vaddr < sec["addr"] + sec["size"]:
            start = sec["off"] + (vaddr - sec["addr"])
            chunk = data[start : start + size]
            if len(chunk) != size:
                raise ValueError(f"{path.name}: {size} bytes를 읽지 못했다")
            return chunk
    raise ValueError(f"{path.name}: 주소 0x{vaddr:x}를 담은 섹션이 없다")


def find_symbol(symbols, fragment, expected_size):
    hits = [
        (name, addr, size)
        for name, (addr, size) in symbols.items()
        if fragment in name and size == expected_size
    ]
    if len(hits) != 1:
        raise AssertionError(
            f"{fragment!r} (크기 {expected_size})에 맞는 심볼이 {len(hits)}개다. "
            f"컴파일러가 바뀌었을 수 있다: {[h[0] for h in hits]}"
        )
    return hits[0]


def extract_pair(generic_fragment, concrete_fragment, size):
    g_name, g_addr, g_size = find_symbol(function_symbols(GENERIC_O3), generic_fragment, size)
    c_name, c_addr, c_size = find_symbol(function_symbols(CONCRETE_O3), concrete_fragment, size)
    generic = read_at_vaddr(GENERIC_O3S, g_addr, g_size)
    concrete = read_at_vaddr(CONCRETE_O3S, c_addr, c_size)
    return (g_name, generic), (c_name, concrete)


def test_artifacts_present():
    for path in (GENERIC_O3, GENERIC_O3S, CONCRETE_O3, CONCRETE_O3S):
        assert path.is_file(), f"산출물이 없다: {path}"


def test_pairs_are_byte_identical():
    """generic 함수와 Concrete Mirror의 기계어가 바이트 단위로 같다."""
    for generic_fragment, concrete_fragment, size in PAIRS:
        (g_name, generic), (c_name, concrete) = extract_pair(
            generic_fragment, concrete_fragment, size
        )
        assert generic == concrete, (
            f"{g_name}와 {c_name}가 더 이상 같지 않다. "
            f"논문 3.3절의 반례가 이 툴체인에서 재현되지 않는다."
        )


def test_hashes_match_published_values():
    """추출한 바이트의 SHA-256이 보고서에 실린 값과 같다."""
    for generic_fragment, concrete_fragment, size in PAIRS:
        (g_name, generic), (c_name, concrete) = extract_pair(
            generic_fragment, concrete_fragment, size
        )
        for name, blob in ((g_name, generic), (c_name, concrete)):
            digest = hashlib.sha256(blob).hexdigest()
            assert digest == PUBLISHED[size], (
                f"{name}: {size} bytes의 해시가 {digest}인데 "
                f"보고서 값은 {PUBLISHED[size]}다."
            )


def main():
    test_artifacts_present()
    print("산출물 4개 확인")
    for generic_fragment, concrete_fragment, size in PAIRS:
        (g_name, generic), (c_name, concrete) = extract_pair(
            generic_fragment, concrete_fragment, size
        )
        digest = hashlib.sha256(generic).hexdigest()
        same = generic == concrete
        ok = same and digest == hashlib.sha256(concrete).hexdigest() == PUBLISHED[size]
        print(f"\n{size} bytes")
        print(f"  generic   {g_name}")
        print(f"  concrete  {c_name}")
        print(f"  sha256    {digest}")
        print(f"  바이트 동일 {same} / 보고서 값 일치 {digest == PUBLISHED[size]}")
        assert ok
    print("\n전부 통과. 논문 3.3절의 반례가 재현된다.")


if __name__ == "__main__":
    main()
