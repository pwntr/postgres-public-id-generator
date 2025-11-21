-- PostgreSQL Public ID Generator
-- SPDX-License-Identifier: MIT
-- Copyright (c) 2025 Peter Winter
-- https://github.com/pwntr/postgres-public-id-generator

-- Enable pgcrypto for randomness & HMAC
CREATE EXTENSION IF NOT EXISTS pgcrypto;

------------------------------------------------------------
-- 1) Key storage inside Postgres (no env vars or external key management system needed)
------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public_id_key (
    id  integer PRIMARY KEY CHECK (id = 1),
    key text NOT NULL
);

-- Get or lazily generate the key once, store it in the table
CREATE OR REPLACE FUNCTION get_public_id_key()
    RETURNS text AS
$$
DECLARE
    k text;
BEGIN
    SELECT key
    INTO k
    FROM public_id_key
    WHERE id = 1;

    IF k IS NULL THEN
        INSERT INTO public_id_key(id, key)
        VALUES (1, encode(gen_random_bytes(32), 'base64'))
        ON CONFLICT (id) DO NOTHING;

        SELECT key
        INTO k
        FROM public_id_key
        WHERE id = 1;
    END IF;

    RETURN k;
END;
$$ LANGUAGE plpgsql;

------------------------------------------------------------
-- 2) Variable-base encoder with alphabet selection
--    Alphabets (all avoid vowels and ambiguous characters for profanity-safety):
--    - lowercase: 23456789bcdfghjklmnpqrstvwxyz (Winter's Base29)
--    - uppercase: 23456789BCDFGHJKLMNPQRSTVWXYZ (Winter's Base29, uppercase variant)
--    - both:      23456789bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ (Winter's Base50)
------------------------------------------------------------
CREATE OR REPLACE FUNCTION encode_base_public_id(_n bigint, _len int, _alphabet text)
    RETURNS text AS
$$
DECLARE
    base  int;
    out   text := '';
    v     bigint;
    digit int;
BEGIN
    IF _len < 1 OR _len > 12 THEN
        RAISE EXCEPTION 'public_id length % is out of allowed range (1..12)', _len;
    END IF;

    base := length(_alphabet);

    IF base < 2 THEN
        RAISE EXCEPTION 'alphabet must have at least 2 characters';
    END IF;

    v := _n;

    -- Produce exactly _len digits in the given base
    FOR i IN 1.._len
        LOOP
            digit := (v % base)::int;
            out := substr(_alphabet, digit + 1, 1) || out;
            v := v / base;
        END LOOP;

    -- If anything remains, the number doesn't fit into _len digits
    IF v <> 0 THEN
        RAISE EXCEPTION
            'number % does not fit into % base-% digits with alphabet size %',
            _n, _len, base, base;
    END IF;

    RETURN out;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

------------------------------------------------------------
-- 3) Feistel PRP over a power-of-two domain (2^bits, bits even, <= 62)
--    Uses equal-width halves to ensure true permutation (bijection).
--    Adaptive round count based on domain size for consistent security.
------------------------------------------------------------
CREATE OR REPLACE FUNCTION feistel_prp_pow2(_x bigint, _key text, _bits int)
    RETURNS bigint AS
$$
DECLARE
    -- Adaptive rounds: smaller domains need more rounds for cryptographically strong mixing
    -- This ensures even tiny ID spaces get adequate security
    rounds     int;
    domain_max bigint;
    half_bits  int;
    half_mask  bigint;

    L          bigint;
    R          bigint;
    tmp        bigint;
    data       text;
    bytes      bytea;
    f          bigint;
BEGIN
    IF _bits < 2 OR _bits > 62 THEN
        RAISE EXCEPTION 'feistel_prp_pow2: bits % out of range (2..62)', _bits;
    END IF;

    -- Scale rounds based on domain size for consistent security strength
    -- Smaller state spaces need more mixing to prevent sequence prediction attacks
    IF _bits <= 10 THEN
        rounds := 12; -- Very small domains: maximum mixing
    ELSIF _bits <= 16 THEN
        rounds := 10; -- Small domains: strong mixing
    ELSIF _bits <= 24 THEN
        rounds := 8; -- Medium domains: balanced mixing
    ELSE
        rounds := 6; -- Large domains: standard mixing
    END IF;

    domain_max := (1::bigint << _bits); -- 2^bits

    IF _x < 0 OR _x >= domain_max THEN
        RAISE EXCEPTION 'feistel_prp_pow2: x % out of [0, %)', _x, domain_max;
    END IF;

    -- Equal halves ensure true permutation
    half_bits := _bits / 2;
    half_mask := (1::bigint << half_bits) - 1;

    -- Initial split: high half = L, low half = R
    L := (_x >> half_bits) & half_mask;
    R := _x & half_mask;

    FOR i IN 0..(rounds - 1)
        LOOP
            data := _key || ':' || i::text || ':' || R::text;
            bytes := hmac(data, _key, 'sha256');

            -- Take 8 bytes from HMAC -> 64 bits -> mask to half_bits
            f := (
                (get_byte(bytes, 0)::bigint << 56) |
                (get_byte(bytes, 1)::bigint << 48) |
                (get_byte(bytes, 2)::bigint << 40) |
                (get_byte(bytes, 3)::bigint << 32) |
                (get_byte(bytes, 4)::bigint << 24) |
                (get_byte(bytes, 5)::bigint << 16) |
                (get_byte(bytes, 6)::bigint << 8)  |
                get_byte(bytes, 7)::bigint
                ) & half_mask;

            tmp := R;
            R   := (L # f) & half_mask; -- XOR and mask
            L   := tmp & half_mask;
        END LOOP;

    RETURN ((L & half_mask) << half_bits) | (R & half_mask);
END;
$$ LANGUAGE plpgsql IMMUTABLE;

------------------------------------------------------------
-- 4) Global sequence (monotonic IDs)
------------------------------------------------------------
CREATE SEQUENCE IF NOT EXISTS public_id_seq
    MINVALUE 1
    START WITH 1
    NO CYCLE;

------------------------------------------------------------
-- 5) Main function: generate_public_id(len, alphabet_type)
--    Default length = 6, supports len 1..12.
--    Alphabet types: 'lower' (default), 'upper', 'both'
--    Collision-free as long as the key and sequence are stable.
--
--    SECURITY MODEL:
--    - Minimum 16-bit domain prevents brute-force sequence prediction
--    - Adaptive Feistel rounds scale with domain size
--    - Defense in depth: large state space + strong cryptographic mixing
--
--    PERFORMANCE IMPACT FOR SMALL ID LENGTHS:
--    Small IDs are cryptographically expensive due to cycle-walking overhead.
--    Each rejected value requires a full Feistel evaluation (10-12 rounds).
--
--    Expected generation cost by length (for Winter's Base29 alphabets):
--    - len=1 (28 total IDs):       ~2,341 avg Feistel evaluations per ID
--    - len=2 (812 total IDs):      ~81 avg Feistel evaluations per ID
--    - len=3 (23,548 total IDs):   ~3 avg Feistel evaluations per ID
--    - len=4+ (682K+ IDs):         ~1-2 avg Feistel evaluations per ID
--
--    Winter's Base50 ('both') provides significantly more capacity (~1.72^n times)
--    and reduces cycle-walking overhead proportionally.
--
--    Recommendation: Avoid len=1-2 for high-throughput use cases, or accept
--    the performance cost as the price of securing such small ID spaces.
------------------------------------------------------------
CREATE OR REPLACE FUNCTION generate_public_id(_len int DEFAULT 6, _alphabet_type text DEFAULT 'lower')
    RETURNS text AS
$$
DECLARE
    secret      text;
    alphabet    text;
    base        int;

    powL        bigint := 1;
    powLm1      bigint := 1;

    min_idx     bigint;
    cap         bigint;

    domain_bits int;
    domain_max  bigint;

    seq_val     bigint;
    x           bigint;
    y           bigint;
BEGIN
    -- Supported lengths: 1..12
    IF _len < 1 OR _len > 12 THEN
        RAISE EXCEPTION 'generate_public_id: length % not supported (must be 1..12)', _len;
    END IF;

    -- Select alphabet based on type
    CASE _alphabet_type
        WHEN 'lower' THEN alphabet := '23456789bcdfghjklmnpqrstvwxyz';
        WHEN 'upper' THEN alphabet := '23456789BCDFGHJKLMNPQRSTVWXYZ';
        WHEN 'both' THEN alphabet := '23456789bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ';
        ELSE RAISE EXCEPTION 'generate_public_id: unsupported alphabet type %. Use ''lower'', ''upper'', or ''both''', _alphabet_type;
    END CASE;

    base := length(alphabet);

    -- Load secret key stored inside DB
    secret := get_public_id_key();

    -- Compute base^(len-1) and base^len
    FOR i IN 1.._len
        LOOP
            powL := powL * base;
            IF i < _len THEN
                powLm1 := powLm1 * base;
            END IF;
        END LOOP;

    min_idx := powLm1;
    cap := powL - powLm1;

    -- Calculate the natural power-of-two domain that fits the capacity
    domain_bits := 0;
    domain_max := 1;

    WHILE domain_max < cap
        LOOP
            domain_max := domain_max * 2;
            domain_bits := domain_bits + 1;
        END LOOP;

    -- Enforce minimum 16-bit domain for security, even if capacity is smaller.
    -- Without this, small ID lengths would have dangerously small state spaces:
    --   len=1: natural domain 64 values (6 bits) - trivially brute-forceable
    --   len=2: natural domain 1,024 values (10 bits) - weak against prediction
    --
    -- The 16-bit minimum (65,536 values) provides adequate security against
    -- sequence prediction attacks, at the cost of cycle-walking overhead
    -- for small ID lengths (see performance notes in function header).
    IF domain_bits < 16 THEN
        domain_bits := 16;
        domain_max := 1::bigint << 16;
    END IF;

    -- Ensure Feistel domain has even bit-width (required for equal-width halves)
    IF (domain_bits % 2) = 1 THEN
        domain_bits := domain_bits + 1;
        domain_max := domain_max * 2;
    END IF;

    IF domain_bits > 62 THEN
        RAISE EXCEPTION
            'generate_public_id: capacity % needs % bits (max 62)',
            cap, domain_bits;
    END IF;

    seq_val := nextval('public_id_seq');
    x := seq_val - 1;

    IF x >= cap THEN
        RAISE EXCEPTION
            'generate_public_id: out of IDs for length %, seq=% (cap=%)',
            _len, seq_val, cap;
    END IF;

    -- Apply Feistel PRP with cycle-walking (rejection sampling).
    -- When domain_max > cap, we repeatedly apply Feistel until we get a valid value.
    -- For small IDs with the 16-bit minimum domain, this creates performance overhead:
    --   - Expected iterations = domain_max / cap
    --   - Each iteration applies full Feistel (10-12 rounds for small domains)
    --   - This is the security trade-off for protecting small ID spaces
    y := feistel_prp_pow2(x, secret, domain_bits);
    WHILE y >= cap
        LOOP
            y := feistel_prp_pow2(y, secret, domain_bits);
        END LOOP;

    RETURN encode_base_public_id(min_idx + y, _len, alphabet);
END;
$$ LANGUAGE plpgsql;

------------------------------------------------------------
-- 6) Example usage
------------------------------------------------------------
-- 6-character public IDs by default (~574M usable IDs with lowercase alphabet)
-- CREATE TABLE IF NOT EXISTS accounts (
--     id        UUID PRIMARY KEY DEFAULT uuidv7(),
--     public_id VARCHAR(6) NOT NULL UNIQUE DEFAULT generate_public_id(6),           -- lowercase (default)
--     public_id VARCHAR(6) NOT NULL UNIQUE DEFAULT generate_public_id(6, 'lower'),  -- explicit lowercase
--     public_id VARCHAR(6) NOT NULL UNIQUE DEFAULT generate_public_id(6, 'upper'),  -- uppercase only
--     public_id VARCHAR(6) NOT NULL UNIQUE DEFAULT generate_public_id(6, 'both')    -- mixed case (~15.3B usable IDs)
-- );