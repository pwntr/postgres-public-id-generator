# Public ID Generator for PostgreSQL

**Deterministic, collision-free, fixed-length, non-guessable, profanity-safe public identifiers**  

A proper public ID generator for PostgreSQL without business information leakage or accidental profanity.

Built entirely in PostgreSQL (PL/pgSQL) using a Feistel network + a database embedded secret key.

---

## ✨ Overview

This repository provides a self-contained SQL module for PostgreSQL that generates **public-facing IDs** which are:

- **Short** (1–12 characters, developer-selectable)
- **Collision-free** (guaranteed as long as the internal sequence is not reset)
- **Non-guessable / non-sequential**  
  A Feistel permutation keyed with a secret hides the underlying sequence number.
- **Deterministic** (IDs never change after generation)
- **Profanity-safe**  
  The alphabet contains **no vowels and no ambiguous characters**, eliminating bad/unsafe words. No static blocklist required!
- **Predictably sized** (no padding or irregular lengths)
- **Fast** (microsecond-level generation)
- **Self-contained** (no extension required besides pgcrypto)

This is ideal for generating public URLs, user-visible IDs, subdomains, invitation codes, account references, etc.

---

## 🧠 How It Works

The generator internally uses:

1. A **monotonic PostgreSQL sequence** (`public_id_seq`)
2. A **cryptographically keyed Feistel network** (HMAC-SHA256)
3. **Three profanity-safe alphabet options**:
   - **lowercase** (default): `23456789bcdfghjklmnpqrstvwxyz` — **Winter's Base29**
   - **uppercase**: `23456789BCDFGHJKLMNPQRSTVWXYZ` — **Winter's Base29** (uppercase variant)
   - **both**: `23456789bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ` — **Winter's Base50**
4. A **fixed-length number band** (base^(L-1) to base^L - 1)
5. A **Feistel domain sized to a power of two** (minimum 16 bits), using cycle-walking to ensure perfect uniformity.

The end result is:

### → A permutation of the integer sequence space  
Every integer maps to exactly one public ID, and vice versa (conceptually; we never decode).

### → No collisions  
Sequence numbers never repeat → Feistel PRP never collides → final encoded IDs are unique.

### → No information leakage  
Attackers cannot derive:
- sequence numbers  
- account creation order  
- total business volume  
- predict next IDs

### → No bad words
All alphabets contain **no vowels** (a, e, i, o, u), so accidental profanity is impossible.
They also omit visually confusing characters (`0`, `O`, `o`, `1`), preventing common [leetspeak](https://en.wikipedia.org/wiki/Leet) permutations of profane words. The [squids blocklist](https://raw.githubusercontent.com/sqids/sqids-blocklist/refs/heads/main/output/blocklist.json), which also contains leetspeak variants, was used for matching verification. This blocklist was the inspiration for this project and the alphabets used here, aiming for the goal to elimante a static list lookup with retries altogether, at the cost of just a wee bit less keyspace.

---

## 🚀 Installation & Usage

### 1. Run the SQL file

```sql
\i public_id_generator.sql
```

This creates:

- the secret key table (`public_id_key`)
- the Feistel PRP function (`feistel_prp_pow2`)
- the variable-base encoder (`encode_base_public_id`)
- the global sequence (`public_id_seq`)
- the main function: `generate_public_id(len int default 6, alphabet_type text default 'lower')`

The first call automatically generates a secret key stored inside PostgreSQL.

#### Docker container
Check out the `Dockerfile` to see how to bootstrap a fresh postgres container with init scripts copied to the `/docker-entrypoint-initdb.d` dir on the first start.

---

### 2. Use in a table definition

```sql
CREATE TABLE accounts (
    id         BIGSERIAL PRIMARY KEY,
    public_id  varchar(6) NOT NULL UNIQUE DEFAULT generate_public_id(6)  -- lowercase (default)
);
```

The default length is 6 characters and alphabet is lowercase, but you can choose:
- Any length from **1 to 12**
- Any alphabet: `'lower'` (default), `'upper'`, or `'both'`

```sql
DEFAULT generate_public_id(7)                 -- 7 chars, lowercase
DEFAULT generate_public_id(8, 'upper')        -- 8 chars, uppercase
DEFAULT generate_public_id(10, 'both')        -- 10 chars, mixed case
```

---

### 3. Generating IDs manually

```sql
SELECT generate_public_id();                -- uses defaults: length 6, lowercase
SELECT generate_public_id(8);               -- 8 characters, lowercase
SELECT generate_public_id(8, 'upper');      -- 8 characters, uppercase
SELECT generate_public_id(12, 'both');      -- maximum length, mixed case
```

---

## 📦 Features

### ✓ Fixed-length IDs  
Each chosen length uses its own base-29/50 numeric band, so no padding is needed.

### ✓ Fully local: no external dependencies  
Only requires:

```
CREATE EXTENSION pgcrypto;
```

### ✓ High entropy / non-guessable  
IDs hide the underlying sequence using a keyed pseudorandom permutation.

### ✓ Automatic key generation  
The Feistel key is generated once and stored inside PostgreSQL. No need to manage it externally.

### ✓ Stateless app servers  
Because ID generation happens centrally *in Postgres*, you need no coordination across services.

### ✓ Profanity-safe
All alphabets contain:

- no vowels (a, e, i, o, u)
- no ambiguous characters (0, O, l, 1)

This is especially important when IDs appear in:

- URLs  
- subdomains  
- user-facing dashboards  
- marketing emails

### ✓ Scalable keyspace
Capacity grows exponentially with length and alphabet size:

**Single-case alphabets** (lowercase `lower` or uppercase `upper`, Winter's Base29):

| ID Length | Usable Unique IDs         |
|-----------|---------------------------|
| 1         | 28                        |
| 2         | 812                       |
| 3         | 23,548                    |
| 4         | 682,892                   |
| 5         | 19,803,868                |
| 6         | 574,312,172               |
| 7         | 16,655,052,988            |
| 8         | 482,996,536,652           |
| 9         | 14,006,899,562,908        |
| 10        | 406,200,087,324,332       |
| 11        | 11,779,802,532,405,628    |
| 12        | 341,614,273,439,763,212   |

**Mixed-case alphabet** (`'both'`, Winter's Base50):

| ID Length | Usable Unique IDs             |
|-----------|-------------------------------|
| 1         | 49                            |
| 2         | 2,450                         |
| 3         | 122,500                       |
| 4         | 6,125,000                     |
| 5         | 306,250,000                   |
| 6         | 15,312,500,000                |
| 7         | 765,625,000,000               |
| 8         | 38,281,250,000,000            |
| 9         | 1,914,062,500,000,000         |
| 10        | 95,703,125,000,000,000        |
| 11        | 4,785,156,250,000,000,000     |
| 12        | 239,257,812,500,000,000,000   |


If you outgrow one length or need more capacity, simply increase the column length or switch alphabets:

```sql
-- Increase length
ALTER TABLE accounts ALTER COLUMN public_id TYPE varchar(7);
ALTER TABLE accounts ALTER COLUMN public_id SET DEFAULT generate_public_id(7);

-- Or switch to mixed-case for ~15.3 billion IDs at length 6
ALTER TABLE accounts ALTER COLUMN public_id TYPE varchar(6);
ALTER TABLE accounts ALTER COLUMN public_id SET DEFAULT generate_public_id(6, 'both');
```

Old IDs remain valid and collision-free, each length brings its own keyspace.

---

## ⚠️ Limitations & Things to Know

### 1. **Never reset the sequence**
Resetting:

```sql
ALTER SEQUENCE public_id_seq RESTART;
```

will cause duplicates, because the same input will map to the same output.

### 2. **Never delete the key**
If you run:

```sql
DELETE FROM public_id_key;
```

a new key will be generated → *all future IDs change permutation behavior*.

Keep the key stable for the lifetime of an ID namespace.

### 3. **Changing length or alphabet creates a new keyspace**
6-char IDs and 7-char IDs do not collide, because they encode different integer bands.
Similarly, lowercase and uppercase/mixed-case IDs do not collide.

This is a feature — it lets you increase capacity without migrations.

### 4. **This is not encryption**
This hides sequence order and prevents prediction, but is not intended for encrypting sensitive data.

### 5. **Changing cryptographic parameters breaks determinism**
If you change Feistel rounds or hashing logic, previously generated IDs cannot be reproduced.

### 6. **Performance considerations for very small ID lengths**
The code enforces a minimum 16-bit Feistel domain for security. This means:
- **Length 1-2 IDs** experience significant cycle-walking overhead (many Feistel evaluations per ID)
- **Length 3+** are performant with minimal overhead

Expected generation cost (average Feistel evaluations per ID) for Winter's Base29:
- Length 1: ~2,341 evaluations per ID
- Length 2: ~81 evaluations per ID
- Length 3: ~3 evaluations per ID
- Length 4+: ~1-2 evaluations per ID

Winter's Base50 (`'both'`) reduces this overhead significantly due to larger capacity.

**Recommendation**: For high-throughput scenarios, use length 3 or greater, or accept the performance trade-off for securing small ID spaces.

---

## 🧪 Testing for duplicates

To sanity-check your installation:

```sql
WITH ids AS (
  SELECT generate_public_id(6) AS id
  FROM generate_series(1, 200000)
)
SELECT id, COUNT(*)
FROM ids
GROUP BY id
HAVING COUNT(*) > 1;
```

Should return **zero rows**, no matter how many you generate.

---

## 🛠️ Use Cases

- User account IDs  
- Public-facing resource IDs  
- API keys (non-secret)  
- Permanent share links  
- Subdomains like `https://{public-id}.example.com`  
- Invoice/order IDs  
- Invitation codes  
- Tenant IDs for multi-tenant SaaS  
- Shortened but collision-free handles

Perfect when you want:

- Short IDs instead of those long UUIDs  
- Globally unique IDs across distributed systems  
- No sequentially growing numbers  
- No embarrassing words in URLs  
- No rigid external dependencies  

---

## 🧑‍💻 Why Feistel?

A Feistel network is a lightweight pseudorandom permutation (PRP):

- reversible per round  
- preserves bijection (1–1 mapping)  
- allows arbitrary bit width (up to 62 bits in bigint)  
- fast and secure when keyed with HMAC-SHA256  

This design guarantees that:

```
Sequence number → scrambled → encoded → public ID
```

remains:

- unique  
- non-reversible  
- non-sequential  
- uniformly distributed  

---

## 📜 License

MIT — free for use in commercial and personal projects, see `LICENSE` for details.