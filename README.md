## 📌 Features

- Fetches TLS server leaf certificate using SNI
- Saves certificate in PEM format
- Supports both PEM and DER file loading
- Displays certificate metadata (subject, issuer, validity)
- Detects Elliptic Curve (EC) public keys
- Extracts EC public point coordinates (x, y)
- Displays domain parameters for known EC curves
- Supports RSA/DSA fallback inspection
- CLI-based fetch and inspect modes

---

## 📂 Function Explanations

---

### ✅ `fetch_leaf_pem(host, port=443, out_file="server_cert.pem", timeout=5.0)`

**Purpose:**  
Connects to a remote TLS server and downloads the **leaf X.509 certificate**, saving it locally as a PEM file.

**How it works (brief):**
- Creates a secure TLS context using system CA trust
- Wraps a TCP socket using TLS and enables **SNI**
- Connects to the target host and port
- Retrieves the certificate in **DER format**
- Converts DER to PEM and writes it to disk

**Inputs:**
- `host` → Target server hostname  
- `port` → TLS port (default: `443`)  
- `out_file` → Filename to save the certificate  
- `timeout` → Socket timeout duration  

**Output:**  
- Returns the saved PEM file path

---

### ✅ `load_cert_from_file(pem_file)`

**Purpose:**  
Loads a certificate file from disk and automatically detects whether it is in **PEM or DER format**.

**How it works:**
- Reads raw bytes from the file
- Attempts to parse as PEM first
- If PEM fails, retries using DER format

**Output:**  
- Returns a `cryptography.x509.Certificate` object

---

### ✅ `print_ec_details(public_key)`

**Purpose:**  
Displays full **Elliptic Curve public key information** from the certificate.

**What it prints:**
- Curve name and key size
- Public EC point coordinates:
  - `x` coordinate
  - `y` coordinate
- If the curve is recognized:
  - Prime modulus `p`
  - Curve coefficients `a` and `b`
  - Generator point `Gx`, `Gy`
  - Group order `n`
  - Cofactor `h`
- The full **curve equation**

**Special behavior:**
- Automatically maps aliases like:
  - `P-256` → `secp256r1`
  - `prime256v1` → `secp256r1`
- If the curve is not found in the local registry, it prints a warning

---

### ✅ `inspect_certificate(pem_file)`

**Purpose:**  
Loads a certificate and prints its **identity, validity period, and public key details**.

**What it prints:**
- Subject
- Issuer
- Validity period:
  - `NotBefore`
  - `NotAfter`
- Public key inspection:
  - EC keys → calls `print_ec_details()`
  - RSA/DSA keys → prints key type and key size

**Why it’s important:**  
This function performs the **main analysis and inspection logic** for both remote and local certificates.

---

### ✅ `main(argv)`

**Purpose:**  
Handles **command-line argument parsing and execution flow**.

**Modes supported:**

#### 🔹 Inspect Mode
```bash
python save_leaf_cert_with_ec_check.py --inspect cert.pem
```
- Loads and analyzes a local certificate file

#### 🔹 Fetch + Inspect Mode
```bash
python save_leaf_cert_with_ec_check.py example.com 443 output.pem
```
- Connects to the server
- Downloads the leaf certificate
- Automatically inspects it

**Default behavior:**
- Port defaults to `443`
- Output file defaults to `server_cert.pem`


---

## ⚠️ Important Note

- Only the **leaf certificate** is downloaded (not the full chain)
