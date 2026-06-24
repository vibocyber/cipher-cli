# Matrix Dead Drop

Matrix Dead Drop is a small command-line cryptography project that turns text into numbers, scrambles those numbers with an invertible matrix, and restores the original message with the inverse matrix.

It is an educational demo. It is not meant for real secret storage.

## What it does

* Generates a random invertible key matrix
* Encrypts text or a file into a JSON payload
* Decrypts the JSON payload back into the original text
* Runs from the command line
* Uses only Python's standard library

## Why I built it

I wanted to understand how matrix-based ciphers work, so I built a small version from scratch. The goal was to see how linear algebra, modular arithmetic, and reversible transformations fit together in one simple project.

This is a learning project, not a replacement for modern cryptographic algorithms such as AES.

## How it works

### 1) Text becomes bytes

Python encodes the message in UTF-8.

Each byte is a number from `0` to `255`.

Example:

* `A` → `65`
* `hi` → `[104, 105]`

### 2) Bytes become blocks

The bytes are grouped into fixed-size blocks that match the matrix dimension.

Example:

```text
[104, 105, 33]
[112, 108, 97]
[105, 110, 116]
```

### 3) Encryption uses matrix multiplication

Each block is treated like a vector.

The key matrix multiplies the vector under modular arithmetic:

```text
cipher_block = key_matrix × plain_block (mod 257)
```

The modulus is `257`, which is prime. That keeps the math clean and makes modular inverses work properly.

### 4) Decryption uses the inverse matrix

Because the key matrix is invertible, there is an inverse matrix `K⁻¹` such that:

```text
K⁻¹ × K = I
```

So decryption is:

```text
plain_block = K⁻¹ × cipher_block (mod 257)
```

### 5) Padding is handled automatically

If the message length is not a multiple of the block size, the last block is padded.

The original byte length is stored in the payload, so the exact message is recovered on decrypt.

## File format

The encrypted payload is stored as JSON.

Example:

```json
{
  "version": 1,
  "modulus": 257,
  "block_size": 3,
  "original_length": 9,
  "cipher": [[12, 88, 210], [44, 9, 173]]
}
```

## Commands

### Generate a key

```bash
python matrix_dead_drop.py generate-key
```
By default, the key is written to key.json.

```
The same key file is required later to decrypt encrypted messages.
```
### Encrypt text

Encrypt a direct message:

```bash
python matrix_dead_drop.py encrypt -k key.json --text "hello world" -o drop.json
```

Encrypt from a file:

```bash
python matrix_dead_drop.py encrypt -k key.json --input message.txt -o drop.json
```

### Decrypt the payload

```bash
python matrix_dead_drop.py decrypt -k key.json --input drop.json
```

To view all available options:

```bash
python matrix_dead_drop.py -h
python matrix_dead_drop.py encrypt -h
python matrix_dead_drop.py decrypt -h
```

## Example Workflow

```bash
python matrix_dead_drop.py generate-key -o key.json
python matrix_dead_drop.py encrypt -k key.json --text "Meet at 9" -o drop.json
python matrix_dead_drop.py decrypt -k key.json --input drop.json
```

## Project Structure

```text
matrix-dead-drop/
├── matrix_dead_drop.py
└── README.md
```

## Limitations

* Not secure for real-world secret storage
* Key files must be protected manually
* Anyone with the key matrix can decrypt the payload
* This is a classical cipher, not modern authenticated encryption
