#!/usr/bin/env python3
"""Matrix Dead Drop

A small CLI project that demonstrates matrix-based encryption over a finite
field. It is meant for learning, not for real-world security.

The program works with UTF-8 text, turns it into numbers, groups those numbers
into fixed-size blocks, and scrambles each block with an invertible matrix.
Decryption uses the inverse matrix to recover the original text.
"""

from __future__ import annotations

import argparse
import json
import random
import secrets
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List, Sequence

DEFAULT_MODULUS = 257  # Prime modulus for clean modular arithmetic.
DEFAULT_PADDING_VALUE = 256  # Safe padding marker; valid UTF-8 bytes are 0-255.

Matrix = List[List[int]]
Vector = List[int]


@dataclass(frozen=True)
class KeyBundle:
    """Container for the secret matrix and its metadata."""

    size: int
    modulus: int
    matrix: Matrix

    def to_dict(self) -> dict:
        return {
            "size": self.size,
            "modulus": self.modulus,
            "matrix": self.matrix,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "KeyBundle":
        return cls(
            size=int(data["size"]),
            modulus=int(data.get("modulus", DEFAULT_MODULUS)),
            matrix=[[int(cell) for cell in row] for row in data["matrix"]],
        )


def seeded_random(seed: int | None):
    """Return a random-number generator.

    When seed is None, use a system RNG. When seed is provided, use a repeatable
    RNG so the same seed produces the same output.
    """

    if seed is None:
        return secrets.SystemRandom()
    return random.Random(seed)


def normalize(value: int, modulus: int) -> int:
    return value % modulus


def modular_inverse(value: int, modulus: int) -> int:
    value = normalize(value, modulus)
    if value == 0:
        raise ValueError("Zero does not have a modular inverse.")
    return pow(value, -1, modulus)


def matrix_identity(size: int) -> Matrix:
    return [[1 if row == col else 0 for col in range(size)] for row in range(size)]


def matrix_multiply(left: Matrix, right: Matrix, modulus: int) -> Matrix:
    """Multiply two matrices using modular arithmetic."""

    row_count = len(left)
    shared_size = len(right)
    column_count = len(right[0])
    product = [[0 for _ in range(column_count)] for _ in range(row_count)]

    for row_index in range(row_count):
        for shared_index in range(shared_size):
            left_value = normalize(left[row_index][shared_index], modulus)
            if left_value == 0:
                continue
            for col_index in range(column_count):
                product[row_index][col_index] = (
                    product[row_index][col_index]
                    + left_value * normalize(right[shared_index][col_index], modulus)
                ) % modulus

    return product


def vector_to_column(vector: Vector) -> Matrix:
    return [[value] for value in vector]


def column_to_vector(column: Matrix) -> Vector:
    return [row[0] for row in column]


def matrix_vector_multiply(matrix: Matrix, vector: Vector, modulus: int) -> Vector:
    return column_to_vector(matrix_multiply(matrix, vector_to_column(vector), modulus))


def invert_matrix(matrix: Matrix, modulus: int) -> Matrix:
    """Invert a square matrix using Gauss-Jordan elimination."""

    size = len(matrix)
    if any(len(row) != size for row in matrix):
        raise ValueError("Matrix must be square.")

    augmented = [
        [normalize(value, modulus) for value in row] + identity_row
        for row, identity_row in zip(matrix, matrix_identity(size))
    ]

    for pivot_column in range(size):
        pivot_row = None
        for candidate_row in range(pivot_column, size):
            if augmented[candidate_row][pivot_column] % modulus != 0:
                pivot_row = candidate_row
                break

        if pivot_row is None:
            raise ValueError("Matrix is not invertible with this modulus.")

        if pivot_row != pivot_column:
            augmented[pivot_column], augmented[pivot_row] = (
                augmented[pivot_row],
                augmented[pivot_column],
            )

        pivot_value = augmented[pivot_column][pivot_column] % modulus
        pivot_inverse = modular_inverse(pivot_value, modulus)
        augmented[pivot_column] = [
            (entry * pivot_inverse) % modulus for entry in augmented[pivot_column]
        ]

        for row_index in range(size):
            if row_index == pivot_column:
                continue

            factor = augmented[row_index][pivot_column] % modulus
            if factor == 0:
                continue

            augmented[row_index] = [
                (current - factor * pivot_cell) % modulus
                for current, pivot_cell in zip(augmented[row_index], augmented[pivot_column])
            ]

    return [row[size:] for row in augmented]


def is_invertible(matrix: Matrix, modulus: int) -> bool:
    try:
        invert_matrix(matrix, modulus)
        return True
    except ValueError:
        return False


def generate_key(size: int, modulus: int = DEFAULT_MODULUS, seed: int | None = None) -> KeyBundle:
    if size < 2:
        raise ValueError("Matrix size must be at least 2.")
    if modulus <= 2:
        raise ValueError("Modulus must be greater than 2.")

    rng = seeded_random(seed)
    for _ in range(10000):
        matrix = [[rng.randrange(modulus) for _ in range(size)] for _ in range(size)]
        if is_invertible(matrix, modulus):
            return KeyBundle(size=size, modulus=modulus, matrix=matrix)

    raise RuntimeError("Could not generate an invertible matrix.")


def text_to_bytes(text: str) -> list[int]:
    return list(text.encode("utf-8"))


def bytes_to_text(values: Sequence[int]) -> str:
    return bytes(values).decode("utf-8")


def pad_values(values: list[int], block_size: int) -> list[int]:
    remainder = len(values) % block_size
    if remainder == 0:
        return values
    padding_needed = block_size - remainder
    return values + [DEFAULT_PADDING_VALUE] * padding_needed


def chunk_values(values: Sequence[int], block_size: int) -> list[Vector]:
    if len(values) % block_size != 0:
        raise ValueError("Values are not aligned to the block size.")
    return [list(values[index : index + block_size]) for index in range(0, len(values), block_size)]


def encrypt_text(text: str, key: KeyBundle) -> dict:
    plain_bytes = text_to_bytes(text)
    padded_bytes = pad_values(plain_bytes, key.size)
    blocks = chunk_values(padded_bytes, key.size)
    cipher_blocks = [matrix_vector_multiply(key.matrix, block, key.modulus) for block in blocks]

    return {
        "version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "modulus": key.modulus,
        "block_size": key.size,
        "original_length": len(plain_bytes),
        "cipher": cipher_blocks,
    }


def decrypt_payload(payload: dict, key: KeyBundle) -> str:
    payload_block_size = int(payload["block_size"])
    payload_modulus = int(payload.get("modulus", key.modulus))
    original_length = int(payload.get("original_length", 0))

    if payload_block_size != key.size:
        raise ValueError("Payload block size does not match the key size.")
    if payload_modulus != key.modulus:
        raise ValueError("Payload modulus does not match the key modulus.")

    inverse_matrix = invert_matrix(key.matrix, key.modulus)
    plain_bytes: list[int] = []

    for block in payload["cipher"]:
        if len(block) != key.size:
            raise ValueError("A cipher block has the wrong length.")
        recovered_block = matrix_vector_multiply(
            inverse_matrix,
            [int(cell) for cell in block],
            key.modulus,
        )
        plain_bytes.extend(recovered_block)

    if original_length > 0:
        plain_bytes = plain_bytes[:original_length]

    return bytes_to_text(plain_bytes)


def read_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path: Path, data: dict) -> None:
    with path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, ensure_ascii=False)
        handle.write("\n")


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def load_key(path: Path) -> KeyBundle:
    return KeyBundle.from_dict(read_json(path))


def save_key(path: Path, key: KeyBundle) -> None:
    write_json(path, key.to_dict())


def read_message(args: argparse.Namespace) -> str:
    if args.text is not None:
        return args.text
    if args.input is not None:
        return read_text(Path(args.input))
    raise SystemExit("Provide either --text or --input.")


def print_matrix(matrix: Matrix) -> None:
    for row in matrix:
        print("  ", row)


def cmd_generate_key(args: argparse.Namespace) -> int:
    key = generate_key(args.size, DEFAULT_MODULUS, args.seed)
    output_path = Path(args.output)
    save_key(output_path, key)

    print(f"Key written to {output_path}")
    print("Key matrix:")
    print_matrix(key.matrix)
    return 0


def cmd_encrypt(args: argparse.Namespace) -> int:
    key = load_key(Path(args.key))
    message = read_message(args)
    payload = encrypt_text(message, key)
    output_path = Path(args.output)
    write_json(output_path, payload)

    print(f"Encrypted dead drop written to {output_path}")
    print(f"Blocks: {len(payload['cipher'])}")
    return 0


def cmd_decrypt(args: argparse.Namespace) -> int:
    key = load_key(Path(args.key))
    payload = read_json(Path(args.input))
    recovered_text = decrypt_payload(payload, key)

    if args.output:
        output_path = Path(args.output)
        write_text(output_path, recovered_text)
        print(f"Recovered text written to {output_path}")
    else:
        print(recovered_text)
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    key = generate_key(args.size, DEFAULT_MODULUS, args.seed)
    payload = encrypt_text(args.text, key)
    recovered_text = decrypt_payload(payload, key)

    print("Demo key matrix:")
    print_matrix(key.matrix)
    print()
    print("Cipher payload:")
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    print()
    print("Recovered text:")
    print(recovered_text)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="matrix-dead-drop",
        description="Educational matrix-based dead drop encryption CLI.",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    key_parser = subparsers.add_parser("generate-key", help="Create a new invertible key matrix.")
    key_parser.add_argument("-s", "--size", type=int, default=3, help="Matrix size. Default: 3.")
    key_parser.add_argument("-o", "--output", default="key.json", help="Output file for the key.")
    key_parser.add_argument("--seed", type=int, default=None, help="Use a fixed seed for repeatable output.")
    key_parser.set_defaults(func=cmd_generate_key)

    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt text into a dead drop JSON file.")
    encrypt_parser.add_argument("-k", "--key", required=True, help="Path to the key JSON file.")
    encrypt_parser.add_argument("-o", "--output", default="drop.json", help="Output file for the encrypted payload.")
    message_source = encrypt_parser.add_mutually_exclusive_group(required=True)
    message_source.add_argument("--text", help="Text to encrypt.")
    message_source.add_argument("--input", help="Read text from a file.")
    encrypt_parser.set_defaults(func=cmd_encrypt)

    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt a dead drop JSON file.")
    decrypt_parser.add_argument("-k", "--key", required=True, help="Path to the key JSON file.")
    decrypt_parser.add_argument("-i", "--input", required=True, help="Encrypted JSON file.")
    decrypt_parser.add_argument("-o", "--output", help="Write recovered text to a file.")
    decrypt_parser.set_defaults(func=cmd_decrypt)

    demo_parser = subparsers.add_parser("demo", help="Run encryption and decryption in one step.")
    demo_parser.add_argument("--text", default="Matrix Dead Drop", help="Demo text.")
    demo_parser.add_argument("-s", "--size", type=int, default=3, help="Matrix size. Default: 3.")
    demo_parser.add_argument("--seed", type=int, default=None, help="Use a fixed seed for repeatable output.")
    demo_parser.set_defaults(func=cmd_demo)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        return int(args.func(args))
    except BrokenPipeError:
        return 1
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
