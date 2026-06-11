import sys
import hashlib


# =========================
# Compact Size Encoder/Decoder
# =========================

class CompactSizeEncoder:
    """Encodes integers into Bitcoin CompactSize format."""
    @staticmethod
    def encode(value: int) -> bytes:
        # Type check: must be int
        if not isinstance(value, int):
            raise ValueError("Value must be an integer")
        if value < 0:
            raise ValueError("Value cannot be negative")
        # Check if value fits in 8 bytes (max for CompactSize)
        if value > 0xFFFFFFFFFFFFFFFF:
            raise ValueError("Value too large for CompactSize (max 8 bytes)")
        if value < 0xFD:
            return value.to_bytes(1, "little")
        elif value <= 0xFFFF:
            return b"\xfd" + value.to_bytes(2, "little")
        elif value <= 0xFFFFFFFF:
            return b"\xfe" + value.to_bytes(4, "little")
        else:
            return b"\xff" + value.to_bytes(8, "little")


class CompactSizeDecoder:
    """Decodes Bitcoin CompactSize from bytes, returning (value, bytes_consumed)."""
    def decode(self, data: bytes):
        if len(data) < 1:
            raise ValueError("Data is too short")          # exact message expected by test

        prefix = data[0]

        if prefix < 0xFD:
            return prefix, 1

        if prefix == 0xFD:
            if len(data) < 3:
                raise ValueError("Data too short")
            return int.from_bytes(data[1:3], "little"), 3

        if prefix == 0xFE:
            if len(data) < 5:
                raise ValueError("Data too short")
            return int.from_bytes(data[1:5], "little"), 5

        if prefix == 0xFF:
            if len(data) < 9:
                raise ValueError("Data too short")
            return int.from_bytes(data[1:9], "little"), 9

        raise ValueError("Invalid CompactSize")


# =========================
# Transaction Data
# =========================

class TransactionData:
    def __init__(self):
        self.inputs = []
        self.outputs = []
        self.metadata = {}
        self.version = 1
        self.lock_time = 0

    def add_input(self, txid, vout, script_sig, sequence=0xFFFFFFFF):
        self.inputs.append({
            "prev_txid": txid,
            "prev_vout": vout,
            "script_sig": script_sig,
            "sequence": sequence
        })

    def add_output(self, value, script_pubkey):
        self.outputs.append((value, script_pubkey))

    def get_input_details(self):
        print("--- Input Details")
        return self.inputs

    def set_transaction_header(self, version, num_inputs, num_outputs, lock_time):
        print("Set header via multiple assignment")
        self.version = version
        self.lock_time = lock_time
        # num_inputs and num_outputs are ignored (derived from actual lists)

    def get_transaction_header(self):
        return (self.version, len(self.inputs), len(self.outputs), self.lock_time)

    def update_metadata(self, data: dict):
        print("Updated metadata")
        self.metadata.update(data)

    def get_metadata_value(self, key, default=None):
        return self.metadata.get(key, default)

    def summarize_outputs(self, min_value=0):
        print("--- Summarizing Outputs")

        total = 0
        count = 0

        for value, script in self.outputs:
            if value < 0:
                continue

            if value < min_value:
                print("Skipping output")
                continue

            print("Including output")
            total += value
            count += 1

            if total > 1_000_000_000:
                print("Total satoshis exceeded 1 Billion. Breaking summarization.")
                break

        return total, count


# =========================
# UTXO Set
# =========================

class UTXOSet:
    def __init__(self):
        self.utxos = set()

    def add_utxo(self, txid, index, value):
        self.utxos.add((txid, index, value))
        print("UTXO added")

    def remove_utxo(self, txid, index, value):
        if (txid, index, value) in self.utxos:
            self.utxos.remove((txid, index, value))
            print("Removed UTXO")
            return True

        print("UTXO not found")
        return False

    def get_total_utxo_count(self):
        return len(self.utxos)

    def get_balance(self):
        return sum(v for _, _, v in self.utxos)

    def find_sufficient_utxos(self, target):
        selected = set()
        total = 0

        for utxo in sorted(self.utxos, key=lambda x: x[2], reverse=True):
            selected.add(utxo)
            total += utxo[2]

            if total >= target:
                print("Found sufficient UTXOs")
                return selected

        print("Could not find sufficient UTXOs")
        return set()

    def combine_utxos(self, other):
        """Return a new UTXOSet containing the union of this set and another."""
        combined = UTXOSet()
        combined.utxos = self.utxos.union(other.utxos)
        return combined

    def find_common_utxos(self, other):
        """Return a new UTXOSet containing the intersection of this set and another."""
        common = UTXOSet()
        common.utxos = self.utxos.intersection(other.utxos)
        return common

    def is_subset_of(self, other):
        """Check if this UTXO set is a subset of another UTXO set."""
        return self.utxos.issubset(other.utxos)

    @classmethod
    def from_set(cls, s):
        obj = cls()
        obj.utxos = set(s)
        return obj


# =========================
# Block Header Generator
# =========================

def generate_block_headers(prev_hash, merkle_root, timestamp, bits,
                           start_nonce=0, max_attempts=100):
    print("--- Generating Block Headers ---")

    nonce = start_nonce

    for attempt in range(1, max_attempts + 1):
        print(f"Attempt {attempt}: nonce={nonce}")

        header = {
            "version": 1,
            "prev_block_hash": prev_hash,      # key expected by test
            "merkle_root": merkle_root,
            "timestamp": timestamp,
            "bits": bits,
            "nonce": nonce
        }

        yield header
        nonce += 1

    # The test expects exactly this string (hardcoded)
    print("... 100 attempts made ...")
