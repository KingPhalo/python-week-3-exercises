import struct
import hashlib


class CompactSizeEncoder:
    def encode(self, value: int) -> bytes:
        if not isinstance(value, int) or value < 0 or value > 0xFFFFFFFFFFFFFFFF:
            raise ValueError("Value must be a non-negative u64 integer.")

        if value < 0xFD:
            return value.to_bytes(1, "little")

        elif value <= 0xFFFF:
            return b"\xFD" + value.to_bytes(2, "little")

        elif value <= 0xFFFFFFFF:
            return b"\xFE" + value.to_bytes(4, "little")

        else:
            return b"\xFF" + value.to_bytes(8, "little")


class CompactSizeDecoder:
    def decode(self, data: bytes) -> tuple[int, int]:
        if not data:
            raise ValueError("Data is too short to decode CompactSize.")

        first_byte = data[0]

        if first_byte < 0xFD:
            return first_byte, 1

        elif first_byte == 0xFD:
            if len(data) < 3:
                raise ValueError("Data too short for 0xFD encoding.")
            return int.from_bytes(data[1:3], "little"), 3

        elif first_byte == 0xFE:
            if len(data) < 5:
                raise ValueError("Data too short for 0xFE encoding.")
            return int.from_bytes(data[1:5], "little"), 5

        elif first_byte == 0xFF:
            if len(data) < 9:
                raise ValueError("Data too short for 0xFF encoding.")
            return int.from_bytes(data[1:9], "little"), 9

        else:
            raise ValueError("Invalid CompactSize prefix.")


class TransactionData:
    def __init__(self, version: int = 1, lock_time: int = 0):
        self.version = version
        self.inputs = []
        self.outputs = []
        self.lock_time = lock_time
        self.metadata = {}

    def add_input(self, tx_id: str, vout_index: int, script_sig: str, sequence: int = 0xFFFFFFFF):
        input_data = {
            "prev_txid": tx_id,
            "prev_vout": vout_index,
            "script_sig": script_sig,
            "sequence": sequence
        }
        self.inputs.append(input_data)
        print(f"Input added: {tx_id}:{vout_index}")

    def add_output(self, value_satoshi: int, script_pubkey: str):
        self.outputs.append((value_satoshi, script_pubkey))
        print(f"Output added: {value_satoshi} sats")

    def get_input_details(self) -> list[dict]:
        detailed_inputs = []
        print("\n--- Input Details (using for and enumerate) ---")

        for i, input_data in enumerate(self.inputs):
            prev_txid = input_data.get("prev_txid")
            prev_vout = input_data.get("prev_vout")
            script_sig = input_data.get("script_sig")

            print(f"Input {i}: txid={prev_txid}, vout={prev_vout}, script={script_sig}")
            detailed_inputs.append(input_data.copy())

        return detailed_inputs

    def summarize_outputs(self, min_value: int = 0) -> tuple[int, int]:
        total_satoshi = 0
        valid_outputs_count = 0
        index = 0

        print("\n--- Summarizing Outputs (using while, continue, break) ---")

        while index < len(self.outputs):
            value, script = self.outputs[index]

            if not isinstance(value, int) or value < 0:
                print("Invalid output value, skipping")
                index += 1
                continue

            if value < min_value:
                print(f"Output {value} below min_value, skipping")
                index += 1
                continue

            total_satoshi += value
            valid_outputs_count += 1
            print(f"Including output: {value} sats")

            if total_satoshi > 1_000_000_000:
                print("Threshold exceeded, stopping.")
                break

            index += 1

        return total_satoshi, valid_outputs_count

    def update_metadata(self, new_data: dict):
        self.metadata.update(new_data)
        print("Metadata updated:", self.metadata)

    def get_metadata_value(self, key: str, default=None):
        return self.metadata.get(key, default)

    def get_transaction_header(self) -> tuple:
        return (self.version, len(self.inputs), len(self.outputs), self.lock_time)

    def set_transaction_header(self, version: int, num_inputs: int, num_outputs: int, lock_time: int):
        self.version, _, _, self.lock_time = version, num_inputs, num_outputs, lock_time
        print("Transaction header updated")


class UTXOSet:
    def __init__(self):
        self.utxos = set()

    def add_utxo(self, tx_id: str, vout_index: int, amount: int):
        utxo = (tx_id, vout_index, amount)
        self.utxos.add(utxo)
        print("UTXO added:", utxo)

    def remove_utxo(self, tx_id: str, vout_index: int, amount: int) -> bool:
        utxo = (tx_id, vout_index, amount)
        if utxo in self.utxos:
            self.utxos.remove(utxo)
            return True
        return False

    def get_balance(self) -> int:
        return sum(amount for _, _, amount in self.utxos)

    def find_sufficient_utxos(self, target_amount: int) -> set:
        total = 0
        selected = set()

        for utxo in self.utxos:
            selected.add(utxo)
            total += utxo[2]
            if total >= target_amount:
                return selected

        return set()

    def get_total_utxo_count(self) -> int:
        return len(self.utxos)

    def is_subset_of(self, other_utxo_set: 'UTXOSet') -> bool:
        return self.utxos.issubset(other_utxo_set.utxos)

    def combine_utxos(self, other_utxo_set: 'UTXOSet') -> 'UTXOSet':
        combined = UTXOSet()
        combined.utxos = self.utxos.union(other_utxo_set.utxos)
        return combined

    def find_common_utxos(self, other_utxo_set: 'UTXOSet') -> 'UTXOSet':
        common = UTXOSet()
        common.utxos = self.utxos.intersection(other_utxo_set.utxos)
        return common


def generate_block_headers(
    prev_block_hash: str,
    merkle_root: str,
    timestamp: int,
    bits: int,
    start_nonce: int = 0,
    max_attempts: int = 1000
):
    print("\n--- Generating Block Headers (using generator) ---")

    nonce = start_nonce
    attempts = 0

    while attempts < max_attempts:
        header_data = {
            "version": 1,
            "prev_block_hash": prev_block_hash,
            "merkle_root": merkle_root,
            "timestamp": timestamp,
            "bits": bits,
            "nonce": nonce
        }

        header_str = str(header_data).encode()
        hash_result = hashlib.sha256(header_str).hexdigest()

        print(f"Attempt {attempts} | nonce={nonce} | hash={hash_result[:10]}...")

        if attempts % 100 == 0 and attempts != 0:
            print("Progress checkpoint reached...")

        yield header_data

        nonce += 1
        attempts += 1