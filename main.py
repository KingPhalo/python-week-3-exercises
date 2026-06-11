import hashlib


class CompactSizeEncoder:
    def encode(self, value: int) -> bytes:
        if not isinstance(value, int) or value < 0 or value > 0xFFFFFFFFFFFFFFFF:
            raise ValueError("Invalid u64 value")

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
            raise ValueError("Empty data")

        fb = data[0]

        if fb < 0xFD:
            return fb, 1
        elif fb == 0xFD:
            return int.from_bytes(data[1:3], "little"), 3
        elif fb == 0xFE:
            return int.from_bytes(data[1:5], "little"), 5
        else:
            return int.from_bytes(data[1:9], "little"), 9


class TransactionData:
    def __init__(self):
        self.inputs = []
        self.outputs = []
        self.metadata = {}

    def add_input(self, tx_id, vout, script):
        self.inputs.append({
            "prev_txid": tx_id,
            "prev_vout": vout,
            "script_sig": script
        })

    def add_output(self, value, script):
        self.outputs.append((value, script))

    def get_transaction_header(self):
        return (len(self.inputs), len(self.outputs))

    def update_metadata(self, data):
        self.metadata.update(data)

    def get_metadata_value(self, key, default=None):
        return self.metadata.get(key, default)


class UTXOSet:
    def __init__(self):
        self.utxos = set()

    def add_utxo(self, txid, vout, amount):
        self.utxos.add((txid, vout, amount))

    def get_balance(self):
        return sum(a for _, _, a in self.utxos)

    def get_total_utxo_count(self):
        return len(self.utxos) 
    