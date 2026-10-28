package ra.btc.psbt;

import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionInput;
import org.bitcoinj.core.TransactionOutput;
import org.bitcoinj.core.TransactionWitness;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.base.ScriptType;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A BIP-174 partially signed Bitcoin transaction. bitcoinj 0.17.1 has none, and this is what lets any signer
 * (a Coldcard over NFC, a QR code or a file; Trezor, Ledger, Sparrow) sign a spend from the watch-only vault.
 *
 * Every key-value pair is kept as read, so fields this class does not understand survive a parse and write unchanged
 * (a signer's extras must not be dropped on the way back). Only single-signature inputs (P2WPKH, P2PKH) can be
 * finalized here; multisig is out of scope for the vault.
 */
public final class Psbt {

    private static final byte[] MAGIC = {'p', 's', 'b', 't', (byte) 0xff};

    private static final int GLOBAL_UNSIGNED_TX = 0x00;
    private static final int IN_NON_WITNESS_UTXO = 0x00;
    private static final int IN_WITNESS_UTXO = 0x01;
    private static final int IN_PARTIAL_SIG = 0x02;
    private static final int IN_BIP32_DERIVATION = 0x06;
    private static final int IN_FINAL_SCRIPTSIG = 0x07;
    private static final int IN_FINAL_SCRIPTWITNESS = 0x08;
    private static final int OUT_BIP32_DERIVATION = 0x02;

    /** One key-value map: the key (type byte then key data) to its value, in file order. */
    public static final class Fields {
        private final Map<ByteKey, byte[]> pairs = new LinkedHashMap<>();

        public byte[] get(int type) {
            return pairs.get(new ByteKey(new byte[]{(byte) type}));
        }

        public void put(int type, byte[] keyData, byte[] value) {
            ByteArrayOutputStream key = new ByteArrayOutputStream();
            key.write(type);
            append(key, keyData);
            pairs.put(new ByteKey(key.toByteArray()), value);
        }

        public void put(int type, byte[] value) {
            put(type, new byte[0], value);
        }

        public void remove(int type) {
            pairs.keySet().removeIf(k -> (k.bytes[0] & 0xff) == type);
        }

        /** Key data (after the type byte) to value, for every pair of this type. */
        public Map<byte[], byte[]> all(int type) {
            Map<byte[], byte[]> out = new LinkedHashMap<>();
            for (Map.Entry<ByteKey, byte[]> e : pairs.entrySet()) {
                if ((e.getKey().bytes[0] & 0xff) == type) out.put(Arrays.copyOfRange(e.getKey().bytes, 1, e.getKey().bytes.length), e.getValue());
            }
            return out;
        }

        void write(ByteArrayOutputStream out) {
            for (Map.Entry<ByteKey, byte[]> e : pairs.entrySet()) {
                writeVarInt(out, e.getKey().bytes.length);
                append(out, e.getKey().bytes);
                writeVarInt(out, e.getValue().length);
                append(out, e.getValue());
            }
            out.write(0); // separator
        }

        static Fields read(ByteBuffer in) {
            Fields map = new Fields();
            while (true) {
                long keyLen = readVarInt(in);
                if (keyLen == 0) return map;
                byte[] key = new byte[checked(keyLen, in)];
                in.get(key);
                byte[] value = new byte[checked(readVarInt(in), in)];
                in.get(value);
                if (map.pairs.put(new ByteKey(key), value) != null) throw new IllegalArgumentException("PSBT has a duplicate key");
            }
        }
    }

    private static final class ByteKey {
        final byte[] bytes;
        ByteKey(byte[] bytes) { this.bytes = bytes; }
        @Override public boolean equals(Object o) { return o instanceof ByteKey && Arrays.equals(bytes, ((ByteKey) o).bytes); }
        @Override public int hashCode() { return Arrays.hashCode(bytes); }
    }

    private final Fields global;
    private final Transaction tx;
    private final List<Fields> inputs;
    private final List<Fields> outputs;

    private Psbt(Fields global, Transaction tx, List<Fields> inputs, List<Fields> outputs) {
        this.global = global;
        this.tx = tx;
        this.inputs = inputs;
        this.outputs = outputs;
    }

    /** A PSBT for an unsigned transaction (every input's scriptSig and witness empty). */
    public static Psbt create(Transaction unsigned) {
        Fields global = new Fields();
        global.put(GLOBAL_UNSIGNED_TX, unsigned.serialize());
        List<Fields> in = new ArrayList<>();
        for (int i = 0; i < unsigned.getInputs().size(); i++) in.add(new Fields());
        List<Fields> out = new ArrayList<>();
        for (int i = 0; i < unsigned.getOutputs().size(); i++) out.add(new Fields());
        return new Psbt(global, Transaction.read(ByteBuffer.wrap(unsigned.serialize())), in, out);
    }

    public static Psbt parse(byte[] data) {
        ByteBuffer in = ByteBuffer.wrap(data);
        byte[] magic = new byte[MAGIC.length];
        if (in.remaining() < MAGIC.length) throw new IllegalArgumentException("not a PSBT");
        in.get(magic);
        if (!Arrays.equals(magic, MAGIC)) throw new IllegalArgumentException("not a PSBT");
        Fields global = Fields.read(in);
        byte[] raw = global.get(GLOBAL_UNSIGNED_TX);
        if (raw == null) throw new IllegalArgumentException("the PSBT has no transaction");
        Transaction tx = Transaction.read(ByteBuffer.wrap(raw));
        List<Fields> inputs = new ArrayList<>();
        for (int i = 0; i < tx.getInputs().size(); i++) inputs.add(Fields.read(in));
        List<Fields> outputs = new ArrayList<>();
        for (int i = 0; i < tx.getOutputs().size(); i++) outputs.add(Fields.read(in));
        if (in.hasRemaining()) throw new IllegalArgumentException("the PSBT has trailing data");
        return new Psbt(global, tx, inputs, outputs);
    }

    /** Accepts base64 (what wallets exchange as text and QR), hex, or the raw bytes' base64 with surrounding whitespace. */
    public static Psbt parseText(String text) {
        String t = text.trim();
        if (t.matches("(?i)[0-9a-f]+") && t.length() % 2 == 0) {
            byte[] b = new byte[t.length() / 2];
            for (int i = 0; i < b.length; i++) b[i] = (byte) Integer.parseInt(t.substring(2 * i, 2 * i + 2), 16);
            return parse(b);
        }
        return parse(Base64.getDecoder().decode(t.replaceAll("\\s+", "").getBytes(StandardCharsets.US_ASCII)));
    }

    public byte[] serialize() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        append(out, MAGIC);
        global.write(out);
        for (Fields m : inputs) m.write(out);
        for (Fields m : outputs) m.write(out);
        return out.toByteArray();
    }

    public String toBase64() {
        return Base64.getEncoder().encodeToString(serialize());
    }

    public Transaction unsignedTransaction() { return tx; }

    public Fields input(int i) { return inputs.get(i); }

    public Fields output(int i) { return outputs.get(i); }

    public int inputCount() { return inputs.size(); }

    /** Sets what input {@code i} spends, which a signer needs to check the amount and fee. */
    public void setWitnessUtxo(int i, TransactionOutput spent) {
        inputs.get(i).put(IN_WITNESS_UTXO, spent.serialize());
    }

    /** The output input {@code i} spends, from its witness UTXO or the matching output of its full previous transaction. */
    public TransactionOutput spentOutput(int i) {
        Fields in = inputs.get(i);
        byte[] witness = in.get(IN_WITNESS_UTXO);
        if (witness != null) return TransactionOutput.read(ByteBuffer.wrap(witness), tx);
        byte[] prev = in.get(IN_NON_WITNESS_UTXO);
        if (prev == null) return null;
        long index = tx.getInput(i).getOutpoint().index();
        return Transaction.read(ByteBuffer.wrap(prev)).getOutput((int) index);
    }

    /**
     * Records which key (by its master fingerprint and path) input {@code i}, or change output {@code outputIndex}
     * when {@code isOutput}, belongs to: a signer finds its key from this.
     */
    public void addDerivation(boolean isOutput, int index, byte[] pubKey, byte[] masterFingerprint, int[] path) {
        ByteBuffer v = ByteBuffer.allocate(4 + 4 * path.length).order(ByteOrder.LITTLE_ENDIAN);
        v.put(masterFingerprint);
        for (int p : path) v.putInt(p);
        if (isOutput) outputs.get(index).put(OUT_BIP32_DERIVATION, pubKey, v.array());
        else inputs.get(index).put(IN_BIP32_DERIVATION, pubKey, v.array());
    }

    public boolean isFinalized(int i) {
        Fields in = inputs.get(i);
        return in.get(IN_FINAL_SCRIPTWITNESS) != null || in.get(IN_FINAL_SCRIPTSIG) != null;
    }

    public boolean isComplete() {
        for (int i = 0; i < inputs.size(); i++) if (!isFinalized(i) && inputs.get(i).all(IN_PARTIAL_SIG).isEmpty()) return false;
        return true;
    }

    /**
     * Turns each input's partial signature into its final scriptSig/witness and returns the signed transaction, ready
     * to broadcast. Fails naming the input if it has no signature or is not single-signature P2WPKH/P2PKH.
     */
    public Transaction finalizeAndExtract() {
        Transaction out = Transaction.read(ByteBuffer.wrap(tx.serialize()));
        for (int i = 0; i < inputs.size(); i++) {
            Fields in = inputs.get(i);
            byte[] finalWitness = in.get(IN_FINAL_SCRIPTWITNESS);
            byte[] finalScriptSig = in.get(IN_FINAL_SCRIPTSIG);
            TransactionInput input = out.getInput(i);
            if (finalWitness != null || finalScriptSig != null) {
                if (finalWitness != null) input = input.withWitness(TransactionWitness.read(ByteBuffer.wrap(finalWitness)));
                if (finalScriptSig != null) input = input.withScriptBytes(finalScriptSig);
                out.replaceInput(i, input);
                continue;
            }
            Map<byte[], byte[]> sigs = in.all(IN_PARTIAL_SIG);
            if (sigs.size() != 1) {
                throw new IllegalStateException(sigs.isEmpty() ? "input " + i + " is not signed"
                        : "input " + i + " needs more than one signature, which the vault does not support");
            }
            Map.Entry<byte[], byte[]> sig = sigs.entrySet().iterator().next();
            TransactionOutput spent = spentOutput(i);
            if (spent == null) throw new IllegalStateException("input " + i + " does not say what it spends");
            ScriptType type = new Script(spent.getScriptBytes()).getScriptType();
            if (type == ScriptType.P2WPKH) {
                out.replaceInput(i, input.withWitness(TransactionWitness.of(sig.getValue(), sig.getKey())));
            } else if (type == ScriptType.P2PKH) {
                out.replaceInput(i, input.withScriptBytes(new ScriptBuilder().data(sig.getValue()).data(sig.getKey()).build().program()));
            } else {
                throw new IllegalStateException("input " + i + " is not a plain single-key address (P2WPKH or P2PKH)");
            }
        }
        return out;
    }

    // --- compact-size integers ---

    private static void append(ByteArrayOutputStream out, byte[] bytes) {
        out.write(bytes, 0, bytes.length);
    }

    private static void writeVarInt(ByteArrayOutputStream out, long v) {
        if (v < 0xfd) out.write((int) v);
        else if (v <= 0xffff) { out.write(0xfd); out.write((int) v); out.write((int) (v >> 8)); }
        else if (v <= 0xffffffffL) { out.write(0xfe); for (int s = 0; s < 32; s += 8) out.write((int) (v >> s)); }
        else { out.write(0xff); for (int s = 0; s < 64; s += 8) out.write((int) (v >> s)); }
    }

    private static long readVarInt(ByteBuffer in) {
        int first = in.get() & 0xff;
        if (first < 0xfd) return first;
        ByteBuffer le = in.order(ByteOrder.LITTLE_ENDIAN);
        try {
            if (first == 0xfd) return le.getShort() & 0xffffL;
            if (first == 0xfe) return le.getInt() & 0xffffffffL;
            return le.getLong();
        } finally {
            in.order(ByteOrder.BIG_ENDIAN);
        }
    }

    private static int checked(long length, ByteBuffer in) {
        if (length < 0 || length > in.remaining()) throw new IllegalArgumentException("the PSBT is truncated");
        return (int) length;
    }
}
