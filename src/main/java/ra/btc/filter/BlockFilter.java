package ra.btc.filter;

import com.google.common.hash.Hashing;
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.core.Block;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionOutput;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * A BIP158 "basic" compact block filter: a Golomb-coded set of the scripts a block pays to and spends from. A wallet that holds a
 * filter for a block can tell, without telling anyone its addresses, whether the block might contain something of its own; only
 * then does it fetch the block. The filter is the same for every user, so whoever serves it learns nothing about who asks.
 *
 * <p>Wire form: the number of elements as a compact size, then the sorted differences between the elements' hashes, each Golomb-Rice
 * coded with parameter {@link #P}. Elements are hashed with SipHash-2-4 keyed by the first 16 bytes of the block hash (as computed, not as printed), then mapped
 * into [0, N * {@link #M}).
 */
public final class BlockFilter {

    /** Golomb-Rice parameter of the basic filter. */
    public static final int P = 19;
    /** Inverse false-positive rate of the basic filter. */
    public static final long M = 784_931L;

    private final byte[] encoded;
    private final long count;

    private BlockFilter(byte[] encoded, long count) {
        this.encoded = encoded;
        this.count = count;
    }

    /** A filter exactly as a node serves it (the {@code N} followed by the coded set); not checked beyond its element count. */
    public static BlockFilter fromBytes(byte[] filter) {
        if (filter == null || filter.length == 0) throw new IllegalArgumentException("empty filter");
        ByteBuffer b = ByteBuffer.wrap(filter);
        return new BlockFilter(filter.clone(), readCompactSize(b));
    }

    /** The serialized filter. */
    public byte[] bytes() {
        return encoded.clone();
    }

    public long elementCount() {
        return count;
    }

    /** {@code dsha256(filter)}: what a filter header commits to. */
    public Sha256Hash hash() {
        return Sha256Hash.twiceOf(encoded);
    }

    /** {@code dsha256(filter hash || previous header)}: each header commits to its filter and to every filter before it. */
    public Sha256Hash header(Sha256Hash previousHeader) {
        return filterHeader(hash(), previousHeader);
    }

    public static Sha256Hash filterHeader(Sha256Hash filterHash, Sha256Hash previousHeader) {
        byte[] both = new byte[64];
        System.arraycopy(filterHash.getBytes(), 0, both, 0, 32);
        System.arraycopy(previousHeader.getBytes(), 0, both, 32, 32);
        return Sha256Hash.twiceOf(both);
    }

    /**
     * The elements a block contributes: every output script that is not empty and not an {@code OP_RETURN}, and the script each input
     * spends ({@code previousOutputScripts}, which the block alone does not carry; a coinbase spends none).
     */
    public static List<byte[]> elementsOf(Block block, Collection<byte[]> previousOutputScripts) {
        Set<ByteBuffer> seen = new LinkedHashSet<>();
        if (block.getTransactions() != null) {
            for (Transaction tx : block.getTransactions()) {
                for (TransactionOutput out : tx.getOutputs()) {
                    byte[] script = out.getScriptBytes();
                    if (script.length == 0 || (script[0] & 0xff) == 0x6a) continue;
                    seen.add(ByteBuffer.wrap(script));
                }
            }
        }
        for (byte[] script : previousOutputScripts) {
            if (script != null && script.length > 0) seen.add(ByteBuffer.wrap(script));
        }
        List<byte[]> out = new ArrayList<>();
        for (ByteBuffer e : seen) out.add(e.array());
        return out;
    }

    /** Builds the filter for a block hash from its elements (what a node that serves filters does; used here to check the decoder). */
    public static BlockFilter build(Sha256Hash blockHash, Collection<byte[]> elements) {
        Set<ByteBuffer> unique = new LinkedHashSet<>();
        for (byte[] e : elements) unique.add(ByteBuffer.wrap(e));
        long n = unique.size();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeCompactSize(out, n);
        if (n == 0) return new BlockFilter(out.toByteArray(), 0);
        long range = n * M;
        long[] hashed = new long[(int) n];
        int i = 0;
        for (ByteBuffer e : unique) hashed[i++] = hashToRange(blockHash, e.array(), range);
        Arrays.sort(hashed);
        BitWriter w = new BitWriter(out);
        long last = 0;
        for (long h : hashed) {
            long delta = h - last;
            last = h;
            long q = delta >>> P;
            for (long k = 0; k < q; k++) w.writeBit(1);
            w.writeBit(0);
            w.writeBits(delta & ((1L << P) - 1), P);
        }
        w.flush();
        return new BlockFilter(out.toByteArray(), n);
    }

    /** True if the block may contain any of {@code scripts}: always when it does, wrongly about once in {@link #M} per script when it does not. */
    public boolean matchAny(Sha256Hash blockHash, Collection<byte[]> scripts) {
        if (count == 0 || scripts.isEmpty()) return false;
        long range = count * M;
        long[] wanted = new long[scripts.size()];
        int i = 0;
        for (byte[] s : scripts) wanted[i++] = hashToRange(blockHash, s, range);
        Arrays.sort(wanted);

        ByteBuffer b = ByteBuffer.wrap(encoded);
        readCompactSize(b);
        BitReader r = new BitReader(encoded, b.position());
        long value = 0;
        int w = 0;
        for (long k = 0; k < count; k++) {
            value += r.readGolomb();
            while (w < wanted.length && wanted[w] < value) w++;
            if (w == wanted.length) return false;
            if (wanted[w] == value) return true;
        }
        return false;
    }

    // -- hashing ------------------------------------------------------------------------------------------

    private static long hashToRange(Sha256Hash blockHash, byte[] element, long range) {
        // The key is the first 16 bytes of the hash in the order it was computed; bitcoinj holds a block hash the way it is printed,
        // which is the reverse of that, so the last 16 bytes read backwards.
        byte[] printed = blockHash.getBytes();
        byte[] key = new byte[16];
        for (int i = 0; i < 16; i++) key[i] = printed[31 - i];
        ByteBuffer k = ByteBuffer.wrap(key).order(ByteOrder.LITTLE_ENDIAN);
        long k0 = k.getLong();
        long k1 = k.getLong();
        long h = Hashing.sipHash24(k0, k1).hashBytes(element).asLong();
        return multiplyHighUnsigned(h, range);
    }

    /** The high 64 bits of the unsigned 128-bit product: (hash * range) >> 64. */
    static long multiplyHighUnsigned(long a, long b) {
        // By hand from 32-bit halves (Math.multiplyHigh is Java 9, not on older Android).
        long aLo = a & 0xffffffffL, aHi = a >>> 32;
        long bLo = b & 0xffffffffL, bHi = b >>> 32;
        long lowLow = aLo * bLo;
        long highLow = aHi * bLo + (lowLow >>> 32);
        long lowHigh = aLo * bHi + (highLow & 0xffffffffL);
        return aHi * bHi + (highLow >>> 32) + (lowHigh >>> 32);
    }

    // -- compact size and bits ----------------------------------------------------------------------------

    private static long readCompactSize(ByteBuffer b) {
        b.order(ByteOrder.LITTLE_ENDIAN);
        int first = b.get() & 0xff;
        if (first < 0xfd) return first;
        if (first == 0xfd) return b.getShort() & 0xffffL;
        if (first == 0xfe) return b.getInt() & 0xffffffffL;
        return b.getLong();
    }

    private static void writeCompactSize(ByteArrayOutputStream out, long n) {
        if (n < 0xfd) {
            out.write((int) n);
        } else if (n <= 0xffffL) {
            out.write(0xfd);
            out.write((int) (n & 0xff));
            out.write((int) ((n >> 8) & 0xff));
        } else if (n <= 0xffffffffL) {
            out.write(0xfe);
            for (int i = 0; i < 4; i++) out.write((int) ((n >> (8 * i)) & 0xff));
        } else {
            out.write(0xff);
            for (int i = 0; i < 8; i++) out.write((int) ((n >> (8 * i)) & 0xff));
        }
    }

    private static final class BitWriter {
        private final ByteArrayOutputStream out;
        private int current;
        private int filled;

        BitWriter(ByteArrayOutputStream out) {
            this.out = out;
        }

        void writeBit(int bit) {
            current = (current << 1) | (bit & 1);
            if (++filled == 8) {
                out.write(current);
                current = 0;
                filled = 0;
            }
        }

        void writeBits(long value, int bits) {
            for (int i = bits - 1; i >= 0; i--) writeBit((int) ((value >> i) & 1));
        }

        void flush() {
            while (filled != 0) writeBit(0);
        }
    }

    private static final class BitReader {
        private final byte[] data;
        private long position; // in bits

        BitReader(byte[] data, int startByte) {
            this.data = data;
            this.position = startByte * 8L;
        }

        int readBit() {
            int byteIndex = (int) (position >> 3);
            if (byteIndex >= data.length) throw new IllegalArgumentException("filter ends early");
            int bit = (data[byteIndex] >> (7 - (int) (position & 7))) & 1;
            position++;
            return bit;
        }

        long readBits(int n) {
            long v = 0;
            for (int i = 0; i < n; i++) v = (v << 1) | readBit();
            return v;
        }

        /** One Golomb-Rice coded difference. */
        long readGolomb() {
            long q = 0;
            while (readBit() == 1) q++;
            return (q << P) | readBits(P);
        }
    }
}
