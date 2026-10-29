package ra.btc.filter;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.base.internal.ByteUtils;
import org.bitcoinj.core.Block;
import org.bitcoinj.core.NetworkParameters;
import org.junit.Test;
import ra.common.JSONParser;

/** Checked against the BIP158 test vectors (testnet, ten blocks): each row has the block, the scripts its inputs spend, the filter and its header. */
public class BlockFilterTest {

    private static final class Vector {
        final int height;
        final String hashPrinted;
        final Block block;
        final List<byte[]> prevScripts;
        final byte[] prevHeader;
        final byte[] filter;
        final byte[] header;
        final String note;

        Vector(int height, String hashPrinted, Block block, List<byte[]> prevScripts, byte[] prevHeader, byte[] filter,
               byte[] header, String note) {
            this.height = height;
            this.hashPrinted = hashPrinted;
            this.block = block;
            this.prevScripts = prevScripts;
            this.prevHeader = prevHeader;
            this.filter = filter;
            this.header = header;
            this.note = note;
        }
    }

    private static List<Vector> vectors() throws Exception {
        NetworkParameters params = NetworkParameters.of(BitcoinNetwork.TESTNET);
        String text;
        try (InputStream in = BlockFilterTest.class.getResourceAsStream("/bip158/testnet-19.json")) {
            text = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
        List<?> rows = (List<?>) JSONParser.parse(text);
        List<Vector> out = new ArrayList<>();
        for (int i = 1; i < rows.size(); i++) {
            List<?> r = (List<?>) rows.get(i);
            List<byte[]> prev = new ArrayList<>();
            for (Object o : (List<?>) r.get(3)) prev.add(ByteUtils.parseHex((String) o));
            Block block = params.getDefaultSerializer().makeBlock(ByteBuffer.wrap(ByteUtils.parseHex((String) r.get(2))));
            out.add(new Vector(Integer.parseInt(String.valueOf(r.get(0))), (String) r.get(1), block, prev,
                    ByteUtils.parseHex((String) r.get(4)), ByteUtils.parseHex((String) r.get(5)),
                    ByteUtils.parseHex((String) r.get(6)), (String) r.get(7)));
        }
        return out;
    }

    private static byte[] reversed(byte[] b) {
        byte[] r = new byte[b.length];
        for (int i = 0; i < b.length; i++) r[i] = b[b.length - 1 - i];
        return r;
    }

    @Test
    public void everyVectorBlockHasTheHashTheVectorSays() throws Exception {
        for (Vector v : vectors()) assertEquals("height " + v.height, v.hashPrinted, v.block.getHashAsString());
    }

    @Test
    public void aFilterBuiltFromTheBlockIsTheFilterTheVectorHas() throws Exception {
        for (Vector v : vectors()) {
            BlockFilter built = BlockFilter.build(v.block.getHash(), BlockFilter.elementsOf(v.block, v.prevScripts));
            assertArrayEquals("filter at height " + v.height + " (" + v.note + ")", v.filter, built.bytes());
        }
    }

    @Test
    public void theFilterHeadersChainTheWayTheVectorsSay() throws Exception {
        for (Vector v : vectors()) {
            BlockFilter f = BlockFilter.fromBytes(v.filter);
            // the vectors print a header the way block hashes are printed: reversed
            Sha256Hash prev = Sha256Hash.wrap(reversed(v.prevHeader));
            assertArrayEquals("header at height " + v.height, v.header, reversed(f.header(prev).getBytes()));
        }
    }

    @Test
    public void aFilterMatchesEveryScriptItWasBuiltFromAndNoUnrelatedOne() throws Exception {
        for (Vector v : vectors()) {
            BlockFilter f = BlockFilter.fromBytes(v.filter);
            List<byte[]> elements = BlockFilter.elementsOf(v.block, v.prevScripts);
            assertEquals("height " + v.height, elements.size(), f.elementCount());
            for (byte[] e : elements) {
                assertTrue("height " + v.height + " should match its own script", f.matchAny(v.block.getHash(), java.util.Arrays.asList(e)));
            }
            if (!elements.isEmpty()) {
                assertTrue(f.matchAny(v.block.getHash(), java.util.Arrays.asList(new byte[]{1, 2, 3}, elements.get(0))));
            }
            // a script that is not in the block: a false positive is possible but about one in 784,931 per script
            List<byte[]> others = new ArrayList<>();
            for (int i = 0; i < 20; i++) others.add(("not-a-script-" + v.height + "-" + i).getBytes(StandardCharsets.UTF_8));
            assertFalse("height " + v.height + " should not match unrelated scripts", f.matchAny(v.block.getHash(), others));
        }
    }

    @Test
    public void anEmptyFilterMatchesNothing() {
        BlockFilter f = BlockFilter.build(Sha256Hash.ZERO_HASH, new ArrayList<byte[]>());
        assertEquals(0, f.elementCount());
        assertFalse(f.matchAny(Sha256Hash.ZERO_HASH, java.util.Arrays.asList(new byte[]{1})));
    }
}
