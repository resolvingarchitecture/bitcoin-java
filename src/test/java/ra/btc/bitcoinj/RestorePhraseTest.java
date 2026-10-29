package ra.btc.bitcoinj;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import ra.btc.BitcoinClient;
import ra.btc.BitcoinService;
import ra.common.Envelope;

import java.io.File;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

/** Real wallets in a temporary directory, started with no peers. */
public class RestorePhraseTest {

    private static final List<String> ABANDON = Arrays.asList(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".split(" "));

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    private BitcoinService service() throws Exception {
        BitcoinService service = new BitcoinService();
        java.lang.reflect.Field f = ra.common.service.BaseService.class.getDeclaredField("serviceDirectory");
        f.setAccessible(true);
        f.set(service, tmp.getRoot());
        return service;
    }

    private static Properties config() {
        Properties p = new Properties();
        p.setProperty("ra.env", "prod");
        p.setProperty("ra.btc.noDirectPeers", "true");
        return p;
    }

    private static String ask(BitcoinJClient c, String op, String header) {
        Envelope e = Envelope.documentFactory();
        e.addRoute("ra.btc.BitcoinService", op);
        c.handleDocument(e);
        return (String) e.getHeader(header);
    }

    @Test
    public void restoresFromWordsAndKeepsThemAcrossRestarts() throws Exception {
        BitcoinJClient first = new BitcoinJClient(service());
        assertTrue(first.init(config()));
        String randomWords = ask(first, BitcoinClient.OPERATION_GET_WALLET_WORDS, BitcoinClient.HEADER_WORDS);
        assertEquals(12, randomWords.split(" ").length);
        first.destroy();

        BitcoinJClient restored = new BitcoinJClient(service());
        restored.setRestorePhrase(ABANDON, 1_700_000_000L);
        assertTrue(restored.init(config()));
        assertEquals(String.join(" ", ABANDON), ask(restored, BitcoinClient.OPERATION_GET_WALLET_WORDS, BitcoinClient.HEADER_WORDS));
        assertNotEquals(randomWords, String.join(" ", ABANDON));
        // BIP-84 m/84'/0'/0'/0/0 for the well-known test phrase, so the words work in any other wallet too.
        assertEquals("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
                ask(restored, BitcoinClient.OPERATION_GET_RECEIVE_ADDRESS, BitcoinClient.HEADER_ADDRESS));
        restored.destroy();

        BitcoinJClient again = new BitcoinJClient(service());
        assertTrue(again.init(config()));
        assertEquals(String.join(" ", ABANDON), ask(again, BitcoinClient.OPERATION_GET_WALLET_WORDS, BitcoinClient.HEADER_WORDS));
        again.destroy();
    }
}
