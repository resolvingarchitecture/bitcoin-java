package ra.btc.bitcoinj;

import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;

public class VaultPathTest {

    @Test
    public void readsHardenedPathsInEitherNotation() {
        int[] expected = {0x80000054, 0x80000000, 0x80000000};
        assertArrayEquals(expected, BitcoinJClient.parsePath("84'/0'/0'"));
        assertArrayEquals(expected, BitcoinJClient.parsePath("84h/0H/0'"));
    }

    @Test
    public void emptyPathIsTheMasterKey() {
        assertArrayEquals(new int[0], BitcoinJClient.parsePath(""));
    }
}
