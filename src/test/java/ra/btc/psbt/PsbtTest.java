package ra.btc.psbt;

import org.bitcoinj.base.Address;
import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.base.Coin;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionOutput;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.crypto.TransactionSignature;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.junit.Test;

import static org.junit.Assert.*;

public class PsbtTest {

    private static final BitcoinNetwork NET = BitcoinNetwork.TESTNET;

    /** A one-input spend of a P2WPKH output the key owns, as the app would build it for a signer. */
    private static Psbt unsignedSpend(ECKey key, Coin funded) {
        Address own = key.toAddress(ScriptType.P2WPKH, NET);
        Transaction tx = new Transaction();
        tx.addInput(Sha256Hash.of(new byte[]{1}), 0, new ScriptBuilder().build());
        tx.addOutput(Coin.valueOf(funded.value - 1_000), new ECKey().toAddress(ScriptType.P2WPKH, NET));
        Psbt psbt = Psbt.create(tx);
        psbt.setWitnessUtxo(0, new TransactionOutput(null, funded, ScriptBuilder.createOutputScript(own).program()));
        psbt.addDerivation(false, 0, key.getPubKey(), new byte[]{1, 2, 3, 4}, new int[]{0x80000054, 0x80000000, 0x80000000, 0, 7});
        return psbt;
    }

    @Test
    public void roundTripsThroughBase64AndKeepsUnknownFields() {
        ECKey key = new ECKey();
        Psbt psbt = unsignedSpend(key, Coin.valueOf(50_000));
        psbt.input(0).put(0xfc, new byte[]{9}, new byte[]{1, 2}); // a field this class has no name for
        Psbt back = Psbt.parseText(psbt.toBase64());
        assertArrayEquals(psbt.serialize(), back.serialize());
        assertArrayEquals(new byte[]{1, 2}, back.input(0).all(0xfc).values().iterator().next());
    }

    @Test
    public void signedPsbtFinalizesToAValidTransaction() {
        ECKey key = new ECKey();
        Psbt psbt = unsignedSpend(key, Coin.valueOf(50_000));
        assertFalse(psbt.isComplete());

        // what a signer does: BIP-143 hash of the input, signed, returned as a partial signature
        Transaction tx = psbt.unsignedTransaction();
        TransactionOutput spent = psbt.spentOutput(0);
        Script code = ScriptBuilder.createP2PKHOutputScript(key);
        TransactionSignature sig = tx.calculateWitnessSignature(0, key, code, spent.getValue(),
                Transaction.SigHash.ALL, false);
        psbt.input(0).put(0x02, key.getPubKey(), sig.encodeToBitcoin());
        assertTrue(psbt.isComplete());

        Transaction signed = Psbt.parse(psbt.serialize()).finalizeAndExtract();
        assertEquals(2, signed.getInput(0).getWitness().getPushCount());
        new Script(spent.getScriptBytes()).correctlySpends(signed, 0, signed.getInput(0).getWitness(),
                spent.getValue(), new Script(spent.getScriptBytes()), Script.ALL_VERIFY_FLAGS);
    }

    @Test
    public void unsignedInputIsRefused() {
        Psbt psbt = unsignedSpend(new ECKey(), Coin.valueOf(50_000));
        try {
            psbt.finalizeAndExtract();
            fail();
        } catch (IllegalStateException expected) {
            assertTrue(expected.getMessage().contains("not signed"));
        }
    }

    @Test(expected = IllegalArgumentException.class)
    public void garbageIsRefused() {
        Psbt.parse(new byte[]{1, 2, 3, 4, 5, 6});
    }

    @Test(expected = IllegalArgumentException.class)
    public void truncatedIsRefused() {
        byte[] full = unsignedSpend(new ECKey(), Coin.valueOf(50_000)).serialize();
        Psbt.parse(java.util.Arrays.copyOf(full, full.length - 3));
    }
}
