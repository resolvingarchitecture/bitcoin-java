package ra.btc.psbt;

import org.bitcoinj.base.Address;
import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.base.Coin;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionOutput;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.script.ScriptBuilder;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.*;

public class VaultWithdrawalTest {

    private static final BitcoinNetwork NET = BitcoinNetwork.TESTNET;
    private static final byte[] FP = {1, 2, 3, 4};
    private static final int[] ORIGIN = {0x80000054, 0x80000000, 0x80000000};

    private final ECKey vaultKey = new ECKey();
    private final Address changeAddress = vaultKey.toAddress(ScriptType.P2WPKH, NET);
    private final Address destination = new ECKey().toAddress(ScriptType.P2WPKH, NET);

    private final VaultWithdrawal.KeyLookup keys = script -> new VaultWithdrawal.KeyInfo(vaultKey.getPubKey(), new int[]{0, 3});

    /** Coins the vault holds, each the output of its own earlier transaction. */
    private List<TransactionOutput> coins(long... sats) {
        List<TransactionOutput> out = new ArrayList<>();
        int n = 0;
        for (long s : sats) {
            Transaction parent = new Transaction();
            parent.addInput(Sha256Hash.of(new byte[]{(byte) ++n}), 0, new ScriptBuilder().build());
            out.add(parent.addOutput(Coin.valueOf(s), changeAddress));
        }
        return out;
    }

    @Test
    public void paysTheDestinationAndReturnsChangeToTheVault() throws Exception {
        VaultWithdrawal.Result r = VaultWithdrawal.build(coins(100_000, 50_000), keys, destination, 30_000, 5,
                changeAddress, FP, ORIGIN);
        assertEquals(1, r.inputs()); // the largest coin alone covers it
        assertEquals(30_000, r.amountSats());
        assertEquals(100_000, r.amountSats() + r.feeSats() + r.changeSats());
        Transaction tx = r.psbt().unsignedTransaction();
        assertEquals(2, tx.getOutputs().size());
        assertEquals(30_000, tx.getOutput(0).getValue().value);
        assertEquals(r.changeSats(), tx.getOutput(1).getValue().value);
        assertEquals(destination, tx.getOutput(0).getScriptPubKey().getToAddress(NET));
        assertEquals(changeAddress, tx.getOutput(1).getScriptPubKey().getToAddress(NET));
        assertEquals(5 * 141, r.feeSats()); // 1 segwit input, 2 segwit outputs: 141 vbytes
    }

    @Test
    public void describesInputsAndChangeForTheSigner() throws Exception {
        VaultWithdrawal.Result r = VaultWithdrawal.build(coins(100_000), keys, destination, 30_000, 2, changeAddress, FP, ORIGIN);
        assertEquals(1, r.psbt().input(0).all(0x06).size());
        assertNotNull(r.psbt().input(0).get(0x01)); // witness UTXO
        assertNotNull(r.psbt().input(0).get(0x00)); // full previous transaction
        assertEquals(1, r.psbt().output(1).all(0x02).size()); // change is marked as the vault's
        assertTrue(r.psbt().output(0).all(0x02).isEmpty());   // the destination is not
        byte[] derivation = r.psbt().input(0).all(0x06).values().iterator().next();
        assertEquals(4 + 5 * 4, derivation.length); // fingerprint + 84'/0'/0'/0/3
    }

    @Test
    public void combinesCoinsWhenOneIsNotEnough() throws Exception {
        VaultWithdrawal.Result r = VaultWithdrawal.build(coins(40_000, 30_000, 20_000), keys, destination, 60_000, 2,
                changeAddress, FP, ORIGIN);
        assertEquals(2, r.inputs());
    }

    @Test
    public void smallRemainderBecomesFeeInsteadOfDust() throws Exception {
        // 10_000 coin, pay 9_000 at 2 sat/vB: the remainder after a change output's fee is below the dust limit
        VaultWithdrawal.Result r = VaultWithdrawal.build(coins(10_000), keys, destination, 9_300, 2, changeAddress, FP, ORIGIN);
        assertEquals(0, r.changeSats());
        assertEquals(1, r.psbt().unsignedTransaction().getOutputs().size());
        assertEquals(10_000, r.amountSats() + r.feeSats());
    }

    @Test
    public void sendingEverythingHasNoChange() throws Exception {
        VaultWithdrawal.Result r = VaultWithdrawal.build(coins(40_000, 30_000), keys, destination, -1, 3, changeAddress, FP, ORIGIN);
        assertEquals(2, r.inputs());
        assertEquals(0, r.changeSats());
        assertEquals(70_000, r.amountSats() + r.feeSats());
        assertEquals(3 * (11 + 2 * 68 + 31), r.feeSats());
    }

    @Test
    public void reportsHowManySatsAreMissing() {
        try {
            VaultWithdrawal.build(coins(10_000), keys, destination, 20_000, 2, changeAddress, FP, ORIGIN);
            fail();
        } catch (VaultWithdrawal.InsufficientFundsException e) {
            assertTrue(e.missingSats >= 10_000);
        }
    }

    @Test
    public void unsignedRequestSurvivesTheTripToTheSigner() throws Exception {
        VaultWithdrawal.Result r = VaultWithdrawal.build(coins(100_000), keys, destination, 30_000, 2, changeAddress, FP, ORIGIN);
        Psbt back = Psbt.parseText(r.psbt().toBase64());
        assertArrayEquals(r.psbt().serialize(), back.serialize());
    }

    /** What a signer returns: the request with a partial signature for each input. */
    private Psbt signed(Psbt request) {
        Psbt copy = Psbt.parse(request.serialize());
        Transaction tx = copy.unsignedTransaction();
        for (int i = 0; i < copy.inputCount(); i++) {
            TransactionOutput spent = copy.spentOutput(i);
            org.bitcoinj.crypto.TransactionSignature sig = tx.calculateWitnessSignature(i, vaultKey,
                    ScriptBuilder.createP2PKHOutputScript(vaultKey), spent.getValue(), Transaction.SigHash.ALL, false);
            copy.input(i).put(0x02, vaultKey.getPubKey(), sig.encodeToBitcoin());
        }
        return copy;
    }

    @Test
    public void finishesAMatchingSignedWithdrawal() throws Exception {
        VaultWithdrawal.Result r = VaultWithdrawal.build(coins(100_000, 50_000), keys, destination, 120_000, 2, changeAddress, FP, ORIGIN);
        VaultWithdrawal.Finished done = VaultWithdrawal.finish(signed(r.psbt()), r.psbt());
        assertEquals(r.feeSats(), done.feeSats());
        Transaction tx = Transaction.read(java.nio.ByteBuffer.wrap(fromHex(done.rawTxHex())));
        assertEquals(2, tx.getInputs().size());
        assertEquals(120_000, tx.getOutput(0).getValue().value);
    }

    @Test
    public void refusesAWithdrawalWhoseOutputsWereChanged() throws Exception {
        List<TransactionOutput> same = coins(100_000);
        VaultWithdrawal.Result asked = VaultWithdrawal.build(same, keys, destination, 30_000, 2, changeAddress, FP, ORIGIN);
        VaultWithdrawal.Result altered = VaultWithdrawal.build(same, keys, destination, 99_000, 2, changeAddress, FP, ORIGIN);
        try {
            VaultWithdrawal.finish(signed(altered.psbt()), asked.psbt());
            fail();
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("not the withdrawal you asked for"));
        }
    }

    @Test
    public void refusesAWithdrawalNobodySigned() throws Exception {
        VaultWithdrawal.Result r = VaultWithdrawal.build(coins(100_000), keys, destination, 30_000, 2, changeAddress, FP, ORIGIN);
        try {
            VaultWithdrawal.finish(r.psbt(), r.psbt());
            fail();
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("not signed"));
        }
    }

    @Test
    public void refusesASignatureMadeByTheWrongKey() throws Exception {
        VaultWithdrawal.Result r = VaultWithdrawal.build(coins(100_000), keys, destination, 30_000, 2, changeAddress, FP, ORIGIN);
        Psbt bad = Psbt.parse(r.psbt().serialize());
        ECKey other = new ECKey();
        TransactionOutput spent = bad.spentOutput(0);
        org.bitcoinj.crypto.TransactionSignature sig = bad.unsignedTransaction().calculateWitnessSignature(0, other,
                ScriptBuilder.createP2PKHOutputScript(other), spent.getValue(), Transaction.SigHash.ALL, false);
        bad.input(0).put(0x02, other.getPubKey(), sig.encodeToBitcoin());
        try {
            VaultWithdrawal.finish(bad, r.psbt());
            fail();
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("does not check out"));
        }
    }

    private static byte[] fromHex(String h) {
        byte[] b = new byte[h.length() / 2];
        for (int i = 0; i < b.length; i++) b[i] = (byte) Integer.parseInt(h.substring(2 * i, 2 * i + 2), 16);
        return b;
    }

    @Test
    public void acceptsAFinishedTransactionAsTheSignerReturnsIt() throws Exception {
        VaultWithdrawal.Result r = VaultWithdrawal.build(coins(100_000), keys, destination, 30_000, 2, changeAddress, FP, ORIGIN);
        String rawHex = VaultWithdrawal.finish(signed(r.psbt()), r.psbt()).rawTxHex(); // what a finalizing signer returns
        VaultWithdrawal.Finished done = VaultWithdrawal.finishAny(rawHex, r.psbt());
        assertEquals(rawHex, done.rawTxHex());
        assertEquals(r.feeSats(), done.feeSats());
        // the same bytes as base64 work too
        String b64 = java.util.Base64.getEncoder().encodeToString(fromHex(rawHex));
        assertEquals(rawHex, VaultWithdrawal.finishAny(b64, r.psbt()).rawTxHex());
    }

    @Test
    public void refusesAFinishedTransactionForADifferentWithdrawal() throws Exception {
        List<TransactionOutput> same = coins(100_000);
        VaultWithdrawal.Result asked = VaultWithdrawal.build(same, keys, destination, 30_000, 2, changeAddress, FP, ORIGIN);
        VaultWithdrawal.Result other = VaultWithdrawal.build(same, keys, destination, 99_000, 2, changeAddress, FP, ORIGIN);
        String rawHex = VaultWithdrawal.finish(signed(other.psbt()), other.psbt()).rawTxHex();
        try {
            VaultWithdrawal.finishAny(rawHex, asked.psbt());
            fail();
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("not the withdrawal you asked for"));
        }
    }

    @Test
    public void psbtTextStillGoesThroughFinishAny() throws Exception {
        VaultWithdrawal.Result r = VaultWithdrawal.build(coins(100_000), keys, destination, 30_000, 2, changeAddress, FP, ORIGIN);
        assertEquals(r.feeSats(), VaultWithdrawal.finishAny(signed(r.psbt()).toBase64(), r.psbt()).feeSats());
    }

    @Test
    public void compactRequestIsSmallerAndStillMatchesTheFullOne() throws Exception {
        VaultWithdrawal.Result r = VaultWithdrawal.build(coins(100_000, 50_000), keys, destination, 120_000, 2, changeAddress, FP, ORIGIN);
        Psbt small = VaultWithdrawal.compact(r.psbt());
        assertTrue(small.serialize().length < r.psbt().serialize().length);
        assertNull(small.input(0).get(0x00));       // previous transaction dropped
        assertNotNull(small.input(0).get(0x01));    // spent output kept
        assertEquals(1, small.input(0).all(0x06).size()); // key path kept
        assertTrue(small.sameTransactionAs(r.psbt()));
        // a result signed from the compact request is accepted against the full one
        assertEquals(r.feeSats(), VaultWithdrawal.finish(signed(small), r.psbt()).feeSats());
    }
}
