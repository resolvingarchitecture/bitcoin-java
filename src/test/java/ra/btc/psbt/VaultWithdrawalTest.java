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
}
