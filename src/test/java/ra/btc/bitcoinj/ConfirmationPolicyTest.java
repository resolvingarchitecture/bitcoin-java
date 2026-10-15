package ra.btc.bitcoinj;

import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.base.Coin;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionOutput;
import org.bitcoinj.wallet.Wallet;
import org.junit.Test;
import ra.btc.BitcoinClient;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

public class ConfirmationPolicyTest {

    @Test
    public void largerPaymentsNeedMoreConfirmations() {
        assertEquals(1, BitcoinClient.requiredConfirmations(19_999));
        assertEquals(2, BitcoinClient.requiredConfirmations(20_000));
        assertEquals(2, BitcoinClient.requiredConfirmations(999_999));
        assertEquals(3, BitcoinClient.requiredConfirmations(1_000_000));
        assertEquals(3, BitcoinClient.requiredConfirmations(9_999_999));
        assertEquals(4, BitcoinClient.requiredConfirmations(10_000_000));
        assertEquals(2, BitcoinClient.requiredConfirmations(-60_768)); // the size of a movement, whichever way it goes
    }

    @Test
    public void anUnconfirmedPaymentFromSomeoneElseIsNotSpendable() {
        org.bitcoinj.core.Context.propagate(new org.bitcoinj.core.Context());
        Wallet wallet = Wallet.createDeterministic(BitcoinNetwork.MAINNET, ScriptType.P2WPKH);
        Transaction incoming = new Transaction();
        incoming.addInput(org.bitcoinj.base.Sha256Hash.of(new byte[]{7}), 0, org.bitcoinj.script.ScriptBuilder.createEmpty());
        incoming.addOutput(Coin.valueOf(60_768), wallet.freshReceiveAddress(ScriptType.P2WPKH));
        wallet.receivePending(incoming, null);
        TransactionOutput out = incoming.getOutput(0);
        assertFalse(BitcoinJClient.meetsConfirmationPolicy(wallet, out));
    }
}
