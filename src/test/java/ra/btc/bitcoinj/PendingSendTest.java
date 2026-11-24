package ra.btc.bitcoinj;

import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.base.Coin;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.core.PeerAddress;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionConfidence;
import org.bitcoinj.wallet.DefaultCoinSelector;
import org.bitcoinj.wallet.Wallet;
import org.bitcoinj.wallet.WalletProtobufSerializer;
import org.junit.Test;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.fail;
import static org.junit.Assert.assertTrue;

public class PendingSendTest {

    private static Wallet wallet() {
        org.bitcoinj.core.Context.propagate(new org.bitcoinj.core.Context());
        return Wallet.createDeterministic(BitcoinNetwork.MAINNET, ScriptType.P2WPKH);
    }

    /** An unconfirmed transaction paying {@code sats} to the wallet; {@code own} marks it as made by the wallet itself. */
    private static Transaction pendingPayment(Wallet wallet, long sats, boolean own, int seed) {
        Transaction tx = new Transaction();
        tx.addInput(org.bitcoinj.base.Sha256Hash.of(new byte[]{(byte) seed}), 0, org.bitcoinj.script.ScriptBuilder.createEmpty());
        tx.addOutput(Coin.valueOf(sats), wallet.freshReceiveAddress(ScriptType.P2WPKH));
        if (own) tx.getConfidence().setSource(TransactionConfidence.Source.SELF);
        wallet.receivePending(tx, null);
        return tx;
    }

    @Test
    public void ownUnconfirmedChangeIsSpendableWithoutWaitingForAPeerToRelayItBack() {
        Wallet wallet = wallet();
        pendingPayment(wallet, 900_000, true, 1);

        // bitcoinj's own rule: not until a peer has announced it, so the whole balance shows as locked.
        assertEquals(Coin.ZERO, wallet.getBalance(DefaultCoinSelector.get(BitcoinNetwork.MAINNET)));
        // Ours: it is the wallet's own change, so it is spendable at once.
        assertEquals(Coin.valueOf(900_000), wallet.getBalance(new BitcoinJClient.OwnChangeCoinSelector()));
    }

    @Test
    public void anUnconfirmedPaymentFromSomeoneElseIsStillNotSpendable() {
        Wallet wallet = wallet();
        Transaction incoming = pendingPayment(wallet, 50_000, false, 2);
        assertEquals(Coin.ZERO, wallet.getBalance(new BitcoinJClient.OwnChangeCoinSelector()));
        assertFalse(BitcoinJClient.isSpendableNow(incoming));
    }

    @Test
    public void spendableNowMeansConfirmedOrOwnPending() {
        Wallet wallet = wallet();
        assertTrue(BitcoinJClient.isSpendableNow(pendingPayment(wallet, 10_000, true, 3)));
        assertFalse(BitcoinJClient.isSpendableNow(pendingPayment(wallet, 10_000, false, 4)));
    }

    @Test
    public void aPeerWithNoIpAddressBreaksTheWalletFileUntilItIsScrubbed() throws Exception {
        Wallet wallet = wallet();
        Transaction tx = pendingPayment(wallet, 900_000, true, 5);
        PeerAddress hostnameOnly = PeerAddress.simple(InetSocketAddress.createUnresolved("exampleonionaddress.onion", 8333));
        PeerAddress normal = PeerAddress.simple(new InetSocketAddress(InetAddress.getByAddress(new byte[]{1, 2, 3, 4}), 8333));
        tx.getConfidence().markBroadcastBy(hostnameOnly);
        tx.getConfidence().markBroadcastBy(normal);

        // The failure behind "send failed: NullPointerException ... InetAddress.getAddress()".
        try {
            new WalletProtobufSerializer().walletToProto(wallet);
            fail("expected the wallet to fail to serialize a peer with no IP address");
        } catch (NullPointerException expected) {
            // reproduced
        }

        assertEquals(1, BitcoinJClient.scrubAddresslessPeers(List.of(tx)));
        assertEquals(1, tx.getConfidence().numBroadcastPeers()); // the peer with an address is kept
        new WalletProtobufSerializer().walletToProto(wallet); // no longer throws
        assertEquals(0, BitcoinJClient.scrubAddresslessPeers(List.of(tx))); // nothing left to remove
    }
}
