package ra.btc.bitcoinj;

import com.google.protobuf.ByteString;
import org.bitcoinj.base.Address;
import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.core.Block;
import org.bitcoinj.core.Context;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.core.StoredBlock;
import org.bitcoinj.params.RegTestParams;
import org.bitcoinj.protobuf.wallet.Protos;
import org.bitcoinj.store.SPVBlockStore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertEquals;

public class WalletRepairTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    @org.junit.Before
    public void context() {
        Context.propagate(new Context(RegTestParams.get())); // building blocks needs one
    }

    private static Protos.Transaction tx(int id, Protos.Transaction.Pool pool, Protos.TransactionConfidence.Type type, boolean inBlock) {
        Protos.Transaction.Builder t = Protos.Transaction.newBuilder()
                .setVersion(1)
                .setPool(pool)
                .setConfidence(Protos.TransactionConfidence.newBuilder().setType(type).setAppearedAtHeight(100 + id));
        t.setHash(ByteString.copyFrom(new byte[]{(byte) id, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}));
        if (inBlock) t.addBlockHash(ByteString.copyFrom(new byte[32]));
        return t.build();
    }

    private File write(Protos.Transaction... txs) throws Exception {
        Protos.Wallet.Builder w = Protos.Wallet.newBuilder().setNetworkIdentifier("org.bitcoin.production");
        for (Protos.Transaction t : txs) w.addTransaction(t);
        File f = tmp.newFile("test.wallet");
        try (FileOutputStream out = new FileOutputStream(f)) { w.build().writeTo(out); }
        return f;
    }

    private Protos.Wallet read(File f) throws Exception {
        try (FileInputStream in = new FileInputStream(f)) { return Protos.Wallet.parseFrom(in); }
    }

    @Test
    public void marksAPendingTransactionThatClaimsABlockPendingAgain() throws Exception {
        File f = write(
                tx(1, Protos.Transaction.Pool.SPENT, Protos.TransactionConfidence.Type.BUILDING, true),
                tx(2, Protos.Transaction.Pool.PENDING, Protos.TransactionConfidence.Type.BUILDING, false));
        assertEquals(1, BitcoinJClient.repairInterruptedWalletSave(f));
        Protos.Wallet w = read(f);
        assertEquals(Protos.TransactionConfidence.Type.BUILDING, w.getTransaction(0).getConfidence().getType());
        assertEquals(Protos.TransactionConfidence.Type.PENDING, w.getTransaction(1).getConfidence().getType());
        assertEquals(0, w.getTransaction(1).getConfidence().getAppearedAtHeight());
    }

    @Test
    public void leavesAConsistentWalletAlone() throws Exception {
        File f = write(
                tx(1, Protos.Transaction.Pool.SPENT, Protos.TransactionConfidence.Type.BUILDING, true),
                tx(2, Protos.Transaction.Pool.PENDING, Protos.TransactionConfidence.Type.PENDING, false));
        byte[] before = java.nio.file.Files.readAllBytes(f.toPath());
        assertEquals(0, BitcoinJClient.repairInterruptedWalletSave(f));
        assertEquals(java.util.Arrays.hashCode(before), java.util.Arrays.hashCode(java.nio.file.Files.readAllBytes(f.toPath())));
    }

    @Test
    public void ignoresAMissingFile() {
        assertEquals(0, BitcoinJClient.repairInterruptedWalletSave(new File(tmp.getRoot(), "none.wallet")));
    }

    /** A chain file at {@code dir/name.spvchain} of {@code blocks} blocks above genesis; returns the hash at each height 1..blocks. */
    private List<Sha256Hash> chain(String name, int blocks) throws Exception {
        RegTestParams params = RegTestParams.get();
        SPVBlockStore store = new SPVBlockStore(params, new File(tmp.getRoot(), name + ".spvchain"));
        StoredBlock head = store.getChainHead();
        Block block = params.getGenesisBlock();
        Address to = new ECKey().toAddress(ScriptType.P2WPKH, BitcoinNetwork.REGTEST);
        List<Sha256Hash> hashes = new ArrayList<>();
        hashes.add(block.getHash());
        for (int i = 1; i <= blocks; i++) {
            block = block.createNextBlock(to);
            block.solve();
            head = head.build(block);
            store.put(head);
            store.setChainHead(head);
            hashes.add(block.getHash());
        }
        store.close();
        return hashes;
    }

    private File walletWith(String name, int lastSeen, Protos.Transaction... txs) throws Exception {
        Protos.Wallet.Builder w = Protos.Wallet.newBuilder().setNetworkIdentifier(RegTestParams.get().getId())
                .setLastSeenBlockHeight(lastSeen);
        for (Protos.Transaction t : txs) w.addTransaction(t);
        File f = new File(tmp.getRoot(), name + ".wallet");
        try (FileOutputStream out = new FileOutputStream(f)) { w.build().writeTo(out); }
        return f;
    }

    /** A transaction left pending although the wallet recorded {@code block} for it. */
    private static Protos.Transaction strandedIn(int id, Protos.Transaction.Pool pool, Sha256Hash block) {
        return tx(id, pool, Protos.TransactionConfidence.Type.PENDING, false).toBuilder()
                .clearConfidence().setConfidence(Protos.TransactionConfidence.newBuilder().setType(Protos.TransactionConfidence.Type.PENDING))
                .addBlockHash(ByteString.copyFrom(block.getBytes())).build();
    }

    @Test
    public void aTransactionStrandedPendingInABestChainBlockIsConfirmedThere() throws Exception {
        List<Sha256Hash> hashes = chain("w1", 6);
        File f = walletWith("w1", 6, strandedIn(1, Protos.Transaction.Pool.SPENT, hashes.get(3)));
        assertEquals(1, BitcoinJClient.repairInterruptedWalletSave(f));
        Protos.TransactionConfidence c = read(f).getTransaction(0).getConfidence();
        assertEquals(Protos.TransactionConfidence.Type.BUILDING, c.getType());
        assertEquals(3, c.getAppearedAtHeight());
        assertEquals(4, c.getDepth());
        assertEquals(0, BitcoinJClient.repairInterruptedWalletSave(f)); // nothing left to repair
    }

    @Test
    public void aBlockTheWalletHasNotSeenYetIsLeftForTheChainToApply() throws Exception {
        List<Sha256Hash> hashes = chain("w2", 6);
        File f = walletWith("w2", 2, strandedIn(1, Protos.Transaction.Pool.UNSPENT, hashes.get(4)));
        assertEquals(0, BitcoinJClient.repairInterruptedWalletSave(f));
        assertEquals(Protos.TransactionConfidence.Type.PENDING, read(f).getTransaction(0).getConfidence().getType());
    }

    @Test
    public void aBlockThatIsNotOnTheChainIsNotTrusted() throws Exception {
        chain("w3", 6);
        File f = walletWith("w3", 6, strandedIn(1, Protos.Transaction.Pool.SPENT, Sha256Hash.of(new byte[]{1, 2, 3})));
        assertEquals(0, BitcoinJClient.repairInterruptedWalletSave(f));
        assertEquals(Protos.TransactionConfidence.Type.PENDING, read(f).getTransaction(0).getConfidence().getType());
    }

    @Test
    public void aNormalPendingTransactionIsLeftAlone() throws Exception {
        List<Sha256Hash> hashes = chain("w4", 6);
        File f = walletWith("w4", 6, strandedIn(1, Protos.Transaction.Pool.PENDING, hashes.get(3)));
        assertEquals(0, BitcoinJClient.repairInterruptedWalletSave(f));
    }

    @Test
    public void withoutAChainFileNothingIsConfirmed() throws Exception {
        List<Sha256Hash> hashes = chain("other", 6);
        File f = walletWith("w5", 6, strandedIn(1, Protos.Transaction.Pool.SPENT, hashes.get(3)));
        assertEquals(0, BitcoinJClient.repairInterruptedWalletSave(f));
    }
}
