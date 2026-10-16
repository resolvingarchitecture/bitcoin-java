package ra.btc.bitcoinj;

import com.google.protobuf.ByteString;
import org.bitcoinj.protobuf.wallet.Protos;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;

import static org.junit.Assert.assertEquals;

public class WalletRepairTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

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
}
