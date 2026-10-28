package ra.btc.bitcoinj;

import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.core.FeeFilterMessage;
import org.bitcoinj.core.GetDataMessage;
import org.bitcoinj.core.InventoryItem;
import org.bitcoinj.core.InventoryMessage;
import org.bitcoinj.core.ListMessage;
import org.bitcoinj.core.Message;
import org.bitcoinj.core.NotFoundMessage;
import org.bitcoinj.core.Peer;
import org.bitcoinj.core.PeerGroup;
import org.bitcoinj.core.RejectMessage;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.listeners.PreMessageReceivedEventListener;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

/**
 * Evidence that a broadcast reached the network, written to the log: what was sent and to which peers, anything a peer says
 * about it (asked for it, announced it back, rejected it, its minimum fee rate), and, after a delay, whether each peer
 * actually holds it in its mempool. "Handed to peers" is not "on the network"; this is how to tell the difference.
 */
final class BroadcastTrace {

    private static final ScheduledExecutorService WORKER = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "broadcast-trace");
        t.setDaemon(true);
        return t;
    });

    private BroadcastTrace() {}

    /** Call just before handing {@code tx} to the peer group. {@code feeSats} is -1 when the caller did not say. */
    static void begin(Logger log, PeerGroup group, Transaction tx, long feeSats) {
        Sha256Hash hash = tx.getTxId();
        String id = hash.toString().substring(0, 12);
        int vsize = tx.getVsize();
        log.info("trace " + id + ": " + tx.getInputs().size() + " inputs, " + tx.getOutputs().size() + " outputs, " + vsize
                + " vbytes, pays out " + tx.getOutputSum().value + " sats"
                + (feeSats >= 0 ? ", fee " + feeSats + " sats = " + String.format("%.2f", (double) feeSats / vsize) + " sat/vB" : ""));
        List<Peer> peers = new ArrayList<>(group.getConnectedPeers());
        log.info("trace " + id + ": " + peers.size() + " peers connected; held until " + group.getMinBroadcastConnections()
                + " are connected (maximum " + group.getMaxConnections() + ")");
        for (Peer peer : peers) {
            org.bitcoinj.core.VersionMessage v = peer.getPeerVersionMessage();
            log.info("trace " + id + ": peer " + peer + " version=" + v.clientVersion + " " + v.subVer
                    + " relaysTxes=" + v.relayTxesBeforeFilter + " ping=" + peer.getPingTime() + "ms");
        }
        PreMessageReceivedEventListener spy = (peer, message) -> {
            note(log, id, hash, peer, message);
            return message;
        };
        for (Peer peer : peers) peer.addPreMessageReceivedEventListener(spy);
        WORKER.schedule(() -> {
            for (Peer peer : peers) peer.removePreMessageReceivedEventListener(spy);
            log.info("trace " + id + ": stopped listening to peers");
        }, 4, TimeUnit.MINUTES);
        for (int seconds : new int[]{5, 30, 90, 180}) {
            WORKER.schedule(() -> mempoolCheck(log, id, hash, group, seconds + "s after sending"), seconds, TimeUnit.SECONDS);
        }
    }

    private static void note(Logger log, String id, Sha256Hash hash, Peer peer, Message message) {
        if (message instanceof RejectMessage) {
            RejectMessage r = (RejectMessage) message;
            boolean ours = hash.equals(r.rejectedMessageHash());
            log.warning("trace " + id + ": peer " + peer + " REJECTED " + (ours ? "OUR TRANSACTION" : r.rejectedMessage())
                    + " code=" + r.code() + " reason=" + r.reason());
        } else if (message instanceof FeeFilterMessage) {
            log.info("trace " + id + ": peer " + peer + " will only relay at or above " + ((FeeFilterMessage) message).feeRate().value
                    + " sats per kB");
        } else if (message instanceof NotFoundMessage) {
            if (mentions((ListMessage) message, hash)) log.warning("trace " + id + ": peer " + peer + " says it does NOT have our transaction");
        } else if (message instanceof GetDataMessage) {
            if (mentions((ListMessage) message, hash)) log.info("trace " + id + ": peer " + peer + " ASKED FOR our transaction (it took the announcement)");
        } else if (message instanceof InventoryMessage) {
            if (mentions((ListMessage) message, hash)) log.info("trace " + id + ": peer " + peer + " ANNOUNCED our transaction back");
        }
    }

    private static boolean mentions(ListMessage list, Sha256Hash hash) {
        for (InventoryItem item : list.getItems()) if (hash.equals(item.hash)) return true;
        return false;
    }

    /** Asks every connected peer for the transaction and logs who has it. */
    static void mempoolCheck(Logger log, String id, Sha256Hash hash, PeerGroup group, String when) {
        List<Peer> peers = new ArrayList<>(group.getConnectedPeers());
        List<CompletableFuture<Transaction>> asked = new ArrayList<>();
        for (Peer peer : peers) asked.add(peer.getPeerMempoolTransaction(hash));
        int have = 0;
        long deadline = System.currentTimeMillis() + 15_000;
        for (int i = 0; i < asked.size(); i++) {
            String verdict;
            try {
                asked.get(i).get(Math.max(1, deadline - System.currentTimeMillis()), TimeUnit.MILLISECONDS);
                have++;
                verdict = "HAS it";
            } catch (java.util.concurrent.TimeoutException e) {
                verdict = "no answer";
            } catch (Exception e) {
                verdict = "does not have it";
            }
            log.info("trace " + id + " (" + when + "): peer " + peers.get(i) + " " + verdict);
        }
        log.info("trace " + id + " (" + when + "): " + have + " of " + peers.size() + " peers have the transaction");
    }
}
