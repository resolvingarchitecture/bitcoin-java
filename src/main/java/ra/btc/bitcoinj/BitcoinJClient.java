package ra.btc.bitcoinj;

import org.bitcoinj.base.Address;
import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.base.Coin;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.base.exceptions.AddressFormatException;
import org.bitcoinj.core.AbstractBlockChain;
import org.bitcoinj.core.Context;
import org.bitcoinj.core.InsufficientMoneyException;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.BitcoinSerializer;
import org.bitcoinj.core.PeerGroup;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionBroadcast;
import org.bitcoinj.core.TransactionOutput;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.kits.WalletAppKit;
import org.bitcoinj.net.BlockingClientManager;
import org.bitcoinj.net.ClientConnectionManager;
import org.bitcoinj.net.discovery.PeerDiscovery;
import org.bitcoinj.net.discovery.PeerDiscoveryException;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.script.ScriptException;
import org.bitcoinj.wallet.CoinSelector;
import org.bitcoinj.wallet.DefaultCoinSelector;
import org.bitcoinj.wallet.CoinSelection;
import org.bitcoinj.wallet.DeterministicSeed;
import org.bitcoinj.wallet.KeyChainGroupStructure;
import org.bitcoinj.wallet.SendRequest;
import org.bitcoinj.wallet.Wallet;
import ra.btc.BTCEscrow;
import ra.btc.BitcoinClient;
import ra.btc.BitcoinService;
import ra.common.Envelope;
import ra.common.route.Route;

import javax.net.SocketFactory;
import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.logging.Logger;

/**
 * BitcoinJ-backed {@link BitcoinClient}, used when no local Bitcoin Core node is detected
 * ({@link ra.btc.BitcoinService#localNodeRunning()}). Runs an SPV wallet via
 * {@link WalletAppKit} (bitcoinj 0.17.1 - package layout and constructors matching the working
 * reference in {@code 1m5-android}'s {@code WalletService}).
 *
 * <p>Peer connectivity matches what {@code 1m5-android}'s {@code WalletService} actually does
 * (checked directly against its current source 2026-09-19, not assumed from this class's own
 * older comment, which claimed peer discovery was unconditionally disabled pending a
 * {@code ra.networkmanager.NetworkManagerService} that was never built - dead code, removed):
 * an explicit peer list (config's {@code ra.btc.peers}, comma-separated {@code host:port})
 * is used when configured, via {@link StaticBitcoinPeerDiscovery}; otherwise, if a {@link
 * #setSeedResolver} was supplied, bitcoinj's built-in DNS seed hostnames are resolved through it
 * via {@link ProxiedDnsSeedDiscovery} (never local DNS); with neither, {@link WalletAppKit}'s own
 * default discovery (bitcoinj's built-in DNS-seed {@code MultiplexingDiscovery}, which does
 * resolve via local DNS) is left untouched, exactly {@code WalletService}'s own fallback. Bitcoin
 * P2P traffic is routed through a SOCKS proxy either way it's supplied -
 * {@link #setProxy}, preferred (a live proxy this node's own network layer already manages,
 * e.g. {@code tor-client-java}'s {@code TorSocksRelay}), or the legacy {@code ra.btc.socks.host}/
 * {@code ra.btc.socks.port} config strings for a caller with no live {@code Proxy} object to
 * hand over - the peer group's connection manager is swapped for a {@link BlockingClientManager}
 * routed through it (bitcoinj's own {@code BlockingClient} javadoc names this as the supported
 * way to connect over a proxy - the newer NIO transport it uses by default cannot).
 *
 * <p>{@code ra.btc.noDirectPeers=true} forces an explicitly empty {@link StaticBitcoinPeerDiscovery}
 * regardless of {@code ra.btc.peers} or any SOCKS config - the wallet still starts (balance,
 * receive address, offline signing via {@link BitcoinClient#OPERATION_SEND_OFFLINE} all work
 * from cached wallet state) but the {@link PeerGroup} makes zero connection attempts of its own.
 * Used when this node has no acceptable network path for its own Bitcoin P2P traffic right now
 * (e.g. no local Tor) but still needs to sign a spend for a peer to broadcast on its behalf.
 */
public class BitcoinJClient implements BitcoinClient {

    private static final Logger LOG = Logger.getLogger(BitcoinJClient.class.getName());

    private final BitcoinService service;

    private DeterministicSeed restoreFromSeed;
    private DeterministicKey restoreFromKey;
    private java.util.List<String> restoreWords;
    private long restoreCreationSeconds;

    private NetworkParameters params;
    private WalletAppKit kit;
    private BitcoinNetwork network;
    private Properties initConfig;
    /** The peer limit the group started with, captured the first time {@link #OPERATION_SET_MAX_PEERS} lowers it. */
    private int startupMaxPeers = -1;
    private long broadcastTimeoutMs = 15_000;
    private volatile Proxy externalProxy;
    private volatile BitcoinClient.ProxiedHostResolver externalSeedResolver;

    private final Map<UUID, BTCEscrow> escrows = new HashMap<>();

    public BitcoinJClient(BitcoinService service) {
        this.service = service;
    }

    /** See {@link BitcoinClient#setRestorePhrase}. Must be called before {@link #init}. */
    @Override
    public void setRestorePhrase(java.util.List<String> words, long creationEpochSeconds) {
        this.restoreWords = words == null ? null : new java.util.ArrayList<>(words);
        this.restoreCreationSeconds = creationEpochSeconds;
    }

    /** See {@link BitcoinClient#setProxy}. Must be called before {@link #init}. */
    @Override
    public void setProxy(Proxy proxy) {
        this.externalProxy = proxy;
    }

    /** See {@link BitcoinClient#setSeedResolver}. Must be called before {@link #init}. */
    @Override
    public void setSeedResolver(BitcoinClient.ProxiedHostResolver resolver) {
        this.externalSeedResolver = resolver;
    }

    public BitcoinJClient(BitcoinService service, DeterministicSeed deterministicSeed) {
        this.service = service;
        this.restoreFromSeed = deterministicSeed;
    }

    public BitcoinJClient(BitcoinService service, DeterministicKey deterministicKey) {
        this.service = service;
        this.restoreFromKey = deterministicKey;
    }

    @Override
    public boolean init(Properties config) throws Exception {
        File directory = service.getServiceDirectory();

        String env = config.getProperty("ra.env");
        final BitcoinNetwork network;
        if ("test".equalsIgnoreCase(env) || "qa".equalsIgnoreCase(env)) {
            network = BitcoinNetwork.TESTNET;
            LOG.info("BitcoinJ Client in Test mode.");
        } else if ("prod".equalsIgnoreCase(env)) {
            network = BitcoinNetwork.MAINNET;
            LOG.info("BitcoinJ Client in Production mode.");
        } else {
            network = BitcoinNetwork.REGTEST;
            LOG.info("BitcoinJ Client in RegTest mode.");
        }
        params = NetworkParameters.of(network);
        // One bitcoinj Context per wallet. A Context owns the table of transaction confidence, so wallets that share
        // one share a single confidence object for every transaction they both hold, and a payment from the main
        // wallet to the vault is exactly that: the vault wallet's older "pending" copy then overwrites the main
        // wallet's "confirmed", and loading the vault wallet can fail outright ("source cannot be set again").
        // Threads with no Context of their own fall back to the last one made, so the main wallet's is made last.
        for (int i = 0; i < vaultContexts.length; i++) vaultContexts[i] = new Context(params);
        mainContext = new Context(params);
        Context.propagate(mainContext);
        this.network = network;
        this.initConfig = config;

        broadcastTimeoutMs = parseLongOrDefault(config.getProperty("ra.btc.broadcastTimeoutMs"), 15_000);

        /*
         * Real, on-device/in-JVM finding: a network-mode restart in the same process ({@code
         * network.onemfive.core.business.BitcoinService.refreshNetworkModeIfChanged()} calls
         * {@code shutdown()} then immediately reconstructs a fresh {@code BitcoinJClient}/{@code
         * WalletAppKit} pointed at the same wallet directory) can hit a real {@code
         * OverlappingFileLockException} - not a rare theoretical case, reproduced repeatedly -
         * either from {@code WalletAppKit.isChainFileLocked()}'s own {@code tryLock()} (its
         * javadoc admits an exception can come from the startup process, but not that the check
         * itself can throw one instead of returning {@code true}), or from deeper inside {@code
         * WalletAppKit.startUp() -> SPVBlockStore}'s own lock acquisition once {@code
         * awaitRunning()} is already underway. Both are the same underlying condition (this JVM's
         * own just-shut-down kit hasn't fully released the lock yet) surfacing at two different
         * call sites, so both are handled the same way: retry the *whole* attempt below -
         * including reconstructing {@code kit} from scratch, since a once-failed {@code
         * WalletAppKit} can't be restarted - rather than patching each call site separately.
         */
        if (restoreWords != null) {
            // The words replace the wallet outright: WalletAppKit only restores into a directory with no wallet.
            for (String suffix : new String[]{".wallet", ".spvchain", ".wallet.repair.tmp"}) {
                File f = new File(directory, "bitcoinj" + suffix);
                if (f.exists() && !f.delete()) {
                    LOG.severe("could not remove " + f.getName() + " before restoring the wallet from its words");
                    return false;
                }
            }
            restoreFromSeed = DeterministicSeed.ofMnemonic(restoreWords, "",
                    java.time.Instant.ofEpochSecond(restoreCreationSeconds));
            restoreWords = null; // the seed keeps its own list
        }
        final int maxAttempts = 3;
        final long retryDelayMs = 250L;
        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            kit = newKit(network, directory, "bitcoinj", ScriptType.P2WPKH, config, null, mainContext,
                    KeyChainGroupStructure.BIP43);

            if (restoreFromSeed != null) {
                kit.restoreWalletFromSeed(restoreFromSeed);
            } else if (restoreFromKey != null) {
                kit.restoreWalletFromKey(restoreFromKey);
            }

            try {
                if (kit.isChainFileLocked()) {
                    LOG.severe("This service is already running and cannot be started twice.");
                    return false;
                }

                kit.startAsync();
                kit.awaitRunning();
                LOG.info("BitcoinJ WalletAppKit is running.");
                return true;
            } catch (RuntimeException e) {
                if (causedByOverlappingLock(e) && attempt < maxAttempts) {
                    LOG.info("WalletAppKit startup hit this JVM's own prior instance still releasing its "
                            + "chain-file lock (attempt " + attempt + "/" + maxAttempts + ") - retrying shortly");
                    try {
                        Thread.sleep(retryDelayMs);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        return false;
                    }
                    continue;
                }
                LOG.log(java.util.logging.Level.SEVERE, "BitcoinJ WalletAppKit failed to start: " + e.getMessage(), e);
                return false;
            }
        }
        return false; // unreachable - the loop above always returns
    }

    /**
     * A {@link WalletAppKit} wired the way every wallet in this client is: P2P connections through the configured
     * SOCKS proxy (or none at all with {@code ra.btc.noDirectPeers}), and peer discovery that never touches local
     * DNS. Not started - the caller restores/starts it. The main wallet and the vault scanner both come from here.
     */
    private WalletAppKit newKit(BitcoinNetwork network, File directory, String prefix, ScriptType scriptType,
                                Properties config) {
        return newKit(network, directory, prefix, scriptType, config, null, mainContext, KeyChainGroupStructure.BIP32);
    }

    /** As above; with {@code watchKey} the kit's wallet is a watch-only wallet for that account public key. */
    /**
     * Repairs two states bitcoinj can leave a wallet file in, either of which keeps a payment from showing as
     * confirmed or stops the wallet loading at all. Keys and every other transaction are untouched.
     *
     * <p>A file saved while a block was being applied holds a transaction in the pending pool whose confidence already
     * says it is in a block, with no block recorded for it; bitcoinj refuses to load that ("expected PENDING or
     * IN_CONFLICT, was BUILDING"). Marking it pending again is enough: the block is applied again as the chain catches
     * up.
     *
     * <p>A transaction can also be left pending although a block is recorded for it. When that block is on the best
     * chain in the wallet's own chain file, and the wallet has already seen that far, nothing will ever apply the block
     * again, so the transaction would stay at zero confirmations for good. It is marked confirmed in that block.
     *
     * <p>A file that is missing, unreadable or already consistent is left alone.
     *
     * @return how many transactions were repaired
     */
    static int repairInterruptedWalletSave(File walletFile) {
        if (!walletFile.isFile()) return 0;
        try {
            org.bitcoinj.protobuf.wallet.Protos.Wallet.Builder wallet;
            try (java.io.InputStream in = new java.io.FileInputStream(walletFile)) {
                wallet = org.bitcoinj.protobuf.wallet.Protos.Wallet.parseFrom(in).toBuilder();
            }
            int repaired = 0;
            java.util.Set<org.bitcoinj.base.Sha256Hash> stranded = new java.util.HashSet<>();
            for (int i = 0; i < wallet.getTransactionCount(); i++) {
                org.bitcoinj.protobuf.wallet.Protos.Transaction tx = wallet.getTransaction(i);
                if (tx.getPool() == org.bitcoinj.protobuf.wallet.Protos.Transaction.Pool.PENDING
                        && tx.getConfidence().getType() == org.bitcoinj.protobuf.wallet.Protos.TransactionConfidence.Type.BUILDING
                        && tx.getBlockHashCount() == 0) {
                    wallet.setTransaction(i, tx.toBuilder().setConfidence(tx.getConfidence().toBuilder()
                            .setType(org.bitcoinj.protobuf.wallet.Protos.TransactionConfidence.Type.PENDING)
                            .clearAppearedAtHeight().clearDepth()));
                    repaired++;
                } else if (tx.getPool() != org.bitcoinj.protobuf.wallet.Protos.Transaction.Pool.PENDING
                        && tx.getConfidence().getType() == org.bitcoinj.protobuf.wallet.Protos.TransactionConfidence.Type.PENDING
                        && tx.getBlockHashCount() > 0) {
                    for (com.google.protobuf.ByteString h : tx.getBlockHashList()) {
                        stranded.add(org.bitcoinj.base.Sha256Hash.wrap(h.toByteArray()));
                    }
                }
            }
            if (!stranded.isEmpty()) repaired += confirmStranded(wallet, stranded, chainFileFor(walletFile));
            if (repaired == 0) return 0;
            File tmp = new File(walletFile.getParentFile(), walletFile.getName() + ".repair.tmp");
            try (java.io.FileOutputStream out = new java.io.FileOutputStream(tmp)) {
                wallet.build().writeTo(out);
                out.getFD().sync();
            }
            java.nio.file.Files.move(tmp.toPath(), walletFile.toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            LOG.warning("repaired " + repaired + " transaction(s) in " + walletFile.getName()
                    + " left in a half-updated state");
            return repaired;
        } catch (IOException | RuntimeException ex) {
            LOG.log(java.util.logging.Level.WARNING, "could not check " + walletFile.getName() + " for an interrupted save", ex);
            return 0;
        }
    }

    /** The chain file that goes with a wallet file: {@code x.wallet} keeps its blocks in {@code x.spvchain}. */
    private static File chainFileFor(File walletFile) {
        String name = walletFile.getName();
        String base = name.endsWith(".wallet") ? name.substring(0, name.length() - ".wallet".length()) : name;
        return new File(walletFile.getParentFile(), base + ".spvchain");
    }

    /**
     * Marks the transactions left pending, whose recorded block is on the best chain at or below the height the wallet
     * has seen, as confirmed in that block. Returns how many were.
     */
    private static int confirmStranded(org.bitcoinj.protobuf.wallet.Protos.Wallet.Builder wallet,
                                       java.util.Set<org.bitcoinj.base.Sha256Hash> blockHashes, File chainFile) {
        if (!chainFile.isFile()) return 0;
        NetworkParameters chainParams;
        try {
            chainParams = NetworkParameters.fromID(wallet.getNetworkIdentifier());
        } catch (RuntimeException ex) {
            return 0;
        }
        if (chainParams == null) return 0;
        java.util.Map<org.bitcoinj.base.Sha256Hash, Integer> heights = new java.util.HashMap<>();
        int head;
        org.bitcoinj.store.SPVBlockStore store = null;
        try {
            store = new org.bitcoinj.store.SPVBlockStore(chainParams, chainFile);
            org.bitcoinj.core.StoredBlock block = store.getChainHead();
            head = block.getHeight();
            for (int steps = 0; block != null && steps < 5000 && heights.size() < blockHashes.size(); steps++) {
                if (blockHashes.contains(block.getHeader().getHash())) heights.put(block.getHeader().getHash(), block.getHeight());
                block = store.get(block.getHeader().getPrevBlockHash());
            }
        } catch (org.bitcoinj.store.BlockStoreException | RuntimeException ex) {
            LOG.log(java.util.logging.Level.WARNING, "could not read " + chainFile.getName() + " to confirm payments", ex);
            return 0;
        } finally {
            if (store != null) {
                try {
                    store.close();
                } catch (org.bitcoinj.store.BlockStoreException ignored) {
                    // nothing left to do with a store that will not close
                }
            }
        }
        int seen = wallet.getLastSeenBlockHeight();
        int confirmed = 0;
        for (int i = 0; i < wallet.getTransactionCount(); i++) {
            org.bitcoinj.protobuf.wallet.Protos.Transaction tx = wallet.getTransaction(i);
            if (tx.getPool() == org.bitcoinj.protobuf.wallet.Protos.Transaction.Pool.PENDING
                    || tx.getConfidence().getType() != org.bitcoinj.protobuf.wallet.Protos.TransactionConfidence.Type.PENDING) continue;
            Integer height = null;
            for (com.google.protobuf.ByteString h : tx.getBlockHashList()) {
                Integer found = heights.get(org.bitcoinj.base.Sha256Hash.wrap(h.toByteArray()));
                if (found != null) height = found;
            }
            if (height == null || height > seen || height > head) continue;
            wallet.setTransaction(i, tx.toBuilder().setConfidence(tx.getConfidence().toBuilder()
                    .setType(org.bitcoinj.protobuf.wallet.Protos.TransactionConfidence.Type.BUILDING)
                    .setAppearedAtHeight(height).setDepth(Math.min(head, seen) - height + 1)));
            confirmed++;
        }
        return confirmed;
    }

    private WalletAppKit newKit(BitcoinNetwork network, File directory, String prefix, ScriptType scriptType,
                                Properties config, DeterministicKey watchKey, Context kitContext,
                                KeyChainGroupStructure structure) {
        repairInterruptedWalletSave(new File(directory, prefix + ".wallet"));
        final Proxy proxy = externalProxy;
        final String socksHost = config.getProperty("ra.btc.socks.host");
        final int socksPort = parseIntOrDefault(config.getProperty("ra.btc.socks.port"), 0);
        final boolean useSocks = proxy != null || (socksHost != null && !socksHost.isEmpty() && socksPort > 0);
        final boolean noDirectPeers = "true".equalsIgnoreCase(config.getProperty("ra.btc.noDirectPeers"));

        WalletAppKit newKit = new WalletAppKit(network, scriptType, structure, directory, prefix) {
            // The kit starts and stops its wallet, chain and peers on threads of its own: give them this wallet's Context.
            @Override
            protected void startUp() throws Exception {
                Context.propagate(kitContext);
                super.startUp();
            }

            @Override
            protected void shutDown() throws Exception {
                Context.propagate(kitContext);
                super.shutDown();
            }

            @Override
            protected Wallet createWallet() {
                // restoreWalletFromKey wants a private key; a public account key needs a watching wallet.
                return watchKey != null ? Wallet.fromWatchingKey(network, watchKey, scriptType) : super.createWallet();
            }

            @Override
            protected void onSetupCompleted() {
                // bitcoinj holds a broadcast until about 80% of the maximum peer connections are up. Over Tor that can take
                // minutes (a withdrawal sat unsent for four), and a few peers are plenty to start the spread.
                peerGroup().setMinBroadcastConnections(3);
                // A watch-only vault only follows the chain, and each peer it uses is handed the vault's address filter, so
                // it keeps fewer connections than the default: less load on Tor and fewer nodes learning its addresses.
                if (watchKey != null) peerGroup().setMaxConnections(MAX_VAULT_PEERS);
                peerGroup().addConnectedEventListener((peer, count) ->
                        LOG.info("Bitcoin peer connected count=" + count + " peerHeight=" + peer.getBestHeight()));
                peerGroup().addDisconnectedEventListener((peer, count) ->
                        LOG.info("Bitcoin peer disconnected remaining=" + count
                                + " services=" + (peer.getPeerVersionMessage() == null ? "no handshake"
                                : peer.getPeerVersionMessage().services())));
                peerGroup().addBlocksDownloadedEventListener((peer, block, filtered, remaining) -> {
                    int height = chain().getBestChainHeight();
                    if (remaining == 0 || height % 10 == 0)
                        LOG.info("Bitcoin sync height=" + height + " blocksRemaining=" + remaining);
                });
            }

            @Override
            protected PeerGroup createPeerGroup() {
                if (!useSocks) {
                    return super.createPeerGroup();
                }
                SocketFactory socksSocketFactory;
                if (proxy != null) {
                    LOG.info("Routing Bitcoin P2P connections through supplied SOCKS proxy " + proxy);
                    socksSocketFactory = socksSocketFactory(proxy);
                } else {
                    LOG.info("Routing Bitcoin P2P connections through SOCKS proxy " + socksHost + ":" + socksPort);
                    socksSocketFactory = socksSocketFactory(new Proxy(Proxy.Type.SOCKS, new InetSocketAddress(socksHost, socksPort)));
                }
                BlockingClientManager connectionManager = new BlockingClientManager(socksSocketFactory) {
                    @Override
                    public org.bitcoinj.utils.ListenableCompletableFuture<java.net.SocketAddress> openConnection(
                            java.net.SocketAddress address, org.bitcoinj.net.StreamConnection connection) {
                        org.bitcoinj.utils.ListenableCompletableFuture<java.net.SocketAddress> result = super.openConnection(address, connection);
                        result.whenComplete((connected, error) -> {
                            if (error != null) LOG.log(java.util.logging.Level.WARNING, "Bitcoin SOCKS connection failed", error);
                            else LOG.info("Bitcoin SOCKS connection established");
                        });
                        return result;
                    }
                };
                connectionManager.setConnectTimeout(Duration.ofSeconds(45));
                PeerGroup peers = new SocksRoutedPeerGroup(network, vChain, connectionManager);
                peers.setConnectTimeout(Duration.ofSeconds(60));
                return peers;
            }
        };

        if (network == BitcoinNetwork.REGTEST) {
            newKit.connectToLocalHost();
        } else if (noDirectPeers) {
            // Explicitly empty, not merely absent: falling through to BitcoinJ's own DNS-seed
            // discovery here would leak a direct clearnet connection attempt, defeating the
            // whole reason this flag was set (no acceptable network path right now). The wallet
            // itself still starts - balance/receive-address/offline signing all work from cached
            // state - only the PeerGroup makes zero connection attempts.
            LOG.info("ra.btc.noDirectPeers=true - wallet starting with zero peer discovery.");
            newKit.setDiscovery(new StaticBitcoinPeerDiscovery(java.util.Collections.emptyList()));
        } else {
            List<InetSocketAddress> explicitPeers = parsePeers(config.getProperty("ra.btc.peers"));
            if (!explicitPeers.isEmpty()) {
                LOG.info("Using explicit Bitcoin peers: " + explicitPeers);
                newKit.setDiscovery(new StaticBitcoinPeerDiscovery(explicitPeers));
            } else if (externalSeedResolver != null) {
                LOG.info("No explicit Bitcoin peers configured (ra.btc.peers) - resolving BitcoinJ's "
                        + "own DNS seeds through the supplied proxied resolver instead of local DNS.");
                newKit.setDiscovery(new ProxiedDnsSeedDiscovery(params.getDnsSeeds(), params.getPort(), externalSeedResolver));
            } else {
                LOG.info("No explicit Bitcoin peers configured (ra.btc.peers) - using BitcoinJ's "
                        + "own default peer discovery, same fallback 1m5-android's WalletService uses.");
                // Deliberately not calling newKit.setDiscovery(...) here - leaving WalletAppKit's
                // own PeerGroup default discovery (bitcoinj's built-in DNS-seed
                // MultiplexingDiscovery) in place. Only reached with no seed resolver supplied -
                // a real leak (see ProxiedDnsSeedDiscovery's javadoc) but the same behavior this
                // class has always had for a caller with no proxied-DNS notion.
            }
        }
        newKit.setBlockingStartup(false);
        return newKit;
    }

    /** Walks {@code t}'s cause chain - see {@link #init}'s retry-loop comment for why this matters. */
    private static boolean causedByOverlappingLock(Throwable t) {
        for (Throwable cause = t; cause != null; cause = cause.getCause()) {
            if (cause instanceof java.nio.channels.OverlappingFileLockException) return true;
        }
        return false;
    }

    private static int parseIntOrDefault(String value, int def) {
        if (value == null || value.isEmpty()) return def;
        try {
            return Integer.parseInt(value.trim());
        } catch (NumberFormatException e) {
            return def;
        }
    }
    
    private static long parseLongOrDefault(String value, long def) {
        if (value == null || value.isEmpty()) return def;
        try {
            return Long.parseLong(value.trim());
        } catch (NumberFormatException e) {
            return def;
        }
    }

    /** Java 8 target (Android) - no {@code java.util.HexFormat} (Java 17+) available. */
    private static byte[] decodeHex(String hex) {
        if ((hex.length() & 1) != 0) {
            throw new IllegalArgumentException("odd-length hex string");
        }
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(hex.charAt(i * 2), 16);
            int lo = Character.digit(hex.charAt(i * 2 + 1), 16);
            if (hi < 0 || lo < 0) {
                throw new IllegalArgumentException("invalid hex character at position " + (i * 2));
            }
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    /** {@code ra.btc.peers}: comma-separated {@code host:port} entries. Unparseable entries are skipped, logged, not fatal. */
    private static List<InetSocketAddress> parsePeers(String value) {
        List<InetSocketAddress> peers = new ArrayList<>();
        if (value == null || value.isBlank()) return peers;
        for (String entry : value.split(",")) {
            String hostPort = entry.trim();
            if (hostPort.isEmpty()) continue;
            int colon = hostPort.lastIndexOf(':');
            if (colon <= 0 || colon == hostPort.length() - 1) {
                LOG.warning("skipping malformed ra.btc.peers entry (expected host:port): " + hostPort);
                continue;
            }
            try {
                String host = hostPort.substring(0, colon);
                int port = Integer.parseInt(hostPort.substring(colon + 1));
                peers.add(InetSocketAddress.createUnresolved(host, port));
            } catch (NumberFormatException e) {
                LOG.warning("skipping malformed ra.btc.peers entry (bad port): " + hostPort);
            }
        }
        return peers;
    }

    /**
     * Matches {@code 1m5-android}'s own {@code WalletService.StaticBitcoinPeerDiscovery} exactly
     * - a fixed, operator-supplied peer list, no DNS lookups of its own.
     */
    private static final class StaticBitcoinPeerDiscovery implements PeerDiscovery {
        private final List<InetSocketAddress> peers;

        StaticBitcoinPeerDiscovery(List<InetSocketAddress> peers) {
            this.peers = new ArrayList<>(peers);
        }

        @Override
        public List<InetSocketAddress> getPeers(long services, Duration timeout) {
            return new ArrayList<>(peers);
        }

        @Override
        public void shutdown() {}
    }

    /**
     * Resolves BitcoinJ's own DNS seed hostnames through a {@link BitcoinClient.ProxiedHostResolver}
     * (e.g. {@code tor-client-java}'s {@code TorSocksRelay#resolve}) instead of {@code
     * DnsDiscovery.DnsSeedDiscovery}'s {@code InetAddress.getAllByName} - which ignores any proxy
     * set via {@link #setProxy} entirely (a {@code Proxy} object only affects {@code Socket}/
     * {@code URLConnection} connects, never {@code InetAddress} resolution) and always resolves
     * through the local/system DNS resolver, leaking this node's Bitcoin activity outside the
     * proxy even when every peer connection afterward is correctly routed through it.
     *
     * <p>Each resolver call answers with a single address - Tor's SOCKS5 {@code RESOLVE}
     * extension has no A-record-set equivalent, unlike a real DNS response - queried in parallel
     * across all configured seeds (same pattern {@code MultiplexingDiscovery} itself uses), so
     * one slow or unreachable seed doesn't hold up the others.
     */
    static final class ProxiedDnsSeedDiscovery implements PeerDiscovery {
        private final String[] seeds;
        private final int port;
        private final BitcoinClient.ProxiedHostResolver resolver;

        ProxiedDnsSeedDiscovery(String[] seeds, int port, BitcoinClient.ProxiedHostResolver resolver) {
            this.seeds = seeds != null ? seeds : new String[0];
            this.port = port;
            this.resolver = resolver;
        }

        @Override
        public List<InetSocketAddress> getPeers(long services, Duration timeout) throws PeerDiscoveryException {
            if (seeds.length == 0) {
                throw new PeerDiscoveryException("no DNS seeds configured for this network");
            }
            ExecutorService pool = Executors.newFixedThreadPool(seeds.length, r -> {
                Thread t = new Thread(r, "Proxied DNS seed lookup");
                t.setDaemon(true);
                return t;
            });
            try {
                List<Callable<InetSocketAddress>> tasks = new ArrayList<>();
                for (String seed : seeds) {
                    // SPV wallets need full blocks, bloom filters and witness support.
                    // Keep service-filtered seed queries inside Tor, just like plain queries.
                    long required = services | 1L | 4L | 8L;
                    String filteredSeed = "x" + Long.toHexString(required) + "." + seed;
                    tasks.add(() -> new InetSocketAddress(resolver.resolve(filteredSeed, timeout), port));
                }
                List<Future<InetSocketAddress>> futures = pool.invokeAll(tasks, timeout.toMillis(), TimeUnit.MILLISECONDS);
                List<InetSocketAddress> result = new ArrayList<>();
                for (int i = 0; i < futures.size(); i++) {
                    Future<InetSocketAddress> future = futures.get(i);
                    if (future.isCancelled()) {
                        LOG.info("proxied DNS seed lookup timed out: " + seeds[i]);
                        continue;
                    }
                    try {
                        result.add(future.get());
                    } catch (ExecutionException e) {
                        LOG.info("proxied DNS seed lookup failed for " + seeds[i] + ": " + e.getCause());
                    }
                }
                if (result.isEmpty()) {
                    throw new PeerDiscoveryException("no proxied DNS seed lookup returned a result in "
                            + timeout.toMillis() + " ms");
                }
                return result;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new PeerDiscoveryException(e);
            } finally {
                pool.shutdownNow();
            }
        }

        @Override
        public void shutdown() {}
    }

    private static SocketFactory socksSocketFactory(Proxy proxy) {
        return new SocketFactory() {
            @Override
            public Socket createSocket() {
                // Unconnected, proxy-bound socket - BlockingClient calls socket.connect(address, timeout) itself.
                return new Socket(proxy);
            }
            @Override
            public Socket createSocket(String host, int port) throws IOException {
                throw new UnsupportedOperationException("only createSocket() is used by BlockingClient");
            }
            @Override
            public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException {
                throw new UnsupportedOperationException("only createSocket() is used by BlockingClient");
            }
            @Override
            public Socket createSocket(InetAddress host, int port) throws IOException {
                throw new UnsupportedOperationException("only createSocket() is used by BlockingClient");
            }
            @Override
            public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
                throw new UnsupportedOperationException("only createSocket() is used by BlockingClient");
            }
        };
    }

    /**
     * {@link PeerGroup}'s connection-manager constructor is {@code protected}; this subclass
     * exists only to reach it from {@link BitcoinJClient}'s {@code createPeerGroup()} override.
     */
    private static final class SocksRoutedPeerGroup extends PeerGroup {
        SocksRoutedPeerGroup(BitcoinNetwork network, AbstractBlockChain chain, ClientConnectionManager connectionManager) {
            super(network, chain, connectionManager);
        }
    }

    @Override
    public void handleDocument(Envelope e) {
        Route route = e.getRoute();
        String operation = route.getOperation();
        boolean forVault = OPERATION_VAULT_SCAN_START.equals(operation) || OPERATION_VAULT_SCAN_STATUS.equals(operation)
                || OPERATION_VAULT_SCAN_CLEAR.equals(operation)
                || OPERATION_VAULT_WITHDRAWAL_REQUEST.equals(operation);
        Context.propagate(forVault ? vaultContextFor(vaultId(e)) : mainContext); // reading a transaction's confidence uses the thread's Context
        switch(operation) {
            case OPERATION_GET_BALANCE: {
                Coin available = kit.wallet().getBalance(Wallet.BalanceType.AVAILABLE);
                Coin estimated = kit.wallet().getBalance(Wallet.BalanceType.ESTIMATED);
                e.setHeader(HEADER_AVAILABLE_SATS, String.valueOf(available.value));
                e.setHeader(HEADER_BALANCE_SATS, String.valueOf(estimated.value));
                break;
            }
            case OPERATION_GET_WALLET_WORDS: {
                org.bitcoinj.wallet.DeterministicSeed seed = kit.wallet().getKeyChainSeed();
                if (seed == null || seed.getMnemonicCode() == null) {
                    e.addErrorMessage("This wallet has no recovery words.");
                } else {
                    e.setHeader(HEADER_WORDS, String.join(" ", seed.getMnemonicCode()));
                }
                break;
            }
            case OPERATION_GET_RECEIVE_ADDRESS: {
                e.setHeader(HEADER_ADDRESS, kit.wallet().currentReceiveAddress().toString());
                break;
            }
            case OPERATION_GET_FRESH_RECEIVE_ADDRESSES: {
                int count;
                try {
                    count = Integer.parseInt(String.valueOf(e.getHeader(HEADER_COUNT)).trim());
                } catch (NumberFormatException ex) {
                    count = 1;
                }
                count = Math.max(1, Math.min(20, count));
                StringBuilder fresh = new StringBuilder();
                for (int i = 0; i < count; i++) {
                    if (i > 0) fresh.append('\n');
                    fresh.append(kit.wallet().freshReceiveAddress(kit.wallet().getActiveKeyChain().getOutputScriptType()));
                }
                e.setHeader(HEADER_ADDRESSES, fresh.toString());
                break;
            }
            case OPERATION_LIST_TRANSACTIONS: {
                // Dependency-free encoding, not org.json: this module runs on plain-JVM hosts
                // (the 1m5-core-java desktop daemon) as well as Android (via 1m5-remnant), and
                // org.json is bundled on Android's boot classpath - adding the standalone
                // org.json:json artifact here would duplicate those classes on the Android side,
                // the exact `mergeDebugJavaResource`/checkDebugDuplicateClasses failure shape
                // 1m5-remnant's step 1 already hit once with BouncyCastle (see its TODO.md).
                // One record per line: txid|valueSats|confirmations|updateTimeMillis - none of
                // these fields can themselves contain '|' or '\n'.
                StringBuilder sb = new StringBuilder();
                try {
                    for (Transaction tx : kit.wallet().getTransactions(false)) {
                        long valueSats = tx.getValue(kit.wallet()).value;
                        int confirmations = tx.getConfidence().getDepthInBlocks();
                        long updateTimeMillis = tx.getUpdateTime().getTime();
                        sb.append(tx.getTxId()).append('|').append(valueSats).append('|')
                                .append(confirmations).append('|').append(updateTimeMillis).append('\n');
                    }
                    e.addContent(sb.toString().getBytes(StandardCharsets.UTF_8));
                } catch (ScriptException ex) {
                    e.addErrorMessage("could not list transactions: " + ex.getMessage());
                }
                break;
            }
            case OPERATION_LIST_PENDING_BROADCASTS: {
                // One record per outgoing wallet transaction: txid|confidenceType|rawTxHex.
                // Pending raw transactions let the core recover a locally committed send even
                // when an older process died before its relay retry was persisted.
                StringBuilder sb = new StringBuilder();
                try {
                    for (Transaction tx : kit.wallet().getTransactions(true)) {
                        long valueSats = tx.getValue(kit.wallet()).value;
                        if (valueSats >= 0) continue;
                        org.bitcoinj.core.TransactionConfidence.ConfidenceType confidence =
                                tx.getConfidence().getConfidenceType();
                        String rawTxHex = confidence == org.bitcoinj.core.TransactionConfidence.ConfidenceType.PENDING
                                ? bytesToHex(tx.serialize()) : "";
                        sb.append(tx.getTxId()).append('|').append(confidence.name()).append('|')
                                .append(rawTxHex).append('\n');
                    }
                    e.addContent(sb.toString().getBytes(StandardCharsets.UTF_8));
                } catch (ScriptException ex) {
                    e.addErrorMessage("could not list pending broadcasts: " + ex.getMessage());
                }
                break;
            }
            case OPERATION_SEND: {
                String addressStr = stringHeaderOrNull(e, HEADER_ADDRESS);
                String amountStr = stringHeaderOrNull(e, HEADER_AMOUNT_SATS);
                if (addressStr == null) {
                    e.addErrorMessage("missing " + HEADER_ADDRESS);
                    break;
                }
                try {
                    Address address = Address.fromString(params, addressStr);
                    long sats = Long.parseLong(amountStr);
                    SendRequest req = applyConfirmationPolicy(useAllInputsIfRequested(e, applyFeeRate(e, addFeeOutput(e, SendRequest.to(address, Coin.valueOf(sats))))));
                    Wallet.SendResult result = kit.wallet().sendCoins(kit.peerGroup(), req);
                    e.setHeader(HEADER_TXID, result.transaction().getTxId().toString());
                } catch (AddressFormatException ex) {
                    e.addErrorMessage("invalid address: " + addressStr);
                } catch (NumberFormatException ex) {
                    e.addErrorMessage("invalid amount: " + amountStr);
                } catch (InsufficientMoneyException ex) {
                    e.setHeader(HEADER_MISSING_SATS, String.valueOf(ex.missing.value));
                    e.addErrorMessage("insufficient balance: need " + ex.missing.value + " more sats");
                } catch (Wallet.DustySendRequested ex) {
                    // A real, on-device finding: at BitcoinChannel.HEADER_FEE_AMOUNT_SATS values
                    // near 1m5-remnant-android's own dev-fee-eligibility floor (1% of a 10,000-15,000
                    // sat send is 100-150 sats), the dev-fee output itself is below bitcoinj's dust
                    // threshold and the whole transaction is rejected here - see that app's own
                    // MIN_DEV_FEE_SATS floor, which exists precisely to keep callers from hitting this.
                    e.addErrorMessage("send failed: an output is too small to relay (dust)");
                } catch (RuntimeException ex) {
                    // Covers Wallet.TransactionCompletionException (itself a RuntimeException) and
                    // anything else sendCoins/Address.fromString can throw unchecked.
                    e.addErrorMessage("send failed: " + ex);
                }
                break;
            }
            case OPERATION_SEND_OFFLINE: {
                String addressStr = stringHeaderOrNull(e, HEADER_ADDRESS);
                String amountStr = stringHeaderOrNull(e, HEADER_AMOUNT_SATS);
                if (addressStr == null) {
                    e.addErrorMessage("missing " + HEADER_ADDRESS);
                    break;
                }
                try {
                    Address address = Address.fromString(params, addressStr);
                    long sats = Long.parseLong(amountStr);
                    SendRequest req = applyConfirmationPolicy(useAllInputsIfRequested(e, applyFeeRate(e, addFeeOutput(e, SendRequest.to(address, Coin.valueOf(sats))))));
                    Transaction tx = kit.wallet().sendCoinsOffline(req);
                    e.setHeader(HEADER_TXID, tx.getTxId().toString());
                    e.setHeader(HEADER_RAW_TX_HEX, bytesToHex(tx.serialize()));
                } catch (AddressFormatException ex) {
                    e.addErrorMessage("invalid address: " + addressStr);
                } catch (NumberFormatException ex) {
                    e.addErrorMessage("invalid amount: " + amountStr);
                } catch (InsufficientMoneyException ex) {
                    e.setHeader(HEADER_MISSING_SATS, String.valueOf(ex.missing.value));
                    e.addErrorMessage("insufficient balance: need " + ex.missing.value + " more sats");
                } catch (Wallet.DustySendRequested ex) {
                    e.addErrorMessage("offline send failed: an output is too small to relay (dust)");
                } catch (RuntimeException ex) {
                    // Covers Wallet.TransactionCompletionException (itself a RuntimeException) and
                    // anything else sendCoinsOffline/Address.fromString can throw unchecked.
                    e.addErrorMessage("offline send failed: " + ex);
                }
                break;
            }

            case OPERATION_ESTIMATE_SEND: {
                String addressStr = stringHeaderOrNull(e, HEADER_ADDRESS);
                String amountStr = stringHeaderOrNull(e, HEADER_AMOUNT_SATS);
                if (addressStr == null) {
                    e.addErrorMessage("missing " + HEADER_ADDRESS);
                    break;
                }
                try {
                    Address address = Address.fromString(params, addressStr);
                    long sats = Long.parseLong(amountStr);
                    SendRequest req = applyConfirmationPolicy(useAllInputsIfRequested(e, applyFeeRate(e, addFeeOutput(e, SendRequest.to(address, Coin.valueOf(sats))))));
                    // completeTx alone (not sendCoins/sendCoinsOffline, neither of which this
                    // calls) selects coins and computes the fee without ever calling commitTx -
                    // no side effects, safe to call on every keystroke. See BitcoinClient's javadoc.
                    kit.wallet().completeTx(req);
                    // Transaction.getFee() (bitcoinj) returns null, not zero, if any selected
                    // input's cached value is unknown - a real, on-device finding: this untested-
                    // until-now success path (every existing test runs against an empty wallet,
                    // which throws InsufficientMoneyException before ever reaching this line) threw
                    // a bare NPE with no message the first time it ran against a real funded wallet.
                    Coin fee = req.tx.getFee();
                    if (fee == null) {
                        e.addErrorMessage("estimate failed: could not determine the fee (an input's value is unknown)");
                        break;
                    }
                    e.setHeader(HEADER_NETWORK_FEE_SATS, String.valueOf(fee.value));
                } catch (AddressFormatException ex) {
                    e.addErrorMessage("invalid address: " + addressStr);
                } catch (NumberFormatException ex) {
                    e.addErrorMessage("invalid amount: " + amountStr);
                } catch (InsufficientMoneyException ex) {
                    e.setHeader(HEADER_MISSING_SATS, String.valueOf(ex.missing.value));
                    e.addErrorMessage("insufficient balance: need " + ex.missing.value + " more sats");
                } catch (Wallet.DustySendRequested ex) {
                    e.addErrorMessage("estimate failed: an output is too small to relay (dust)");
                } catch (RuntimeException ex) {
                    e.addErrorMessage("estimate failed: " + ex);
                }
                break;
            }
            case OPERATION_SET_MAX_PEERS: {
                String requested = stringHeaderOrNull(e, HEADER_MAX_PEERS);
                PeerGroup group;
                try {
                    group = kit == null ? null : kit.peerGroup();
                } catch (IllegalStateException notStarted) {
                    group = null;
                }
                if (group == null) {
                    e.addErrorMessage("wallet is not running");
                    break;
                }
                synchronized (this) {
                    if (startupMaxPeers < 0) startupMaxPeers = group.getMaxConnections();
                    int target;
                    try {
                        target = "default".equalsIgnoreCase(requested) ? startupMaxPeers : Integer.parseInt(requested.trim());
                    } catch (RuntimeException ex) {
                        e.addErrorMessage("invalid " + HEADER_MAX_PEERS + ": " + requested);
                        break;
                    }
                    if (target < 1) {
                        e.addErrorMessage("invalid " + HEADER_MAX_PEERS + ": " + requested);
                        break;
                    }
                    group.setMaxConnections(target);
                    LOG.info("Bitcoin max peers set to " + target + " (startup " + startupMaxPeers + ")");
                    e.setHeader(HEADER_MAX_PEERS, String.valueOf(target));
                }
                break;
            }
            case OPERATION_SYNC_STATUS: {
                // A download peer being assigned is not "still syncing" - bitcoinj
                // keeps one designated for ongoing chain-tip following long after
                // the initial block download finishes, so that alone was true
                // forever post-sync (a real, user-visible bug: the wallet screen's
                // "Syncing..." text never went away even after real transactions
                // were confirmed). Comparing against a single peer's getBestHeight()
                // has its own version of the same problem: that value is a snapshot
                // from that peer's version handshake, never updated afterward, so
                // one persistently-stale peer keeps "syncing" true forever even
                // fully caught up (also observed on-device: stuck on CONNECTING with
                // a healthy, growing peer count). getMostCommonChainHeight() is
                // bitcoinj's own network-consensus signal - the mode across every
                // connected peer, the same one it uses internally to decide whether
                // to start a chain download at all - so it can't get stuck on one
                // outlier and self-corrects as peers connect/disconnect.
                //
                // Real, on-device finding: with zero connected peers (observed repeatedly - Tor
                // circuit churn/peer drops are normal, not rare), this defaulted to false, i.e.
                // "caught up" - the wallet screen showed "Synced at block N" with N a stale local
                // height and no peer confirming the real network is anywhere near it. Zero peers
                // means "unconfirmed," not "confirmed caught up" - defaults to true (still
                // syncing/unverified) until a peer's own consensus height says otherwise.
                boolean syncing = true;
                if (kit.peerGroup() != null && kit.chain() != null && !kit.peerGroup().getConnectedPeers().isEmpty()) {
                    int networkHeight = kit.peerGroup().getMostCommonChainHeight();
                    syncing = networkHeight > kit.chain().getBestChainHeight();
                }
                int bestHeight = kit.chain() != null ? kit.chain().getBestChainHeight() : -1;
                int connectedPeers = kit.peerGroup() != null ? kit.peerGroup().getConnectedPeers().size() : 0;
                e.setHeader(HEADER_SYNCING, String.valueOf(syncing));
                e.setHeader(HEADER_BEST_HEIGHT, String.valueOf(bestHeight));
                e.setHeader(HEADER_CONNECTED_PEERS, String.valueOf(connectedPeers));
                break;
            }
            case OPERATION_VAULT_SCAN_START: {
                startVaultScan(e);
                break;
            }
            case OPERATION_VAULT_SCAN_STATUS: {
                vaultScanStatus(e);
                break;
            }
            case OPERATION_VAULT_SCAN_CLEAR: {
                clearVaultScan(vaultId(e));
                break;
            }
            case OPERATION_VAULT_WITHDRAWAL_REQUEST: {
                vaultWithdrawalRequest(e);
                break;
            }
            case OPERATION_VAULT_WITHDRAWAL_FINISH: {
                vaultWithdrawalFinish(e);
                break;
            }
            case OPERATION_TX_PEER_CHECK: {
                String txidText = stringHeaderOrNull(e, HEADER_TXID);
                if (txidText == null) {
                    e.addErrorMessage("checking a transaction needs " + HEADER_TXID);
                    break;
                }
                org.bitcoinj.base.Sha256Hash hash;
                try {
                    hash = org.bitcoinj.base.Sha256Hash.wrap(txidText.trim());
                } catch (IllegalArgumentException ex) {
                    e.addErrorMessage("That is not a transaction ID.");
                    break;
                }
                List<org.bitcoinj.core.Peer> peers = new ArrayList<>(kit.peerGroup().getConnectedPeers());
                List<java.util.concurrent.CompletableFuture<Transaction>> asked = new ArrayList<>();
                for (org.bitcoinj.core.Peer peer : peers) asked.add(peer.getPeerMempoolTransaction(hash));
                int have = 0;
                long deadline = System.currentTimeMillis() + 20_000;
                for (java.util.concurrent.CompletableFuture<Transaction> f : asked) {
                    try {
                        f.get(Math.max(1, deadline - System.currentTimeMillis()), TimeUnit.MILLISECONDS);
                        have++;
                    } catch (Exception ignored) {
                        // not found, timed out or the peer left: it does not have it as far as we can tell
                    }
                }
                e.setHeader(HEADER_PEERS_ASKED, String.valueOf(peers.size()));
                e.setHeader(HEADER_PEERS_HAVE, String.valueOf(have));
                break;
            }
            case OPERATION_VAULT_WITHDRAWAL_COMPACT: {
                String requestText = stringHeaderOrNull(e, HEADER_VAULT_REQUEST);
                if (requestText == null) {
                    e.addErrorMessage("compacting a withdrawal needs " + HEADER_VAULT_REQUEST);
                    break;
                }
                try {
                    e.setHeader(HEADER_VAULT_PSBT, ra.btc.psbt.VaultWithdrawal.compact(ra.btc.psbt.Psbt.parseText(requestText)).toBase64());
                } catch (IllegalArgumentException ex) {
                    e.addErrorMessage("That is not a withdrawal this app can read.");
                }
                break;
            }
            case OPERATION_BROADCAST_TRANSACTION: {
                String rawTxHex = stringHeaderOrNull(e, HEADER_RAW_TX_HEX);
                if (rawTxHex == null) {
                    e.addErrorMessage("missing " + HEADER_RAW_TX_HEX);
                    break;
                }
                byte[] raw;
                try {
                    raw = decodeHex(rawTxHex.trim());
                } catch (IllegalArgumentException ex) {
                    e.addErrorMessage("invalid raw transaction hex: " + ex.getMessage());
                    break;
                }
                Transaction tx;
                try {
                    tx = new BitcoinSerializer(params).makeTransaction(ByteBuffer.wrap(raw));
                } catch (RuntimeException ex) {
                    // Transaction.read() throws bitcoinj's own ProtocolException for some
                    // malformed inputs and a raw java.nio.BufferUnderflowException for others
                    // (confirmed by actually triggering both, not assumed) - either way, the
                    // hex decoded fine but the bytes aren't a valid transaction structure.
                    e.addErrorMessage("could not parse raw transaction: " + ex.getMessage());
                    break;
                }
                try {
                    LOG.info("bitcoinj broadcast submitted txid=" + tx.getTxId()
                            + " connectedPeers=" + kit.peerGroup().getConnectedPeers().size());
                    long declaredFee = -1;
                    try {
                        String feeText = stringHeaderOrNull(e, HEADER_NETWORK_FEE_SATS);
                        if (feeText != null) declaredFee = Long.parseLong(feeText.trim());
                    } catch (NumberFormatException ignored) {
                        // the fee is only for the log
                    }
                    BroadcastTrace.begin(LOG, kit.peerGroup(), tx, declaredFee);
                    TransactionBroadcast broadcast = kit.peerGroup().broadcastTransaction(tx);
                    final String traceId = tx.getTxId().toString().substring(0, 12);
                    broadcast.setProgressCallback(progress ->
                            LOG.info("trace " + traceId + ": " + String.format("%.0f", progress * 100) + "% of the peers it was sent to have announced it back"));
                    broadcast.awaitSent().whenComplete((b, err) -> LOG.info("trace " + traceId + ": "
                            + (err == null ? "handed to its first peers" : "could not be handed to peers: " + err)));
                    try {
                        // Bounded wait for real propagation confirmation, not just "we tried" -
                        // A timeout retains the durable retry: a write alone is not acceptance.
                        broadcast.awaitRelayed().get(broadcastTimeoutMs, TimeUnit.MILLISECONDS);
                        LOG.info("bitcoinj broadcast relay acknowledged txid=" + tx.getTxId());
                    } catch (TimeoutException ignored) {
                        LOG.info("broadcast of " + tx.getTxId() + " sent, not yet confirmed relayed after "
                                + broadcastTimeoutMs + "ms - propagation continues in the background");
                        e.addErrorMessage("broadcast relay acknowledgement pending; retain transaction for retry");
                    }
                    e.setHeader(HEADER_TXID, tx.getTxId().toString());
                } catch (ExecutionException ex) {
                    String reason = ex.getCause() != null ? ex.getCause().getMessage() : ex.getMessage();
                    LOG.log(java.util.logging.Level.WARNING, "bitcoinj broadcast rejected txid="
                            + tx.getTxId() + " reason=" + reason, ex);
                    e.addErrorMessage("broadcast rejected: " + reason);
                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                    LOG.log(java.util.logging.Level.WARNING, "bitcoinj broadcast interrupted txid="
                            + tx.getTxId(), ex);
                    e.addErrorMessage("broadcast interrupted");
                }
                break;
            }
        }
    }

    /** {@code null} if the header is absent - {@link Envelope#getHeader} returns {@code Object}, no plain string accessor. */
    private static String stringHeaderOrNull(Envelope e, String name) {
        Object v = e.getHeader(name);
        return v != null ? String.valueOf(v) : null;
    }

    /**
     * See {@link BitcoinClient#HEADER_FEE_ADDRESS}: when both fee headers are present, adds a
     * second output to {@code req}'s transaction paying the dev fee, in the same transaction as
     * the primary send - {@code req} is returned unchanged (both headers absent) otherwise.
     *
     * <p>Deliberately re-wraps {@link AddressFormatException}/{@link NumberFormatException} as a
     * plain {@link IllegalArgumentException} rather than letting either propagate as-is: {@code
     * OPERATION_SEND}/{@code OPERATION_SEND_OFFLINE}'s own catch blocks for those two exact
     * exception types report the *primary* address/amount by name, which would misattribute a bad
     * fee header to the primary send instead.
     */
    private SendRequest addFeeOutput(Envelope e, SendRequest req) {
        String feeAddressStr = stringHeaderOrNull(e, HEADER_FEE_ADDRESS);
        String feeAmountStr = stringHeaderOrNull(e, HEADER_FEE_AMOUNT_SATS);
        if (feeAddressStr == null || feeAmountStr == null) return req;
        try {
            Address feeAddress = Address.fromString(params, feeAddressStr);
            long feeSats = Long.parseLong(feeAmountStr);
            req.tx.addOutput(Coin.valueOf(feeSats), feeAddress);
            return req;
        } catch (AddressFormatException ex) {
            throw new IllegalArgumentException("invalid fee address: " + feeAddressStr, ex);
        } catch (NumberFormatException ex) {
            throw new IllegalArgumentException("invalid fee amount: " + feeAmountStr, ex);
        }
    }

    /**
     * See {@link BitcoinClient#HEADER_FEE_RATE_SAT_PER_VBYTE}: when present, overrides bitcoinj's
     * default fee-per-kb policy for this one request - {@code req} is returned unchanged otherwise.
     * Same "re-wrap as IllegalArgumentException" reasoning as {@link #addFeeOutput}: a malformed
     * rate must not be misattributed to the primary amount by the caller's {@code
     * NumberFormatException} catch block.
     */
    private SendRequest applyFeeRate(Envelope e, SendRequest req) {
        String rateStr = stringHeaderOrNull(e, HEADER_FEE_RATE_SAT_PER_VBYTE);
        if (rateStr == null) return req;
        try {
            long satPerVByte = Long.parseLong(rateStr);
            req.setFeePerVkb(Coin.valueOf(satPerVByte * 1000L));
            return req;
        } catch (NumberFormatException ex) {
            throw new IllegalArgumentException("invalid fee rate: " + rateStr, ex);
        }
    }

    /**
     * Makes a send spend only coins the wallet counts as spendable: a payment received from someone else must have the
     * confirmations {@link BitcoinClient#requiredConfirmations} asks for its size, and change from this wallet's own
     * sends is left to bitcoinj's usual rule. Without this, bitcoinj spends any coin with a single confirmation, so
     * the wallet could send funds its own balance still shows as locked. Applies to a "send everything" selector too.
     */
    private SendRequest applyConfirmationPolicy(SendRequest req) {
        CoinSelector base = req.coinSelector != null ? req.coinSelector : DefaultCoinSelector.get(network);
        Wallet wallet = kit.wallet();
        req.coinSelector = (target, candidates) -> {
            java.util.List<TransactionOutput> allowed = new ArrayList<>();
            for (TransactionOutput o : candidates) {
                if (meetsConfirmationPolicy(wallet, o)) allowed.add(o);
            }
            return base.select(target, allowed);
        };
        return req;
    }

    static boolean meetsConfirmationPolicy(Wallet wallet, TransactionOutput o) {
        Transaction parent = o.getParentTransaction();
        try {
            if (parent != null && parent.getValueSentFromMe(wallet).signum() > 0) return true; // our own change
        } catch (ScriptException ex) {
            return false;
        }
        return o.getParentTransactionDepthInBlocks() >= BitcoinClient.requiredConfirmations(o.getValue().value);
    }

    /**
     * See {@link BitcoinClient#HEADER_USE_ALL_INPUTS}: when {@code "true"}, replaces bitcoinj's
     * default "select just enough" coin selection with one that unconditionally spends every
     * candidate it's given - {@code req} is returned unchanged otherwise. Bitcoinj's own change
     * logic still applies on top of this: if the requested outputs (plus the now-larger fee this
     * forces) leave a sub-dust remainder, it's folded into the fee rather than becoming a change
     * output - which is what makes a true zero-remainder max send possible with an extra (dev-fee)
     * output, unlike {@code SendRequest.emptyWallet} (see {@link #addFeeOutput}'s javadoc).
     */
    private SendRequest useAllInputsIfRequested(Envelope e, SendRequest req) {
        if (!"true".equals(stringHeaderOrNull(e, HEADER_USE_ALL_INPUTS))) return req;
        req.coinSelector = (target, candidates) -> new CoinSelection(candidates);
        return req;
    }

    /**
     * Sending party (of BTC) creates an Escrow with a selected Receiving party
     * by sending BTC to an Escrow address controlled by both the Sending and
     * Receiving party.
     *
     * Once the Sending party is satisfied conditions have been met, they release
     * the Bitcoin to be sent to the Receiving party.
     *
     * If the Sending party is not satisfied conditions have been met and they
     * wish for a refund, they ask the Receiving party to release the funds back
     * to the Sending party.
     *
     * For this service, the peer with the Bitcoin always initiates the escrow as the Sending party.
     * A fee for the service is paid up-front first using the Lightning Network to keep chain fees down.
     */

    /**
     * Step 1 - Obtain Receiving Party's Public Key
     */

    /**
     * Step 2 - Request Fee Address from Dev Group Peer
     */

    /**
     * Step 3 - Send Fee to Dev Group Peer
     */

    /**
     * Step 4 - Receive Signature from Dev Group Peer
     */

    /**
     * Step 5 - Initiate Escrow Transaction
     * @param sendingParty
     * @param receivingParty
     * @param satsToSend
     * @param estimatedNetworkFeeSats
     * @param devGroupFeeSats
     * @return
     */
    private BTCEscrow initiateEscrow(ECKey sendingParty, ECKey receivingParty, Long satsToSend, Long estimatedNetworkFeeSats, Long devGroupFeeSats) {
        BTCEscrow escrow = new BTCEscrow();
        escrow.id = UUID.randomUUID();
        escrow.sendingParty = sendingParty;
        escrow.receivingParty = receivingParty;
        escrow.satsToSend = satsToSend;
        escrow.estimatedNetworkFeeSats = estimatedNetworkFeeSats;
        escrow.devGroupFeeSats = devGroupFeeSats;
        escrow.tx = new Transaction(params);
        Script script = ScriptBuilder.createMultiSigOutputScript(2, Arrays.asList(escrow.sendingParty, escrow.receivingParty));
        Coin amount = Coin.valueOf(escrow.satsToSend);
        escrow.tx.addOutput(amount, script);
        escrows.put(escrow.id, escrow);
        kit.peerGroup().broadcastTransaction(escrow.tx);
        return escrow;
    }

    /**
     * Step 6A - Complete Escrow
     */
    private void completeEscrow(BTCEscrow escrow) {
        TransactionOutput multisigOutput = escrow.tx.getOutput(0);
        escrow.tx = new Transaction(params);
        escrow.tx.addOutput(multisigOutput.getValue(), escrow.sendingParty);

        kit.peerGroup().broadcastTransaction(escrow.tx);
    }

    /**
     * Step 6B - Refund Escrow
     */
    private void refundEscrow(BTCEscrow escrow) {
        TransactionOutput multisigOutput = escrow.tx.getOutput(0);
        Script multisigScript = multisigOutput.getScriptPubKey();
        Coin value = multisigOutput.getValue();
        escrow.tx = new Transaction(params);
        escrow.tx.addOutput(value, escrow.sendingParty);
        escrow.tx.addInput(multisigOutput);
        Sha256Hash sigHash = escrow.tx.hashForSignature(0, multisigScript, Transaction.SigHash.ALL, false);
        escrow.receivingPartySig = escrow.receivingParty.sign(sigHash);

        kit.peerGroup().broadcastTransaction(escrow.tx);
    }

    // -- vault scan --------------------------------------------------------

    /** How many Bitcoin peers each vault scan keeps (the main wallet keeps bitcoinj's default). */
    static final int MAX_VAULT_PEERS = 5;

    /** How many vaults can be scanned at once; each has its own chain, peers and bitcoinj Context. */
    static final int MAX_VAULTS = 8;

    /** One vault being scanned: its wallet and chain, and the Context they run in. */
    private static final class VaultScan {
        final WalletAppKit kit;
        final String fingerprint;
        final int slot;

        VaultScan(WalletAppKit kit, String fingerprint, int slot) {
            this.kit = kit;
            this.fingerprint = fingerprint;
            this.slot = slot;
        }
    }

    private final Map<String, VaultScan> vaults = new HashMap<>();
    private Context mainContext;
    private final Context[] vaultContexts = new Context[MAX_VAULTS];

    /** The caller's name for a vault; empty when it has only one (the original single-vault callers). */
    private static String vaultId(Envelope e) {
        String id = stringHeaderOrNull(e, HEADER_VAULT_ID);
        return id == null ? "" : id.trim();
    }

    private static boolean validVaultId(String id) {
        return id.isEmpty() || id.matches("[A-Za-z0-9_-]{1,32}");
    }

    /** The Context of the vault's scan if it has one, otherwise of the first slot no scan is using. */
    private synchronized Context vaultContextFor(String id) {
        VaultScan scan = vaults.get(id);
        return vaultContexts[scan != null ? scan.slot : freeVaultSlot()];
    }

    private int freeVaultSlot() {
        for (int i = 0; i < vaultContexts.length; i++) {
            boolean used = false;
            for (VaultScan v : vaults.values()) if (v.slot == i) used = true;
            if (!used) return i;
        }
        return -1;
    }

    private File vaultDirectory(String id) {
        return new File(kitDirectory(), id.isEmpty() ? "vault" : "vault-" + id);
    }

    private File kitDirectory() {
        return service.getServiceDirectory();
    }

    /**
     * A watch-only vault wallet, kept apart from the main wallet and its chain (and from any other vault's): replaying
     * history from the vault's start date means a chain of its own, and the main wallet must not be reset to do it.
     * Started from the nearest bundled checkpoint before the date, so only headers from there on are fetched.
     */
    private synchronized void startVaultScan(Envelope e) {
        String id = vaultId(e);
        String key = stringHeaderOrNull(e, HEADER_VAULT_KEY);
        String typeStr = stringHeaderOrNull(e, HEADER_VAULT_TYPE);
        String sinceStr = stringHeaderOrNull(e, HEADER_VAULT_SINCE);
        if (!validVaultId(id)) {
            e.addErrorMessage("invalid vault id");
            return;
        }
        if (key == null || sinceStr == null) {
            e.addErrorMessage("vault scan needs " + HEADER_VAULT_KEY + " and " + HEADER_VAULT_SINCE);
            return;
        }
        ScriptType type;
        if ("P2WPKH".equals(typeStr)) type = ScriptType.P2WPKH;
        else if ("P2PKH".equals(typeStr)) type = ScriptType.P2PKH;
        else {
            e.addErrorMessage("the vault balance can only be tracked for xpub (legacy) and zpub (native segwit) keys");
            return;
        }
        long sinceSeconds;
        try {
            sinceSeconds = Long.parseLong(sinceStr.trim());
        } catch (NumberFormatException ex) {
            e.addErrorMessage("invalid vault start date");
            return;
        }
        String fingerprint = key.trim() + "|" + type + "|" + sinceSeconds;
        VaultScan running = vaults.get(id);
        if (running != null && fingerprint.equals(running.fingerprint)
                && running.kit.state() != com.google.common.util.concurrent.Service.State.FAILED
                && running.kit.state() != com.google.common.util.concurrent.Service.State.TERMINATED) {
            return; // already scanning this vault
        }
        File dir = vaultDirectory(id);
        File marker = new File(dir, "vault.fingerprint");
        boolean sameAsOnDisk = false;
        try {
            sameAsOnDisk = marker.exists()
                    && fingerprint.equals(new String(java.nio.file.Files.readAllBytes(marker.toPath()), StandardCharsets.UTF_8));
        } catch (IOException ignored) {
            // treated as a different vault below: scan afresh
        }
        stopVaultKit(id);
        int slot = freeVaultSlot();
        if (slot < 0) {
            e.addErrorMessage("too many vaults are being scanned (at most " + MAX_VAULTS + ")");
            return;
        }
        if (!sameAsOnDisk) deleteRecursively(dir);

        try {
            DeterministicKey account = DeterministicKey.deserializeB58(key.trim(), network);
            account.setCreationTime(java.time.Instant.ofEpochSecond(sinceSeconds));
            WalletAppKit k = newKit(network, dir, "vault", type, initConfig, account, vaultContexts[slot], KeyChainGroupStructure.BIP32);
            if (network != BitcoinNetwork.REGTEST) {
                k.setCheckpoints(org.bitcoinj.core.CheckpointManager.openStream(params));
            }
            k.startAsync();
            vaults.put(id, new VaultScan(k, fingerprint, slot));
            if (!dir.exists() && !dir.mkdirs()) LOG.warning("could not create " + dir);
            java.nio.file.Files.write(marker.toPath(), fingerprint.getBytes(StandardCharsets.UTF_8));
            LOG.info("vault scan " + (id.isEmpty() ? "" : id + " ") + "started from " + java.time.Instant.ofEpochSecond(sinceSeconds));
        } catch (RuntimeException | IOException ex) {
            LOG.log(java.util.logging.Level.WARNING, "vault scan failed to start", ex);
            stopVaultKit(id);
            e.addErrorMessage("could not start the vault scan: " + ex.getMessage());
        }
    }

    private synchronized void vaultScanStatus(Envelope e) {
        VaultScan scan = vaults.get(vaultId(e));
        WalletAppKit k = scan == null ? null : scan.kit;
        if (k == null || !k.isRunning()) {
            e.setHeader(HEADER_VAULT_SCAN_STATE, k == null ? "NONE" : "SYNCING");
            return;
        }
        Wallet w = k.wallet();
        boolean syncing = true;
        if (k.peerGroup() != null && k.chain() != null && !k.peerGroup().getConnectedPeers().isEmpty()) {
            syncing = k.peerGroup().getMostCommonChainHeight() > k.chain().getBestChainHeight();
        }
        e.setHeader(HEADER_VAULT_SCAN_STATE, syncing ? "SYNCING" : "SYNCED");
        e.setHeader(HEADER_BALANCE_SATS, String.valueOf(confirmedVaultSats(w)));
        e.setHeader(HEADER_BEST_HEIGHT, String.valueOf(k.chain() != null ? k.chain().getBestChainHeight() : -1));
        StringBuilder sb = new StringBuilder();
        try {
            for (Transaction tx : w.getTransactions(false)) {
                sb.append(tx.getTxId()).append('|').append(tx.getValue(w).value).append('|')
                        .append(tx.getConfidence().getDepthInBlocks()).append('|')
                        .append(tx.getUpdateTime().getTime()).append('\n');
            }
        } catch (ScriptException ex) {
            e.addErrorMessage("could not list vault transactions: " + ex.getMessage());
            return;
        }
        e.addContent(sb.toString().getBytes(StandardCharsets.UTF_8));
    }

    /**
     * The vault's balance counting only outputs with the confirmations {@link BitcoinClient#requiredConfirmations}
     * asks for their size, the rule the main wallet's balance uses. Unconfirmed money is left out so the app can show
     * it separately as pending, instead of counting it in the balance as well.
     */
    static long confirmedVaultSats(Wallet w) {
        long sum = 0;
        for (TransactionOutput o : w.calculateAllSpendCandidates(true, false)) {
            if (o.getParentTransactionDepthInBlocks() >= BitcoinClient.requiredConfirmations(o.getValue().value)) {
                sum += o.getValue().value;
            }
        }
        return sum;
    }

    /** See {@link BitcoinClient#OPERATION_VAULT_WITHDRAWAL_FINISH}. Needs no wallet or network. */
    private void vaultWithdrawalFinish(Envelope e) {
        String signedText = stringHeaderOrNull(e, HEADER_VAULT_PSBT);
        String requestText = stringHeaderOrNull(e, HEADER_VAULT_REQUEST);
        if (signedText == null || requestText == null) {
            e.addErrorMessage("finishing a withdrawal needs " + HEADER_VAULT_PSBT + " and " + HEADER_VAULT_REQUEST);
            return;
        }
        try {
            ra.btc.psbt.VaultWithdrawal.Finished done = ra.btc.psbt.VaultWithdrawal.finishAny(
                    signedText, ra.btc.psbt.Psbt.parseText(requestText));
            e.setHeader(HEADER_RAW_TX_HEX, done.rawTxHex());
            e.setHeader(HEADER_NETWORK_FEE_SATS, String.valueOf(done.feeSats()));
        } catch (IllegalArgumentException ex) {
            e.addErrorMessage(ex.getMessage() != null && ex.getMessage().length() > 0 ? ex.getMessage()
                    : "That is not a withdrawal this app can read.");
        }
    }

    /** See {@link BitcoinClient#OPERATION_VAULT_WITHDRAWAL_REQUEST}. */
    private synchronized void vaultWithdrawalRequest(Envelope e) {
        VaultScan scan = vaults.get(vaultId(e));
        WalletAppKit k = scan == null ? null : scan.kit;
        if (k == null || !k.isRunning()) {
            e.addErrorMessage("the vault is not being scanned yet");
            return;
        }
        boolean scannedBefore = "true".equals(stringHeaderOrNull(e, HEADER_VAULT_SCAN_COMPLETED_BEFORE));
        if (!scannedBefore && (k.peerGroup() == null || k.chain() == null || k.peerGroup().getConnectedPeers().isEmpty()
                || k.peerGroup().getMostCommonChainHeight() > k.chain().getBestChainHeight())) {
            e.addErrorMessage("the vault is still doing its first scan; its coins are not all known yet");
            return;
        }
        String destinationStr = stringHeaderOrNull(e, HEADER_ADDRESS);
        String fingerprintStr = stringHeaderOrNull(e, HEADER_VAULT_FINGERPRINT);
        String pathStr = stringHeaderOrNull(e, HEADER_VAULT_PATH);
        String rateStr = stringHeaderOrNull(e, HEADER_FEE_RATE_SAT_PER_VBYTE);
        if (destinationStr == null || fingerprintStr == null || pathStr == null || rateStr == null) {
            e.addErrorMessage("a withdrawal needs " + HEADER_ADDRESS + ", " + HEADER_VAULT_FINGERPRINT + ", "
                    + HEADER_VAULT_PATH + " and " + HEADER_FEE_RATE_SAT_PER_VBYTE);
            return;
        }
        boolean all = "true".equals(stringHeaderOrNull(e, HEADER_VAULT_SEND_ALL));
        try {
            Address destination;
            try {
                destination = Address.fromString(params, destinationStr.trim());
            } catch (AddressFormatException ex) {
                e.addErrorMessage("That is not a valid Bitcoin address for this network.");
                return;
            }
            long amount = all ? -1 : Long.parseLong(stringHeaderOrNull(e, HEADER_AMOUNT_SATS));
            long rate = Long.parseLong(rateStr.trim());
            byte[] fingerprint = decodeHex(fingerprintStr.trim());
            if (fingerprint.length != 4) throw new IllegalArgumentException("the fingerprint is 8 hex characters");
            int[] origin = parsePath(pathStr);

            Wallet w = k.wallet();
            List<TransactionOutput> coins = new ArrayList<>();
            for (TransactionOutput o : w.calculateAllSpendCandidates(true, false)) {
                if (o.getParentTransactionDepthInBlocks() >= BitcoinClient.requiredConfirmations(o.getValue().value)) coins.add(o);
            }
            Address change = w.currentChangeAddress();
            ra.btc.psbt.VaultWithdrawal.KeyLookup keys = script -> {
                org.bitcoinj.crypto.ECKey key = w.findKeyFromAddress(script.getToAddress(params));
                if (!(key instanceof DeterministicKey)) return null;
                org.bitcoinj.crypto.HDPath path = ((DeterministicKey) key).getPath();
                int n = path.size();
                return new ra.btc.psbt.VaultWithdrawal.KeyInfo(key.getPubKey(),
                        new int[]{path.get(n - 2).i(), path.get(n - 1).i()});
            };
            ra.btc.psbt.VaultWithdrawal.Result r = ra.btc.psbt.VaultWithdrawal.build(coins, keys, destination, amount, rate,
                    change, fingerprint, origin);
            e.setHeader(HEADER_VAULT_PSBT, r.psbt().toBase64());
            e.setHeader(HEADER_AMOUNT_SATS, String.valueOf(r.amountSats()));
            e.setHeader(HEADER_NETWORK_FEE_SATS, String.valueOf(r.feeSats()));
            e.setHeader(HEADER_VAULT_CHANGE_SATS, String.valueOf(r.changeSats()));
        } catch (ra.btc.psbt.VaultWithdrawal.InsufficientFundsException ex) {
            e.setHeader(HEADER_MISSING_SATS, String.valueOf(ex.missingSats));
            e.addErrorMessage(ex.getMessage());
        } catch (IllegalArgumentException | IllegalStateException | NullPointerException ex) {
            e.addErrorMessage("could not build the withdrawal: " + ex.getMessage());
        }
    }


    /** {@code 84'/0'/0'} (or with {@code h}) as child numbers with the hardened bit set. */
    static int[] parsePath(String path) {
        String t = path.trim();
        if (t.isEmpty()) return new int[0];
        String[] parts = t.split("/");
        int[] out = new int[parts.length];
        for (int i = 0; i < parts.length; i++) {
            String p = parts[i];
            boolean hardened = p.endsWith("'") || p.endsWith("h") || p.endsWith("H");
            int n = Integer.parseInt(hardened ? p.substring(0, p.length() - 1) : p);
            out[i] = hardened ? (n | 0x80000000) : n;
        }
        return out;
    }

    private synchronized void clearVaultScan(String id) {
        stopVaultKit(id);
        deleteRecursively(vaultDirectory(id));
    }

    private void stopVaultKit(String id) {
        VaultScan scan = vaults.remove(id);
        if (scan == null) return;
        try {
            scan.kit.stopAsync();
            scan.kit.awaitTerminated(30, TimeUnit.SECONDS);
        } catch (RuntimeException | TimeoutException ex) {
            LOG.log(java.util.logging.Level.WARNING, "vault scan did not stop cleanly", ex);
        }
    }

    private static void deleteRecursively(File f) {
        File[] children = f.listFiles();
        if (children != null) for (File c : children) deleteRecursively(c);
        f.delete();
    }

    @Override
    public boolean destroy() throws Exception {
        // WalletAppKit auto-saves the wallet (default) and persists the SPV chain file itself;
        // stopAsync()/awaitTerminated() flushes both to disk.
        synchronized (this) {
            for (String id : new ArrayList<>(vaults.keySet())) stopVaultKit(id);
        }
        if (kit != null) {
            kit.stopAsync();
            kit.awaitTerminated();
        }
        return true;
    }

    @Override
    public boolean destroyGracefully() throws Exception {
        return destroy();
    }
}
