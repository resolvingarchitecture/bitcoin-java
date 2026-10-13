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

    private NetworkParameters params;
    private WalletAppKit kit;
    /** The peer limit the group started with, captured the first time {@link #OPERATION_SET_MAX_PEERS} lowers it. */
    private int startupMaxPeers = -1;
    private long broadcastTimeoutMs = 15_000;
    private volatile Proxy externalProxy;
    private volatile BitcoinClient.ProxiedHostResolver externalSeedResolver;

    private final Map<UUID, BTCEscrow> escrows = new HashMap<>();

    public BitcoinJClient(BitcoinService service) {
        this.service = service;
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
        Context.propagate(new Context(params));

        final Proxy proxy = externalProxy;
        final String socksHost = config.getProperty("ra.btc.socks.host");
        final int socksPort = parseIntOrDefault(config.getProperty("ra.btc.socks.port"), 0);
        final boolean useSocks = proxy != null || (socksHost != null && !socksHost.isEmpty() && socksPort > 0);
        final boolean noDirectPeers = "true".equalsIgnoreCase(config.getProperty("ra.btc.noDirectPeers"));

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
        final int maxAttempts = 3;
        final long retryDelayMs = 250L;
        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            kit = new WalletAppKit(network, ScriptType.P2WPKH, KeyChainGroupStructure.BIP32, directory, "bitcoinj") {
                @Override
                protected void onSetupCompleted() {
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

                if (network == BitcoinNetwork.REGTEST) {
                    kit.connectToLocalHost();
                } else if (noDirectPeers) {
                    // Explicitly empty, not merely absent: falling through to BitcoinJ's own DNS-seed
                    // discovery here would leak a direct clearnet connection attempt, defeating the
                    // whole reason this flag was set (no acceptable network path right now). The wallet
                    // itself still starts - balance/receive-address/offline signing all work from cached
                    // state - only the PeerGroup makes zero connection attempts.
                    LOG.info("ra.btc.noDirectPeers=true - wallet starting with zero peer discovery.");
                    kit.setDiscovery(new StaticBitcoinPeerDiscovery(java.util.Collections.emptyList()));
                } else {
                    List<InetSocketAddress> explicitPeers = parsePeers(config.getProperty("ra.btc.peers"));
                    if (!explicitPeers.isEmpty()) {
                        LOG.info("Using explicit Bitcoin peers: " + explicitPeers);
                        kit.setDiscovery(new StaticBitcoinPeerDiscovery(explicitPeers));
                    } else if (externalSeedResolver != null) {
                        LOG.info("No explicit Bitcoin peers configured (ra.btc.peers) - resolving BitcoinJ's "
                                + "own DNS seeds through the supplied proxied resolver instead of local DNS.");
                        kit.setDiscovery(new ProxiedDnsSeedDiscovery(params.getDnsSeeds(), params.getPort(), externalSeedResolver));
                    } else {
                        LOG.info("No explicit Bitcoin peers configured (ra.btc.peers) - using BitcoinJ's "
                                + "own default peer discovery, same fallback 1m5-android's WalletService uses.");
                        // Deliberately not calling kit.setDiscovery(...) here - leaving WalletAppKit's
                        // own PeerGroup default discovery (bitcoinj's built-in DNS-seed
                        // MultiplexingDiscovery) in place. Only reached with no seed resolver supplied -
                        // a real leak (see ProxiedDnsSeedDiscovery's javadoc) but the same behavior this
                        // class has always had for a caller with no proxied-DNS notion.
                    }
                }
                kit.setBlockingStartup(false);

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
        switch(operation) {
            case OPERATION_GET_BALANCE: {
                Coin available = kit.wallet().getBalance(Wallet.BalanceType.AVAILABLE);
                Coin estimated = kit.wallet().getBalance(Wallet.BalanceType.ESTIMATED);
                e.setHeader(HEADER_AVAILABLE_SATS, String.valueOf(available.value));
                e.setHeader(HEADER_BALANCE_SATS, String.valueOf(estimated.value));
                break;
            }
            case OPERATION_GET_RECEIVE_ADDRESS: {
                e.setHeader(HEADER_ADDRESS, kit.wallet().currentReceiveAddress().toString());
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
                    SendRequest req = useAllInputsIfRequested(e, applyFeeRate(e, addFeeOutput(e, SendRequest.to(address, Coin.valueOf(sats)))));
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
                    SendRequest req = useAllInputsIfRequested(e, applyFeeRate(e, addFeeOutput(e, SendRequest.to(address, Coin.valueOf(sats)))));
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
                    SendRequest req = useAllInputsIfRequested(e, applyFeeRate(e, addFeeOutput(e, SendRequest.to(address, Coin.valueOf(sats)))));
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
                    TransactionBroadcast broadcast = kit.peerGroup().broadcastTransaction(tx);
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

    @Override
    public boolean destroy() throws Exception {
        // WalletAppKit auto-saves the wallet (default) and persists the SPV chain file itself;
        // stopAsync()/awaitTerminated() flushes both to disk.
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
