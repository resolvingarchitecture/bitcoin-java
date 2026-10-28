package ra.btc;

import ra.common.Envelope;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Proxy;
import java.time.Duration;
import java.util.Properties;

public interface BitcoinClient {

    /**
     * Route P2P connections through a live SOCKS proxy this node's own network
     * layer already manages (e.g. {@code tor-client-java}'s {@code
     * TorSocksRelay}) instead of building one from {@code ra.btc.socks.host}/
     * {@code ra.btc.socks.port} config strings. Call before {@link #init}.
     * Default no-op - a client with no SOCKS notion (e.g. {@code
     * LocalBitcoinClient}, talking to a local full node over RPC) ignores it.
     */
    default void setProxy(Proxy proxy) {}

    /**
     * Resolves a hostname the same proxied way {@link #setProxy}'s SOCKS proxy already routes
     * connections - never the local/system DNS resolver. {@code tor-client-java}'s {@code
     * TorSocksRelay#resolve} is the real implementation this is built for (Tor's own SOCKS5
     * {@code RESOLVE} extension).
     */
    @FunctionalInterface
    interface ProxiedHostResolver {
        InetAddress resolve(String hostname, Duration timeout) throws IOException;
    }

    /**
     * Used for bitcoin peer discovery (bitcoinj's default DNS-seed {@code MultiplexingDiscovery})
     * when no explicit {@code ra.btc.peers} is configured: without this, that discovery calls
     * {@link InetAddress#getAllByName} directly, which ignores any proxy set via {@link
     * #setProxy} entirely and always leaks a plain local DNS query - {@code java.net.Proxy} only
     * affects {@code Socket}/{@code URLConnection} connect calls, never {@code InetAddress}
     * resolution. Call before {@link #init}. Default no-op - a client with no proxied-DNS notion
     * ignores it, same as an unset {@link #setProxy}.
     */
    default void setSeedResolver(ProxiedHostResolver resolver) {}

    /**
     * Start from the wallet these BIP-39 {@code words} make instead of the one on disk: the existing wallet and
     * chain files are deleted first, and the wallet is rebuilt from the words, scanning from
     * {@code creationEpochSeconds} (0 = unknown, scan from the start). Call before {@link #init}. Default no-op.
     */
    default void setRestorePhrase(java.util.List<String> words, long creationEpochSeconds) {}

    /**
     * The wallet's own BIP-39 words, space-separated in {@link #HEADER_WORDS}. Sensitive: only for a back-up
     * screen the user has unlocked, never logged or stored.
     */
    String OPERATION_GET_WALLET_WORDS = "GET_WALLET_WORDS";
    String HEADER_WORDS = "btc.words";

    // ** Wallet query/send - the operations a host actually needs for a real wallet UI, as
    // opposed to the lower/upper-level use cases below, none of which are implemented yet. **
    String OPERATION_GET_BALANCE = "GET_BALANCE";
    String OPERATION_GET_RECEIVE_ADDRESS = "GET_RECEIVE_ADDRESS";
    String OPERATION_LIST_TRANSACTIONS = "LIST_TRANSACTIONS";
    /** Lists unconfirmed outgoing wallet transactions with their raw signed bytes for restart-safe rebroadcast. */
    String OPERATION_LIST_PENDING_BROADCASTS = "LIST_PENDING_BROADCASTS";
    String OPERATION_SEND = "SEND";
    String OPERATION_SYNC_STATUS = "SYNC_STATUS";
    /**
     * Caps how many peers the wallet keeps connected, at runtime: {@link #HEADER_MAX_PEERS} is a positive
     * number, or {@code "default"} to restore the limit the client started with. Peers above a lowered cap
     * are dropped. Lets a host ease the load on a shared transport (Tor) while something else needs it.
     */
    String OPERATION_SET_MAX_PEERS = "SET_MAX_PEERS";

    /**
     * Same inputs as {@link #OPERATION_SEND} (spends this client's own wallet
     * funds, per {@code HEADER_ADDRESS}/{@code HEADER_AMOUNT_SATS}) but signs
     * and commits the spend locally ({@code Wallet.sendCoinsOffline}, bitcoinj's
     * own offline-signing method) without ever touching a {@code PeerGroup} -
     * no network involvement at all. Response carries the same
     * {@link #HEADER_TXID} as {@link #OPERATION_SEND} plus
     * {@link #HEADER_RAW_TX_HEX} (the signed raw transaction), so the caller can
     * broadcast it however it needs to - locally when connected, or handed to a
     * peer for {@link #OPERATION_BROADCAST_TRANSACTION} when this node has no
     * direct/Tor path of its own. Committing the spend here (not only once a
     * broadcast succeeds) matches {@code sendCoinsOffline}'s own contract and
     * prevents a retry from double-spending the same coins.
     */
    String OPERATION_SEND_OFFLINE = "SEND_OFFLINE";

    /**
     * A true dry run of {@link #OPERATION_SEND}/{@link #OPERATION_SEND_OFFLINE}: builds, selects
     * coins for, and computes the fee of the same transaction {@code sendCoins}/{@code
     * sendCoinsOffline} would ({@code Wallet.completeTx(SendRequest)}), but never commits or
     * broadcasts it - repeatable with zero side effects (no coins get marked spent), unlike either
     * of those, which is the whole point: a UI can call this on every keystroke while an amount is
     * being typed. Same request headers as {@link #OPERATION_SEND} ({@link #HEADER_ADDRESS}/
     * {@link #HEADER_AMOUNT_SATS}, optionally {@link #HEADER_FEE_ADDRESS}/
     * {@link #HEADER_FEE_AMOUNT_SATS}). Response: {@link #HEADER_NETWORK_FEE_SATS} on success, or
     * the same {@code x.error.message}/{@link #HEADER_MISSING_SATS} shape as a real send on
     * failure (most commonly insufficient balance) - so a caller can shrink the amount by exactly
     * {@link #HEADER_MISSING_SATS} and retry, the basis for computing a "max sendable" amount
     * without bitcoinj's own {@code SendRequest.emptyWallet} (which silently drops any additional
     * output - incompatible with also wanting a dev-fee output, see {@code BitcoinJClient}).
     */
    String OPERATION_ESTIMATE_SEND = "ESTIMATE_SEND";

    /**
     * Broadcast an already-finalized, already-signed raw transaction (a plain node/relay
     * operation - no wallet involved on this end at all, unlike {@link #OPERATION_SEND} which
     * spends this client's own wallet funds). bitcoinj 0.17.1 has no BIP-174 PSBT support
     * (confirmed against its actual source - no PSBT-related class exists anywhere in it), so
     * a caller holding a PSBT must finalize and extract the raw transaction itself before
     * submitting it here, same as {@code bitcoind}'s own {@code sendrawtransaction} RPC expects.
     */
    String OPERATION_BROADCAST_TRANSACTION = "BROADCAST_TRANSACTION";

    // Request/response header names for the operations above.
    /**
     * {@link #HEADER_COUNT} (1..20) distinct addresses this wallet has never handed out before, newest index
     * last, returned newline-separated in {@link #HEADER_ADDRESSES}. Unlike {@link #OPERATION_GET_RECEIVE_ADDRESS},
     * which keeps returning the same current address until it is used, every call advances the wallet.
     */
    String OPERATION_GET_FRESH_RECEIVE_ADDRESSES = "GET_FRESH_RECEIVE_ADDRESSES";
    String HEADER_COUNT = "btc.count";
    String HEADER_ADDRESSES = "btc.addresses";
    String HEADER_BALANCE_SATS = "btc.balanceSats";
    String HEADER_AVAILABLE_SATS = "btc.availableSats";
    String HEADER_ADDRESS = "btc.address";
    String HEADER_AMOUNT_SATS = "btc.amountSats";
    String HEADER_TXID = "btc.txid";
    String HEADER_SYNCING = "btc.syncing";
    String HEADER_BEST_HEIGHT = "btc.bestHeight";
    String HEADER_CONNECTED_PEERS = "btc.connectedPeers";
    /** Request/response header for {@link #OPERATION_SET_MAX_PEERS}. */
    String HEADER_MAX_PEERS = "btc.maxPeers";
    /** Request header for {@link #OPERATION_BROADCAST_TRANSACTION}: hex-encoded raw signed transaction bytes. */
    String HEADER_RAW_TX_HEX = "btc.rawTxHex";
    /**
     * Optional on {@link #OPERATION_SEND}/{@link #OPERATION_SEND_OFFLINE}: adds a second output,
     * paying this address, to the same transaction - the 1M5 dev fee, per 1m5-remnant-android's
     * DESIGN.md §"Sending Bitcoin to Contacts". Requires {@link #HEADER_FEE_AMOUNT_SATS} too;
     * either one alone is ignored (no fee output added).
     */
    String HEADER_FEE_ADDRESS = "btc.fee.address";
    /** Sats sent to {@link #HEADER_FEE_ADDRESS} in the same transaction - see its javadoc. */
    String HEADER_FEE_AMOUNT_SATS = "btc.fee.amountSats";
    /** {@link #OPERATION_ESTIMATE_SEND} response: the computed miner/network fee, in sats. */
    String HEADER_NETWORK_FEE_SATS = "btc.networkFeeSats";
    /**
     * Response header alongside an insufficient-balance {@code x.error.message}, on any of
     * {@link #OPERATION_SEND}/{@link #OPERATION_SEND_OFFLINE}/{@link #OPERATION_ESTIMATE_SEND}:
     * exactly how many more sats were needed - lets a caller retry with the amount reduced by
     * precisely this much, rather than guessing or string-parsing the error message.
     */
    String HEADER_MISSING_SATS = "btc.missingSats";
    /**
     * Optional on {@link #OPERATION_SEND}/{@link #OPERATION_SEND_OFFLINE}/{@link
     * #OPERATION_ESTIMATE_SEND}: a caller-chosen fee rate, in sats/vByte, overriding bitcoinj's own
     * default fee-per-kb policy for this one request - the basis for a low/medium/high priority
     * picker fed by a live mempool fee estimate. Absent: bitcoinj's default applies, unchanged.
     */
    String HEADER_FEE_RATE_SAT_PER_VBYTE = "btc.feeRateSatPerVByte";
    /**
     * Optional on {@link #OPERATION_SEND}/{@link #OPERATION_SEND_OFFLINE}/{@link
     * #OPERATION_ESTIMATE_SEND}: {@code "true"} forces every spendable UTXO to be used as an input,
     * regardless of whether the requested output amounts need them all - the basis for a true
     * "send everything, no remainder" max send with an additional (dev-fee) output, which
     * bitcoinj's own {@code SendRequest.emptyWallet} can't do (it silently drops any output beyond
     * the first). Combined with output amounts that exactly account for the fee (see {@code
     * BitcoinJClient}), this leaves nothing for bitcoinj to return as change.
     */
    String HEADER_USE_ALL_INPUTS = "btc.useAllInputs";

    /**
     * Starts (or keeps running) a second, watch-only wallet for a vault: its own SPV chain and peers, scanning
     * from {@link #HEADER_VAULT_SINCE} for payments to addresses derived from {@link #HEADER_VAULT_KEY}, a
     * standard BIP32 (xpub/tpub) account key. {@link #HEADER_VAULT_TYPE} is {@code P2PKH} or {@code P2WPKH}.
     * Idempotent for an unchanged key and date; a different key or date starts a fresh scan.
     */
    String OPERATION_VAULT_SCAN_START = "VAULT_SCAN_START";
    /**
     * Response: {@link #HEADER_VAULT_SCAN_STATE} ({@code NONE}, {@code SYNCING} or {@code SYNCED}),
     * {@link #HEADER_BALANCE_SATS}, {@link #HEADER_BEST_HEIGHT} and the vault wallet's transactions as content,
     * one {@code txid|valueSats|confirmations|updateTimeMillis} per line.
     */
    String OPERATION_VAULT_SCAN_STATUS = "VAULT_SCAN_STATUS";
    /** Stops the vault scan and deletes its chain and wallet files. */
    String OPERATION_VAULT_SCAN_CLEAR = "VAULT_SCAN_CLEAR";
    /**
     * Builds, from the coins the vault scan holds, a signing request (a PSBT, base64 in {@link #HEADER_VAULT_PSBT}) that
     * pays {@link #HEADER_ADDRESS} {@link #HEADER_AMOUNT_SATS} - or everything when {@link #HEADER_VAULT_SEND_ALL} is
     * {@code true} - at {@link #HEADER_FEE_RATE_SAT_PER_VBYTE}, with the change returning to the vault. The signer's
     * {@link #HEADER_VAULT_FINGERPRINT} and {@link #HEADER_VAULT_PATH} go into the request so it finds its keys. Replies
     * {@link #HEADER_AMOUNT_SATS}, {@link #HEADER_NETWORK_FEE_SATS} and {@link #HEADER_VAULT_CHANGE_SATS}; fails while the
     * scan is still catching up, or, short of funds, with {@link #HEADER_MISSING_SATS}. Nothing is signed or sent.
     */
    String OPERATION_VAULT_WITHDRAWAL_REQUEST = "VAULT_WITHDRAWAL_REQUEST";
    /**
     * Checks what a signing device returned ({@link #HEADER_VAULT_PSBT}: base64 or hex) against the request it was given
     * ({@link #HEADER_VAULT_REQUEST}): the same coins to the same outputs, signed, every signature valid. Replies the
     * ready-to-broadcast {@link #HEADER_RAW_TX_HEX} and {@link #HEADER_NETWORK_FEE_SATS}, or an error fit to show the
     * user. Sends nothing - broadcasting is {@link #OPERATION_BROADCAST_TRANSACTION}, after the user confirms.
     */
    String OPERATION_VAULT_WITHDRAWAL_FINISH = "VAULT_WITHDRAWAL_FINISH";
    String HEADER_VAULT_REQUEST = "btc.vault.request";
    /**
     * Asks every connected Bitcoin peer whether it has the transaction {@link #HEADER_TXID} in its mempool, and replies how
     * many were asked ({@link #HEADER_PEERS_ASKED}) and how many had it ({@link #HEADER_PEERS_HAVE}), waiting up to 20
     * seconds. No third party is involved: it is the wallet's own peers, over whatever route they use. A transaction a
     * peer has already mined out of its mempool counts as not found, so ask soon after sending.
     */
    String OPERATION_TX_PEER_CHECK = "TX_PEER_CHECK";
    String HEADER_PEERS_ASKED = "btc.peersAsked";
    String HEADER_PEERS_HAVE = "btc.peersHave";
    /**
     * A smaller copy of the request in {@link #HEADER_VAULT_REQUEST}, returned in {@link #HEADER_VAULT_PSBT}, for a slow
     * link such as an NFC tap: the previous-transaction copies of native segwit coins are dropped. See
     * {@code ra.btc.psbt.VaultWithdrawal#compact}.
     */
    String OPERATION_VAULT_WITHDRAWAL_COMPACT = "VAULT_WITHDRAWAL_COMPACT";
    String HEADER_VAULT_FINGERPRINT = "btc.vault.fingerprint";
    String HEADER_VAULT_PATH = "btc.vault.path";
    String HEADER_VAULT_SEND_ALL = "btc.vault.sendAll";
    /**
     * {@code true} on {@link #OPERATION_VAULT_WITHDRAWAL_REQUEST} when the caller knows a scan of this vault has finished
     * before: the coins the wallet holds are then used even while it reconnects and catches up after a restart. Without
     * it the request is refused until the scan is caught up, since a first scan's coin list may be incomplete.
     */
    String HEADER_VAULT_SCAN_COMPLETED_BEFORE = "btc.vault.scanCompletedBefore";
    String HEADER_VAULT_PSBT = "btc.vault.psbt";
    String HEADER_VAULT_CHANGE_SATS = "btc.vault.changeSats";
    String HEADER_VAULT_KEY = "btc.vault.key";
    String HEADER_VAULT_TYPE = "btc.vault.type";
    /** Epoch seconds the vault scan starts from. */
    String HEADER_VAULT_SINCE = "btc.vault.since";
    String HEADER_VAULT_SCAN_STATE = "btc.vault.scanState";

    /**
     * How many confirmations a received payment of {@code sats} needs before it counts as spendable: the more
     * it is, the more confirmations. This is the one definition - the wallet's coin selection applies it when
     * building a send, and the app shows balances by the same rule (mirrored in {@code BitcoinChannel}, with a test
     * that keeps the two equal).
     */
    static int requiredConfirmations(long sats) {
        long amount = sats == Long.MIN_VALUE ? Long.MAX_VALUE : Math.abs(sats);
        if (amount < 20_000L) return 1;
        if (amount < 1_000_000L) return 2;
        if (amount < 10_000_000L) return 3;
        return 4;
    }

    // Lower Level Use Case Requests
    String OPERATION_CREATE_2_N_MULTISIG = "CREATE_2_N_MULTISIG";
    String OPERATION_CLOSE_2_N_MULTISIG = "CLOSE_2_N_MULTISIG";

    // Upper Level Use Case Requests
    // ** Wallet **
    String OPERATION_CREATE_HD_WALLET = "CREATE_HD_WALLET";
    String OPERATION_LOCK_HD_WALLET = "LOCK_HD_WALLET";
    String OPERATION_UNLOCK_HD_WALLET = "UNLOCK_HD_WALLET";
    String OPERATION_DESTROY_HD_WALLET = "DESTROY_HD_WALLET";
    String OPERATION_CREATE_CLASSIC_WALLET = "CREATE_CLASSIC_WALLET";
    String OPERATION_LOCK_CLASSIC_WALLET = "LOCK_CLASSIC_WALLET";
    String OPERATION_UNLOCK_CLASSIC_WALLET = "UNLOCK_CLASSIC_WALLET";
    String OPERATION_DESTROY_CLASSIC_WALLET = "DESTROY_CLASSIC_WALLET";
    // ** Escrow **
    String OPERATION_CREATE_ESCROW = "CREATE_ESCROW";
    String OPERATION_CLOSE_ESCROW = "CLOSE_ESCROW";
    // ** Exchange BTC/Assets **
    String OPERATION_MAKE_BTC_BUY_OFFER = "MAKE_BTC_BUY_OFFER";
    String OPERATION_TAKE_BTC_BUY_OFFER = "TAKE_BTC_BUY_OFFER";
    String OPERATION_MAKE_BTC_SELL_OFFER = "MAKE_BTC_SELL_OFFER";
    String OPERATION_TAKE_BTC_SELL_OFFER = "TAKE_BTC_SELL_OFFER";
    String OPERATION_EXCHANGE_FOR_BTC = "EXCHANGE_FOR_BTC";
    // ** BTC Trusts **
    String OPERATION_CREATE_REVOCABLE_TRUST = "CREATE_REVOCABLE_TRUST";
    String OPERATION_UPDATE_REVOCABLE_TRUST= "UPDATE_REVOCABLE_TRUST";
    String OPERATION_CLOSE_REVOCABLE_TRUST = "CLOSE_REVOCABLE_TRUST";
    String OPERATION_CREATE_IRREVOCABLE_TRUST = "CREATE_IRREVOCABLE_TRUST";
    // ** Payment Channels **
    String OPERATION_OPEN_PAYMENT_CHANNEL = "OPEN_PAYMENT_CHANNEL";
    String OPERATION_MAKE_PAYMENT_IN_CHANNEL = "MAKE_PAYMENT_IN_CHANNEL";
    String OPERATION_CLOSE_PAYMENT_CHANNEL = "CLOSE_PAYMENT_CHANNEL";

    boolean init(Properties props) throws Exception;

    void handleDocument(Envelope e);

    boolean destroy() throws Exception;

    boolean destroyGracefully() throws Exception;
}
