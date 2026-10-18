package ra.btc;

import ra.btc.bitcoinj.BitcoinJClient;
import ra.btc.rpc.LocalBitcoinClient;
import ra.common.Envelope;
import ra.common.messaging.MessageProducer;
import ra.common.service.BaseService;
import ra.common.service.ServiceStatus;
import ra.common.service.ServiceStatusObserver;
import ra.common.Config;
import ra.common.tasks.TaskRunner;

import java.net.Proxy;
import java.util.*;
import java.util.logging.Logger;

/**
 * Service for providing access to the Bitcoin network
 */
public class BitcoinService extends BaseService {

    private static final Logger LOG = Logger.getLogger(BitcoinService.class.getName());

    private BitcoinClient client;
    private volatile Proxy pendingProxy;
    private volatile BitcoinClient.ProxiedHostResolver pendingSeedResolver;
    private volatile java.util.List<String> pendingRestoreWords;
    private volatile long pendingRestoreCreation;

    public BitcoinService() {}

    public BitcoinService(MessageProducer producer, ServiceStatusObserver observer) {
        super(producer, observer);
    }

    /**
     * Staged and applied to {@code client} on the next {@link #start}, since
     * {@code client} is a fresh instance every time (see {@link #start} below) -
     * this outer service instance is what stays stable across a caller's
     * restart-on-availability-change cycle (e.g. {@code network.onemfive.core.
     * business.BitcoinService.reconcileNetworking}), so the proxy has to be
     * staged here, not on the transient client. See {@link BitcoinClient#setProxy}.
     */
    public void setProxy(Proxy proxy) {
        this.pendingProxy = proxy;
    }

    /** Staged the same way and for the same reason as {@link #setProxy} - see {@link BitcoinClient#setSeedResolver}. */
    public void setSeedResolver(BitcoinClient.ProxiedHostResolver resolver) {
        this.pendingSeedResolver = resolver;
    }

    /**
     * Staged like {@link #setProxy}: the next {@link #start} rebuilds the wallet from {@code words} (see
     * {@link BitcoinClient#setRestorePhrase}) and then forgets them, so later restarts keep that wallet.
     */
    public void setRestorePhrase(java.util.List<String> words, long creationEpochSeconds) {
        this.pendingRestoreWords = words == null ? null : new java.util.ArrayList<>(words);
        this.pendingRestoreCreation = creationEpochSeconds;
    }

    @Override
    public void handleDocument(Envelope e) {
        client.handleDocument(e);
    }

    @Override
    public boolean start(Properties p) {
        LOG.info("Starting...");
        updateStatus(ServiceStatus.STARTING);
        if(!super.start(p))
            return false;
        LOG.info("Loading properties...");
        try {
            config = Config.loadAll(p, "ra-btc.config");
        } catch (Exception e) {
            LOG.log(java.util.logging.Level.SEVERE, "could not load ra-btc.config: " + e.getLocalizedMessage(), e);
            return false;
        }
        if(localNodeRunning()) {
            client = new LocalBitcoinClient(this);
        } else {
            client = new BitcoinJClient(this);
        }
        client.setProxy(pendingProxy);
        client.setSeedResolver(pendingSeedResolver);
        java.util.List<String> restoreWords = pendingRestoreWords;
        if (restoreWords != null) client.setRestorePhrase(restoreWords, pendingRestoreCreation);
        try {
            if(!client.init(config)) {
                LOG.severe("Client initialization failed, exiting.");
                return false;
            }
        } catch (Exception e) {
            LOG.log(java.util.logging.Level.SEVERE, "Bitcoin client initialization failed: " + e.getLocalizedMessage(), e);
            return false;
        }
        if (restoreWords != null) {
            pendingRestoreWords = null;
            restoreWords.clear();
        }
        updateStatus(ServiceStatus.RUNNING);
        LOG.info("Started.");
        return true;
    }

    @Override
    public boolean shutdown() {
        LOG.info("Shutting down...");
        updateStatus(ServiceStatus.SHUTTING_DOWN);
        try {
            client.destroy();
        } catch (Exception e) {
            LOG.warning(e.getLocalizedMessage());
        }
        updateStatus(ServiceStatus.SHUTDOWN);
        LOG.info("Shutdown.");
        return true;
    }

    @Override
    public boolean gracefulShutdown() {
        LOG.info("Gracefully shutting down...");
        updateStatus(ServiceStatus.GRACEFULLY_SHUTTING_DOWN);
        try {
            client.destroyGracefully();
        } catch (Exception e) {
            LOG.warning(e.getLocalizedMessage());
        }
        updateStatus(ServiceStatus.GRACEFULLY_SHUTDOWN);
        LOG.info("Gracefully shutdown.");
        return true;
    }

    private boolean localNodeRunning() {

        return false;
    }

//    public static void main(String[] args) {
//        BitcoinService service = new BitcoinService();
//        service.setProducer(new MessageProducer() {
//            @Override
//            public boolean send(Envelope envelope) {
//                return true;
//            }
//
//            @Override
//            public boolean send(Envelope envelope, Client client) {
//                return true;
//            }
//
//            @Override
//            public boolean deadLetter(Envelope envelope) {
//                return true;
//            }
//        });
//        Properties props = new Properties();
//        for(String arg : args) {
//            String[] nvp = arg.split("=");
//            props.put(nvp[0],nvp[1]);
//        }
//        if(service.start(props)) {
//            while(service.getServiceStatus() != ServiceStatus.SHUTDOWN) {
//                Wait.aSec(1);
//            }
//        } else {
//            System.exit(-1);
//        }
//    }

}
