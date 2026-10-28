package ra.btc.psbt;

import org.bitcoinj.base.Address;
import org.bitcoinj.base.Coin;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionOutput;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.script.ScriptPattern;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Builds the signing request for a withdrawal from the vault: picks the vault's coins, pays the destination, returns the
 * change to the vault, and describes every input and the change so a signing device can find its own keys and check
 * the fee. Pure arithmetic over the coins it is given - no wallet, no network - so the selection and fee are testable.
 */
public final class VaultWithdrawal {

    /** The vault key behind a coin: its public key and its path below the account (receive or change chain, then index). */
    public static final class KeyInfo {
        private final byte[] pubKey;
        private final int[] chainAndIndex;

        public KeyInfo(byte[] pubKey, int[] chainAndIndex) {
            this.pubKey = pubKey;
            this.chainAndIndex = chainAndIndex;
        }

        public byte[] pubKey() { return pubKey; }
        public int[] chainAndIndex() { return chainAndIndex; }
    }

    public interface KeyLookup {
        /** The vault key a script pays to, or null if it is not one of the vault's. */
        KeyInfo forScript(Script script);
    }

    /** @param amountSats what the destination gets; @param feeSats what the miners get; @param changeSats back to the vault, 0 if none */
    public static final class Result {
        private final Psbt psbt;
        private final long amountSats;
        private final long feeSats;
        private final long changeSats;
        private final int inputs;

        public Result(Psbt psbt, long amountSats, long feeSats, long changeSats, int inputs) {
            this.psbt = psbt;
            this.amountSats = amountSats;
            this.feeSats = feeSats;
            this.changeSats = changeSats;
            this.inputs = inputs;
        }

        public Psbt psbt() { return psbt; }
        public long amountSats() { return amountSats; }
        public long feeSats() { return feeSats; }
        public long changeSats() { return changeSats; }
        public int inputs() { return inputs; }
    }

    public static final class InsufficientFundsException extends Exception {
        public final long missingSats;
        public InsufficientFundsException(long missingSats) {
            super("The vault is " + missingSats + " sats short of that amount plus the fee.");
            this.missingSats = missingSats;
        }
    }

    private static final long DUST_SATS = 546;

    private VaultWithdrawal() {}

    /**
     * @param candidates       the vault's spendable coins (the caller has applied the confirmation rule)
     * @param amountSats       what to pay the destination, or -1 for everything (no change)
     * @param feeRate          sats per virtual byte
     * @param masterFingerprint the signing device's 4-byte fingerprint
     * @param originPath       the account path (hardened bit set), e.g. 84'/0'/0'
     */
    public static Result build(List<TransactionOutput> candidates, KeyLookup keys, Address destination, long amountSats,
                               long feeRate, Address change, byte[] masterFingerprint, int[] originPath)
            throws InsufficientFundsException {
        if (feeRate < 1) throw new IllegalArgumentException("The fee rate must be at least 1 sat per byte.");
        boolean all = amountSats < 0;
        if (!all && amountSats < DUST_SATS) throw new IllegalArgumentException("That amount is too small to send.");

        List<TransactionOutput> sorted = new ArrayList<>(candidates);
        sorted.sort(Comparator.comparingLong((TransactionOutput o) -> o.getValue().value).reversed());

        long destOutVBytes = outputVBytes(ScriptBuilder.createOutputScript(destination));
        long changeOutVBytes = outputVBytes(ScriptBuilder.createOutputScript(change));

        List<TransactionOutput> chosen = new ArrayList<>();
        long total = 0;
        long inputVBytes = 0;
        for (TransactionOutput o : sorted) {
            chosen.add(o);
            total += o.getValue().value;
            inputVBytes += inputVBytes(o.getScriptPubKey());
            if (!all && total >= amountSats + fee(feeRate, inputVBytes, destOutVBytes + changeOutVBytes)) break;
        }

        long amount;
        long fee;
        long changeSats = 0;
        if (all) {
            fee = fee(feeRate, inputVBytes, destOutVBytes);
            amount = total - fee;
            if (chosen.isEmpty() || amount < DUST_SATS) throw new InsufficientFundsException(Math.max(0, DUST_SATS - amount));
        } else {
            amount = amountSats;
            long withChange = fee(feeRate, inputVBytes, destOutVBytes + changeOutVBytes);
            if (total < amount + fee(feeRate, inputVBytes, destOutVBytes)) {
                throw new InsufficientFundsException(amount + withChange - total);
            }
            long remainder = total - amount - withChange;
            if (remainder >= DUST_SATS) {
                fee = withChange;
                changeSats = remainder;
            } else {
                fee = total - amount; // too little left to be worth a change output: it goes to the miners
            }
        }

        Transaction tx = new Transaction();
        for (TransactionOutput o : chosen) tx.addInput(o.getParentTransactionHash(), o.getIndex(), new ScriptBuilder().build());
        tx.addOutput(Coin.valueOf(amount), destination);
        if (changeSats > 0) tx.addOutput(Coin.valueOf(changeSats), change);

        Psbt psbt = Psbt.create(tx);
        for (int i = 0; i < chosen.size(); i++) {
            TransactionOutput o = chosen.get(i);
            psbt.setWitnessUtxo(i, o);
            if (o.getParentTransaction() != null) psbt.setNonWitnessUtxo(i, o.getParentTransaction());
            else if (!ScriptPattern.isP2WPKH(o.getScriptPubKey())) {
                throw new IllegalStateException("a legacy coin needs its full previous transaction, which the vault scan lacks");
            }
            KeyInfo key = keys.forScript(o.getScriptPubKey());
            if (key == null) throw new IllegalStateException("a coin does not belong to the vault's key");
            psbt.addDerivation(false, i, key.pubKey(), masterFingerprint, fullPath(originPath, key.chainAndIndex()));
        }
        if (changeSats > 0) {
            KeyInfo key = keys.forScript(ScriptBuilder.createOutputScript(change));
            if (key == null) throw new IllegalStateException("the change address does not belong to the vault's key");
            psbt.addDerivation(true, 1, key.pubKey(), masterFingerprint, fullPath(originPath, key.chainAndIndex()));
        }
        return new Result(psbt, amount, fee, changeSats, chosen.size());
    }

    private static int[] fullPath(int[] origin, int[] rest) {
        int[] out = new int[origin.length + rest.length];
        System.arraycopy(origin, 0, out, 0, origin.length);
        System.arraycopy(rest, 0, out, origin.length, rest.length);
        return out;
    }

    private static long fee(long rate, long inputVBytes, long outputVBytes) {
        return rate * (11 + inputVBytes + outputVBytes); // 10.5 of overhead, rounded up
    }

    private static long inputVBytes(Script script) {
        return ScriptPattern.isP2WPKH(script) ? 68 : 148;
    }

    private static long outputVBytes(Script script) {
        return ScriptPattern.isP2WPKH(script) ? 31 : ScriptPattern.isP2PKH(script) ? 34 : 43;
    }
}
