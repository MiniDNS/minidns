/*
 * Copyright 2015-2024 the original author or authors
 *
 * This software is licensed under the Apache License, Version 2.0,
 * the GNU Lesser General Public License version 2 or later ("LGPL")
 * and the WTFPL.
 * You may choose either license to govern your use of this software only
 * upon the condition that you accept all of the terms of either
 * the Apache License 2.0, the LGPL 2.1+ or the WTFPL.
 */
package org.minidns.dnssec;

import org.minidns.DnsCache;
import org.minidns.constants.DnssecConstants.DigestAlgorithm;
import org.minidns.dnsmessage.DnsMessage;
import org.minidns.dnsmessage.Question;
import org.minidns.dnsname.DnsName;
import org.minidns.dnsname.InvalidDnsNameException;
import org.minidns.dnsqueryresult.DnsQueryResult;
import org.minidns.dnssec.DnssecUnverifiedReason.NoActiveSignaturesReason;
import org.minidns.dnssec.DnssecUnverifiedReason.NoSecureEntryPointReason;
import org.minidns.dnssec.DnssecUnverifiedReason.NoSignaturesReason;
import org.minidns.dnssec.DnssecUnverifiedReason.NoTrustAnchorReason;
import org.minidns.dnssec.DnssecValidationFailedException.AuthorityDoesNotContainSoa;
import org.minidns.dnssec.algorithms.AlgorithmMap;
import org.minidns.iterative.ReliableDnsClient;
import org.minidns.record.CNAME;
import org.minidns.record.DLV;
import org.minidns.record.DNAME;
import org.minidns.record.DNSKEY;
import org.minidns.record.DS;
import org.minidns.record.Data;
import org.minidns.record.DelegatingDnssecRR;
import org.minidns.record.NSEC;
import org.minidns.record.NSEC3;
import org.minidns.record.RRSIG;
import org.minidns.record.Record;
import org.minidns.record.Record.CLASS;
import org.minidns.record.Record.TYPE;

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.CopyOnWriteArrayList;

public class DnssecClient extends ReliableDnsClient {

    /**
     * The root zone's KSK-2017, whose ID is "Klajeyz" and whose key tag value is "20326".
     *
     * @see <a href="https://data.iana.org/root-anchors/root-anchors.xml">IANA root zone trust anchors</a>
     */
    private static final BigInteger ROOT_KSK_2017 = new BigInteger("1628686155461064465348252249725010996177649738666492500572664444461532807739744536029771810659241049343994038053541290419968870563183856865780916376571550372513476957870843322273120879361960335192976656756972171258658400305760429696147778001233984421619267530978084631948434496468785021389956803104620471232008587410372348519229650742022804219634190734272506220018657920136902014393834092648785514548876370028925405557661759399901378816916683122474038734912535425670533237815676134840739565610963796427401855723026687073600445461090736240030247906095053875491225879656640052743394090544036297390104110989318819106653199917493");

    /**
     * The root zone's KSK-2024, whose ID is "Kmyv6jo" and whose key tag value is "38696". The root zone's DNSKEY RRset
     * is signed with this key since 2026-10-11.
     *
     * @see <a href="https://data.iana.org/root-anchors/root-anchors.xml">IANA root zone trust anchors</a>
     */
    private static final BigInteger ROOT_KSK_2024 = new BigInteger("1628686155774121212168081024680239155604420268691380415887810174716442156063993152758837847983942799877886941977560662680203835048611462974430324555256015052877501366226310539062711393346584350551693842362076723827358391786883611293998126527175865775276768514791204165196787699241676676814251122639194103258915247638509608611180547418668353298742571235995455990809680031413088313234415379381686894805351607921243348741522050630785576836709808997878870113887781468394260370502860846217704015926043569970756428556654452203219129363526322839180253672785807974524503640093519709242302125704407718029753636688205844737179386330503");

    private static final DnsName DEFAULT_DLV = DnsName.from("dlv.isc.org");

    /**
     * Create a new DNSSEC aware DNS client using the global default cache.
     */
    public DnssecClient() {
        this(DEFAULT_CACHE);
    }

    /**
     * Create a new DNSSEC aware DNS client with the given DNS cache.
     *
     * @param cache The backend DNS cache.
     */
    public DnssecClient(DnsCache cache) {
        super(cache);
        addSecureEntryPoint(DnsName.ROOT, ROOT_KSK_2017.toByteArray());
        addSecureEntryPoint(DnsName.ROOT, ROOT_KSK_2024.toByteArray());
    }

    /**
     * Known secure entry points (SEPs).
     */
    private final ConcurrentMap<DnsName, List<byte[]>> knownSeps = new ConcurrentHashMap<>();

    private boolean stripSignatureRecords = true;

    /**
     * The active DNSSEC Look-aside Validation Registry. May be <code>null</code>.
     */
    private DnsName dlv;

    @Override
    public DnsQueryResult query(Question q) throws IOException {
        DnssecQueryResult dnssecQueryResult =  queryDnssec(q);
        if (!dnssecQueryResult.isAuthenticData()) {
            // TODO: Refine exception.
            throw new IOException();
        }
        return dnssecQueryResult.dnsQueryResult;
    }

    public DnssecQueryResult queryDnssec(CharSequence name, TYPE type) throws IOException {
        Question q = new Question(name, type, CLASS.IN);
        return queryDnssec(q);
    }

    public DnssecQueryResult queryDnssec(Question q) throws IOException {
        DnsQueryResult dnsQueryResult = super.query(q);
        DnssecQueryResult dnssecQueryResult = performVerification(dnsQueryResult);
        return dnssecQueryResult;
    }

    private DnssecQueryResult performVerification(DnsQueryResult dnsQueryResult) throws IOException {
        if (dnsQueryResult == null) return null;

        DnsMessage dnsMessage = dnsQueryResult.response;
        DnsMessage.Builder messageBuilder = dnsMessage.asBuilder();

        Set<DnssecUnverifiedReason> unverifiedReasons = verify(dnsMessage);

        messageBuilder.setAuthenticData(unverifiedReasons.isEmpty());

        List<Record<? extends Data>> answers = dnsMessage.answerSection;
        List<Record<? extends Data>> nameserverRecords = dnsMessage.authoritySection;
        List<Record<? extends Data>> additionalResourceRecords = dnsMessage.additionalSection;
        Set<Record<RRSIG>> signatures = new HashSet<>();
        Record.filter(signatures, RRSIG.class, answers);
        Record.filter(signatures, RRSIG.class, nameserverRecords);
        Record.filter(signatures, RRSIG.class, additionalResourceRecords);

        if (stripSignatureRecords) {
            messageBuilder.setAnswers(stripSignatureRecords(answers));
            messageBuilder.setNameserverRecords(stripSignatureRecords(nameserverRecords));
            messageBuilder.setAdditionalResourceRecords(stripSignatureRecords(additionalResourceRecords));
        }

        return new DnssecQueryResult(messageBuilder.build(), dnsQueryResult, signatures, unverifiedReasons);
    }

    private static List<Record<? extends Data>> stripSignatureRecords(List<Record<? extends Data>> records) {
        if (records.isEmpty()) return records;
        List<Record<? extends Data>> recordList = new ArrayList<>(records.size());
        for (Record<? extends Data> record : records) {
            if (record.type != TYPE.RRSIG) {
                recordList.add(record);
            }
        }
        return recordList;
    }

    private Set<DnssecUnverifiedReason> verify(DnsMessage dnsMessage) throws IOException {
        if (!dnsMessage.answerSection.isEmpty()) {
            return verifyAnswer(dnsMessage);
        } else {
            return verifyNsec(dnsMessage);
        }
    }

    private Set<DnssecUnverifiedReason> verifyAnswer(DnsMessage dnsMessage) throws IOException {
        Question q = dnsMessage.questions.get(0);
        List<Record<? extends Data>> answers = dnsMessage.answerSection;
        List<Record<? extends Data>> toBeVerified = dnsMessage.copyAnswers();
        VerifySignaturesResult verifiedSignatures = verifySignatures(q, answers, toBeVerified);
        Set<DnssecUnverifiedReason> result = verifiedSignatures.reasons;
        if (!result.isEmpty()) {
            return result;
        }

        // A DNSKEY RRset owned by the queried name is authenticated only through a secure entry point (SEP), i.e., a
        // key of the RRset that validly signs the RRset and that is a trust anchor or is referred to by a DS RR in the
        // parent zone (RFC 4035 § 5.2). It is never authenticated by a signature from another zone. Hence, if the
        // answer carries such a DNSKEY RRset, a SEP has to be found below, or the answer is not authentic.
        boolean dnskeyRrsetRequiresSep = false;
        for (Record<? extends Data> record : answers) {
            if (record.type == TYPE.DNSKEY && record.name.equals(q.name)) {
                dnskeyRrsetRequiresSep = true;
                break;
            }
        }

        // We only need one valid SEP.
        boolean sepSignatureValid = false;
        Set<DnssecUnverifiedReason> sepReasons = new HashSet<>();
        Set<DNSKEY> selfSigningKeys = verifiedSignatures.selfSigningKeys;
        for (Iterator<Record<? extends Data>> iterator = toBeVerified.iterator(); iterator.hasNext(); ) {
            Record<DNSKEY> record = iterator.next().ifPossibleAs(DNSKEY.class);
            if (record == null) {
                continue;
            }
            iterator.remove();

            // Only a DNSKEY that validly signs the DNSKEY RRset can establish the chain of trust to the RRset.
            if (!selfSigningKeys.contains(record.payloadData)) {
                LOGGER.finer("Not considering DNSKEY " + record.payloadData.getKeyTag() + " of " + record.name
                                + " as secure entry point, as it does not validly sign the DNSKEY RRset");
                continue;
            }

            // Verify the DNSKEY as if it was a SEP. If we find a single SEP we are safe.
            Set<DnssecUnverifiedReason> reasons = verifySecureEntryPoint(record);
            if (reasons.isEmpty()) {
                sepSignatureValid = true;
            } else {
                sepReasons.addAll(reasons);
            }
        }

        if (dnskeyRrsetRequiresSep && !sepSignatureValid) {
            if (sepReasons.isEmpty()) {
                // The DNSKEY RRset is not validly signed by any DNSKEY that is a secure entry point, for example
                // because it is only signed by a key from another zone.
                result.add(new NoSecureEntryPointReason(q.name));
            } else {
                result.addAll(sepReasons);
            }
        }
        removeDnameSynthesizedCnames(answers, toBeVerified);
        if (!toBeVerified.isEmpty()) {
            if (toBeVerified.size() != answers.size()) {
                throw new DnssecValidationFailedException(q, "Only some records are signed!");
            } else {
                result.add(new NoSignaturesReason(q));
            }
        }
        return result;
    }

    /**
     * Remove the CNAME RRs synthesized from validated DNAME RRs from the RRs to be verified. Synthesized CNAME RRs are
     * not signed, instead a validator has to check that they are consistent with a validated DNAME RR (RFC 6672
     * § 5.3.1).
     *
     * @param answers the RRs of the answer section.
     * @param toBeVerified the RRs of the answer section that have not been verified yet.
     */
    private static void removeDnameSynthesizedCnames(List<Record<? extends Data>> answers, List<Record<? extends Data>> toBeVerified) {
        List<Record<DNAME>> validatedDnames = new ArrayList<>();
        for (Record<? extends Data> record : answers) {
            Record<DNAME> dnameRecord = record.ifPossibleAs(DNAME.class);
            // The RRs that are no longer to be verified have been validated by verifySignatures().
            if (dnameRecord == null || toBeVerified.contains(dnameRecord)) continue;
            validatedDnames.add(dnameRecord);
        }
        if (validatedDnames.isEmpty()) return;

        for (Iterator<Record<? extends Data>> iterator = toBeVerified.iterator(); iterator.hasNext(); ) {
            Record<CNAME> cnameRecord = iterator.next().ifPossibleAs(CNAME.class);
            if (cnameRecord == null) continue;

            for (Record<DNAME> dnameRecord : validatedDnames) {
                if (isSynthesizedFrom(cnameRecord, dnameRecord)) {
                    iterator.remove();
                    break;
                }
            }
        }
    }

    private static boolean isSynthesizedFrom(Record<CNAME> cnameRecord, Record<DNAME> dnameRecord) {
        if (cnameRecord.clazz != dnameRecord.clazz) return false;

        DnsName owner = cnameRecord.name;
        DnsName dnameOwner = dnameRecord.name;
        // A DNAME RR does not redirect its owner name, only the names below it (RFC 6672 § 2.3).
        if (!owner.isChildOf(dnameOwner) || owner.equals(dnameOwner)) return false;

        DnsName synthesizedTarget;
        try {
            synthesizedTarget = owner.replaceSuffix(dnameOwner, dnameRecord.payloadData.target);
        } catch (InvalidDnsNameException.DNSNameTooLongException e) {
            // The substitution overflows, hence no CNAME is synthesized (RFC 6672 § 2.2).
            return false;
        }
        return cnameRecord.payloadData.target.equals(synthesizedTarget);
    }

    private Set<DnssecUnverifiedReason> verifyNsec(DnsMessage dnsMessage) throws IOException {
        Set<DnssecUnverifiedReason> result = new HashSet<>();
        Question q = dnsMessage.questions.get(0);
        boolean validNsec = false;
        boolean nsecPresent = false;

        // Get the SOA RR that has to be in the authority section. Note that we will verify its signature later, after
        // we have verified the NSEC3 RR. And although the data form the SOA RR is only required for NSEC3 we check for
        // its existence here, since it would be invalid if there is none.
        // TODO: Add a reference to the relevant RFC parts which specify that there has to be a SOA RR in X.
        DnsName zone = null;
        List<Record<? extends Data>> authoritySection = dnsMessage.authoritySection;
        for (Record<? extends Data> authorityRecord : authoritySection) {
            if (authorityRecord.type == TYPE.SOA) {
                zone = authorityRecord.name;
                break;
            }
        }
        if (zone == null)
            throw new AuthorityDoesNotContainSoa(dnsMessage);

        // TODO Examine if it is better to verify the RRs in the authority section *before* we verify NSEC(3). We
        // currently do it the other way around.

        // TODO: This whole logic needs to be changed. It currently checks one NSEC(3) record after another, when it
        // should first determine if we are dealing with NSEC or NSEC3 and the verify the whole response.
        for (Record<? extends Data> record : authoritySection) {
            DnssecUnverifiedReason reason;

            switch (record.type) {
            case NSEC:
                nsecPresent = true;
                Record<NSEC> nsecRecord = record.as(NSEC.class);
                reason = Verifier.verifyNsec(nsecRecord, q);
                break;
            case NSEC3:
                nsecPresent = true;
                Record<NSEC3> nsec3Record = record.as(NSEC3.class);
                reason = Verifier.verifyNsec3(zone, nsec3Record, q);
                break;
            default:
                continue;
            }

            if (reason != null) {
                result.add(reason);
            } else {
                validNsec = true;
            }
        }

        // TODO: Shouldn't we also throw if !nsecPresent?
        if (nsecPresent && !validNsec) {
            throw new DnssecValidationFailedException(q, "Invalid NSEC!");
        }

        List<Record<? extends Data>> toBeVerified = dnsMessage.copyAuthority();
        VerifySignaturesResult verifiedSignatures = verifySignatures(q, authoritySection, toBeVerified);
        if (validNsec && verifiedSignatures.reasons.isEmpty()) {
            result.clear();
        } else {
            result.addAll(verifiedSignatures.reasons);
        }

        if (!toBeVerified.isEmpty() && toBeVerified.size() != authoritySection.size()) {
            // TODO Refine this exception and include the missing toBeVerified RRs and the whole DnsMessage into it.
            throw new DnssecValidationFailedException(q, "Only some resource records from the authority section are signed!");
        }

        return result;
    }

    private static final class VerifySignaturesResult {
        /**
         * The DNSKEYs of the queried name that validly sign the DNSKEY RRset. If empty, then the DNSKEY RRset has no
         * valid self-signature.
         */
        Set<DNSKEY> selfSigningKeys = new HashSet<>();
        Set<DnssecUnverifiedReason> reasons = new HashSet<>();
    }

    private static final class RrSetId {
        final DnsName name;
        final int typeCoveredValue;

        RrSetId(DnsName name, int typeCoveredValue) {
            this.name = name;
            this.typeCoveredValue = typeCoveredValue;
        }

        @Override
        public boolean equals(Object other) {
            if (this == other) return true;
            if (!(other instanceof RrSetId)) return false;
            RrSetId otherRrSetId = (RrSetId) other;
            return typeCoveredValue == otherRrSetId.typeCoveredValue && name.equals(otherRrSetId.name);
        }

        @Override
        public int hashCode() {
            return 37 * name.hashCode() + typeCoveredValue;
        }
    }

    @SuppressWarnings("JavaUtilDate")
    private VerifySignaturesResult verifySignatures(Question q, Collection<Record<? extends Data>> reference, List<Record<? extends Data>> toBeVerified) throws IOException {
        final Date now = new Date();
        final List<RRSIG> outdatedRrSigs = new ArrayList<>();
        VerifySignaturesResult result = new VerifySignaturesResult();
        final List<Record<RRSIG>> rrsigs = new ArrayList<>(toBeVerified.size());

        for (Record<? extends Data> recordToBeVerified : toBeVerified) {
            Record<RRSIG> record = recordToBeVerified.ifPossibleAs(RRSIG.class);
            if (record == null) continue;

            RRSIG rrsig = record.payloadData;
            if (rrsig.signatureExpiration.compareTo(now) < 0 || rrsig.signatureInception.compareTo(now) > 0) {
                // This RRSIG is out of date, but there might be one that is not.
                outdatedRrSigs.add(rrsig);
                continue;
            }
            rrsigs.add(record);
        }

        if (rrsigs.isEmpty()) {
            if (!outdatedRrSigs.isEmpty()) {
                result.reasons.add(new NoActiveSignaturesReason(q, outdatedRrSigs));
            } else {
                // TODO: Check if QNAME results should have signatures and add a different reason if there are RRSIGs
                // expected compared to when not.
                result.reasons.add(new NoSignaturesReason(q));
            }
            return result;
        }

        // Group the RRSIGs by the RRset they cover, i.e., by owner name and covered type.
        Map<RrSetId, List<Record<RRSIG>>> rrsigsByRrSet = new LinkedHashMap<>();
        for (Record<RRSIG> sigRecord : rrsigs) {
            RrSetId rrSetId = new RrSetId(sigRecord.name, sigRecord.payloadData.typeCoveredValue);
            List<Record<RRSIG>> rrSetRrsigs = rrsigsByRrSet.get(rrSetId);
            if (rrSetRrsigs == null) {
                rrSetRrsigs = new ArrayList<>();
                rrsigsByRrSet.put(rrSetId, rrSetRrsigs);
            }
            rrSetRrsigs.add(sigRecord);
        }

        for (Map.Entry<RrSetId, List<Record<RRSIG>>> entry : rrsigsByRrSet.entrySet()) {
            RrSetId rrSetId = entry.getKey();
            List<Record<RRSIG>> rrSetRrsigs = entry.getValue();
            toBeVerified.removeAll(rrSetRrsigs);

            List<Record<? extends Data>> records = new ArrayList<>(reference.size());
            for (Record<? extends Data> record : reference) {
                if (record.typeValue == rrSetId.typeCoveredValue && record.name.equals(rrSetId.name)) {
                    records.add(record);
                }
            }

            // An RRset is verified if at least one of its RRSIGs is valid (RFC 4035 § 5.3.3, RFC 6840 § 5.11). For
            // example, during a key or algorithm rollover, the RRset may also carry RRSIGs that we are unable to
            // verify.
            boolean rrSetVerified = false;
            boolean rrSetSelfSigned = false;
            Set<DnssecUnverifiedReason> rrSetReasons = new HashSet<>();
            DnssecValidationFailedException validationFailedException = null;
            for (Record<RRSIG> sigRecord : rrSetRrsigs) {
                RRSIG rrsig = sigRecord.payloadData;

                if (!isParentOrSelf(sigRecord.name.ace, rrsig.signerName.ace)) {
                    LOGGER.finer("Records at " + sigRecord.name + " are cross-signed with a key from " + rrsig.signerName);
                    continue;
                }

                boolean selfSignedDnskeys = q.name.equals(rrsig.signerName) && rrsig.typeCovered == TYPE.DNSKEY;
                rrSetSelfSigned |= selfSignedDnskeys;

                VerifySignedRecordsResult verifySignedRecordsResult;
                try {
                    verifySignedRecordsResult = verifySignedRecords(q, rrsig, records);
                } catch (DnssecValidationFailedException e) {
                    if (validationFailedException == null) {
                        validationFailedException = e;
                    }
                    continue;
                }

                if (!verifySignedRecordsResult.reasons.isEmpty()) {
                    rrSetReasons.addAll(verifySignedRecordsResult.reasons);
                    continue;
                }

                rrSetVerified = true;
                if (!selfSignedDnskeys) {
                    break;
                }
                // Continue verifying the remaining RRSIGs, as we need to know all DNSKEYs that validly sign the
                // DNSKEY RRset in order to find the one that is a secure entry point.
                result.selfSigningKeys.add(verifySignedRecordsResult.signingKey);
            }

            if (!rrSetVerified) {
                if (validationFailedException != null) {
                    throw validationFailedException;
                }
                if (rrSetReasons.isEmpty()) {
                    // All RRSIGs of this RRset are cross-signed, hence the records remain to be verified.
                    continue;
                }
                result.reasons.addAll(rrSetReasons);
            }

            if (rrSetSelfSigned) {
                // DNSKEYs are verified separately, so don't mark them verified now.
                continue;
            }
            toBeVerified.removeAll(records);
        }
        return result;
    }

    private static boolean isParentOrSelf(String child, String parent) {
        if (child.equals(parent)) return true;
        if (parent.isEmpty()) return true;
        String[] childSplit = child.split("\\.");
        String[] parentSplit = parent.split("\\.");
        if (parentSplit.length > childSplit.length) return false;
        for (int i = 1; i <= parentSplit.length; i++) {
            if (!parentSplit[parentSplit.length - i].equals(childSplit[childSplit.length - i])) {
                return false;
            }
        }
        return true;
    }

    private static final class VerifySignedRecordsResult {
        final Set<DnssecUnverifiedReason> reasons = new HashSet<>();
        DNSKEY signingKey;
    }

    private VerifySignedRecordsResult verifySignedRecords(Question q, RRSIG rrsig, List<Record<? extends Data>> records) throws IOException {
        VerifySignedRecordsResult result = new VerifySignedRecordsResult();
        List<Record<DNSKEY>> dnskeyRrs;

        if (rrsig.typeCovered == TYPE.DNSKEY) {
            // Key must be present
            dnskeyRrs = Record.filter(DNSKEY.class, records);
        } else if (q.type == TYPE.DS && rrsig.signerName.equals(q.name)) {
            // We should not probe for the self signed DS negative response, as it will be an endless loop.
            result.reasons.add(new NoTrustAnchorReason(q.name));
            return result;
        } else {
            DnssecQueryResult dnskeyRes = queryDnssec(rrsig.signerName, TYPE.DNSKEY);
            result.reasons.addAll(dnskeyRes.getUnverifiedReasons());
            dnskeyRrs = dnskeyRes.dnsQueryResult.response.filterAnswerSectionBy(DNSKEY.class);
        }

        // Key tags are not unique, hence try every DNSKEY with a matching key tag (RFC 4034 § 5.3.1).
        boolean keyFound = false;
        DnssecUnverifiedReason unverifiedReason = null;
        for (Record<DNSKEY> dnsKeyRecord : dnskeyRrs) {
            DNSKEY dnskey = dnsKeyRecord.payloadData;
            if (dnskey.getKeyTag() != rrsig.keyTag) {
                continue;
            }
            keyFound = true;

            unverifiedReason = Verifier.verify(records, rrsig, dnskey);
            if (unverifiedReason == null) {
                result.signingKey = dnskey;
                return result;
            }
        }

        if (!keyFound) {
            throw new DnssecValidationFailedException(q, records.size() + " " + rrsig.typeCovered + " record(s) are signed using an unknown key.");
        }

        result.reasons.add(unverifiedReason);
        return result;
    }

    private Set<DnssecUnverifiedReason> verifySecureEntryPoint(final Record<DNSKEY> sepRecord) throws IOException {
        final DNSKEY dnskey = sepRecord.payloadData;

        Set<DnssecUnverifiedReason> unverifiedReasons = new HashSet<>();
        Set<DnssecUnverifiedReason> activeReasons = new HashSet<>();
        List<byte[]> knownSepKeys = knownSeps.get(sepRecord.name);
        if (knownSepKeys != null) {
            for (byte[] knownSepKey : knownSepKeys) {
                if (dnskey.keyEquals(knownSepKey)) {
                    return unverifiedReasons;
                }
            }
            unverifiedReasons.add(new DnssecUnverifiedReason.ConflictsWithSep(sepRecord));
            return unverifiedReasons;
        }

        // If we are looking for the SEP of the root zone at this point, then the client was not
        // configured with one. Hence we can abort and state the reason why we aborted.
        if (sepRecord.name.isRootLabel()) {
           unverifiedReasons.add(new DnssecUnverifiedReason.NoRootSecureEntryPointReason());
           return unverifiedReasons;
        }

        DnssecQueryResult dsResp = queryDnssec(sepRecord.name, TYPE.DS);
        unverifiedReasons.addAll(dsResp.getUnverifiedReasons());

        List<DS> dsRrs = new ArrayList<>();
        for (Record<DS> dsRecord : dsResp.dnsQueryResult.response.filterAnswerSectionBy(DS.class)) {
            dsRrs.add(dsRecord.payloadData);
        }
        List<DelegatingDnssecRR> delegations = getDelegationsFor(dnskey, dsRrs);
        if (!delegations.isEmpty()) {
            activeReasons = dsResp.getUnverifiedReasons();
        } else {
            LOGGER.fine("There is no DS record for \'" + sepRecord.name + "\', server gives empty result");
        }

        if (delegations.isEmpty() && dlv != null && !dlv.isChildOf(sepRecord.name)) {
            DnssecQueryResult dlvResp = queryDnssec(DnsName.from(sepRecord.name, dlv), TYPE.DLV);
            unverifiedReasons.addAll(dlvResp.getUnverifiedReasons());

            List<DLV> dlvRrs = new ArrayList<>();
            for (Record<DLV> dlvRecord : dlvResp.dnsQueryResult.response.filterAnswerSectionBy(DLV.class)) {
                dlvRrs.add(dlvRecord.payloadData);
            }
            delegations = getDelegationsFor(dnskey, dlvRrs);
            if (!delegations.isEmpty()) {
                LOGGER.fine("Found DLV for " + sepRecord.name + ", awesome.");
                activeReasons = dlvResp.getUnverifiedReasons();
            }
        }

        if (!delegations.isEmpty()) {
            Set<DnssecUnverifiedReason> delegationReasons = verifyDelegations(sepRecord, delegations);
            if (delegationReasons.isEmpty()) {
                unverifiedReasons = activeReasons;
            } else {
                unverifiedReasons.addAll(delegationReasons);
            }
        } else if (unverifiedReasons.isEmpty()) {
            unverifiedReasons.add(new NoTrustAnchorReason(sepRecord.name));
        }
        return unverifiedReasons;
    }

    /**
     * Get the delegating RRs, i.e., DS or DLV RRs, that refer to the given DNSKEY. A delegating RR refers to a DNSKEY
     * if its key tag and algorithm match the ones of the DNSKEY (RFC 4035 § 5.2). If there is a delegating RR with a
     * supported digest type other than SHA-1, then the ones with SHA-1 are ignored (RFC 4509 § 3).
     *
     * @param dnskey the DNSKEY.
     * @param delegatingRrs the delegating RRs.
     * @return the delegating RRs that refer to the DNSKEY.
     */
    private static List<DelegatingDnssecRR> getDelegationsFor(DNSKEY dnskey, List<? extends DelegatingDnssecRR> delegatingRrs) {
        List<DelegatingDnssecRR> delegations = new ArrayList<>(delegatingRrs.size());
        boolean strongerThanSha1Present = false;
        for (DelegatingDnssecRR delegatingRr : delegatingRrs) {
            if (delegatingRr.keyTag != dnskey.getKeyTag() || delegatingRr.algorithmByte != dnskey.algorithmByte) {
                continue;
            }
            delegations.add(delegatingRr);

            DigestAlgorithm digestType = delegatingRr.digestType;
            if (digestType != null && digestType != DigestAlgorithm.SHA1
                    && AlgorithmMap.INSTANCE.getDsDigestCalculator(digestType) != null) {
                strongerThanSha1Present = true;
            }
        }

        if (strongerThanSha1Present) {
            for (Iterator<DelegatingDnssecRR> iterator = delegations.iterator(); iterator.hasNext(); ) {
                if (iterator.next().digestType == DigestAlgorithm.SHA1) {
                    iterator.remove();
                }
            }
        }
        return delegations;
    }

    /**
     * Verify the given SEP using the given delegating RRs. The SEP is verified if at least one of the delegating RRs
     * verifies it.
     *
     * @param sepRecord the SEP.
     * @param delegations the delegating RRs that refer to the SEP.
     * @return the reasons why the SEP could not be verified, which is empty if the SEP is verified.
     * @throws DnssecValidationFailedException if the SEP could not be verified because a digest did not match.
     */
    private static Set<DnssecUnverifiedReason> verifyDelegations(Record<DNSKEY> sepRecord, List<DelegatingDnssecRR> delegations)
                    throws DnssecValidationFailedException {
        Set<DnssecUnverifiedReason> reasons = new HashSet<>();
        DnssecValidationFailedException validationFailedException = null;
        for (DelegatingDnssecRR delegation : delegations) {
            DnssecUnverifiedReason unverifiedReason;
            try {
                unverifiedReason = Verifier.verify(sepRecord, delegation);
            } catch (DnssecValidationFailedException e) {
                if (validationFailedException == null) {
                    validationFailedException = e;
                }
                continue;
            }

            if (unverifiedReason == null) {
                return Collections.emptySet();
            }
            reasons.add(unverifiedReason);
        }

        if (validationFailedException != null) {
            throw validationFailedException;
        }
        return reasons;
    }

    @Override
    protected DnsMessage.Builder newQuestion(DnsMessage.Builder message) {
        message.getEdnsBuilder().setUdpPayloadSize(dataSource.getUdpPayloadSize()).setDnssecOk();
        message.setCheckingDisabled(true);
        return super.newQuestion(message);
    }

    @Override
    protected String isResponseAcceptable(DnsMessage response) {
        boolean dnssecOk = response.isDnssecOk();
        if (!dnssecOk) {
            // This is a deliberate violation of RFC 6840 § 5.6. I doubt that
            // "resolvers MUST ignore the DO bit in responses" does any good. Also we basically ignore the DO bit after
            // the fall back to iterative mode.
            return "DNSSEC OK (DO) flag not set in response";
        }
        boolean checkingDisabled = response.checkingDisabled;
        if (!checkingDisabled) {
            return "CHECKING DISABLED (CD) flag not set in response";
        }
        return super.isResponseAcceptable(response);
    }

    /**
     * Add a new secure entry point to the list of known secure entry points.
     *
     * A secure entry point acts as a trust anchor. By default, the secure entry points are the key signing keys of the
     * root zone. A domain name may have multiple secure entry points, e.g., during a key rollover, in which case a
     * DNSKEY that matches any of them is accepted.
     *
     * @param name The domain name originating the key. Once the secure entry point for this domain is requested,
     *             the resolver will use this key without further verification instead of using the DNS system to
     *             verify the key.
     * @param key  The secure entry point corresponding to the domain name. This key can be retrieved by requesting
     *             the DNSKEY record for the domain and using the key with first flags bit set
     *             (also called key signing key)
     */
    public final void addSecureEntryPoint(DnsName name, byte[] key) {
        List<byte[]> keys = knownSeps.get(name);
        if (keys == null) {
            keys = new CopyOnWriteArrayList<>();
            List<byte[]> previousKeys = knownSeps.putIfAbsent(name, keys);
            if (previousKeys != null) {
                keys = previousKeys;
            }
        }
        keys.add(key);
    }

    /**
     * Remove the secure entry points stored for a domain name.
     *
     * @param name The domain name of which the corresponding secure entry points shall be removed. For the root zone,
     *             use the empty string here.
     */
    public void removeSecureEntryPoint(DnsName name) {
        knownSeps.remove(name);
    }

    /**
     * Clears the list of known secure entry points.
     *
     * This will also remove the secure entry point of the root zone and
     * thus render this instance useless until a new secure entry point is added.
     */
    public void clearSecureEntryPoints() {
        knownSeps.clear();
    }

    /**
     * Whether signature records (RRSIG) are stripped from the resulting {@link DnsMessage}.
     *
     * Default is {@code true}.
     *
     * @return Whether signature records are stripped.
     */
    public boolean isStripSignatureRecords() {
        return stripSignatureRecords;
    }

    /**
     * Enable or disable stripping of signature records (RRSIG) from the result {@link DnsMessage}.
     * @param stripSignatureRecords Whether signature records shall be stripped.
     */
    public void setStripSignatureRecords(boolean stripSignatureRecords) {
        this.stripSignatureRecords = stripSignatureRecords;
    }

    /**
     * Enables DNSSEC Lookaside Validation (DLV) using the default DLV service at dlv.isc.org.
     */
    public void enableLookasideValidation() {
        configureLookasideValidation(DEFAULT_DLV);
    }

    /**
     * Disables DNSSEC Lookaside Validation (DLV).
     * DLV is disabled by default, this is only required if {@link #enableLookasideValidation()} was used before.
     */
    public void disableLookasideValidation() {
        configureLookasideValidation(null);
    }

    /**
     * Enables DNSSEC Lookaside Validation (DLV) using the given DLV service.
     *
     * @param dlv The domain name of the DLV service to be used or {@code null} to disable DLV.
     */
    public void configureLookasideValidation(DnsName dlv) {
        this.dlv = dlv;
    }
}
