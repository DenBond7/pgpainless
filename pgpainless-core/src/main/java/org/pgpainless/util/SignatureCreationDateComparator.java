package org.pgpainless.util;

import java.util.Comparator;

import org.bouncycastle.openpgp.PGPSignature;

public class SignatureCreationDateComparator implements Comparator<PGPSignature> {
    @Override
    public int compare(PGPSignature one, PGPSignature two) {
        return one.getCreationTime().compareTo(two.getCreationTime());
    }
}
