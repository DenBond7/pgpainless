package org.pgpainless.util.selection.key.signature;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.util.SignatureCreationDateComparator;

public abstract class PickSignature {

    public final PGPSignature selectLatestValid(List<PGPSignature> signatures, Date validationDate) {
        List<PGPSignature> list = new ArrayList<>(signatures);
        list.sort(new SignatureCreationDateComparator());
        return selectLastValidFromList(list, validationDate);
    }

    protected abstract PGPSignature selectLastValidFromList(List<PGPSignature> signatures, Date validationDate);

    public static PickSignature latestValidForUserId(String userId, Date validationDate) {
        return new PickSignature() {
            @Override
            public PGPSignature selectLastValidFromList(List<PGPSignature> signatures, Date validationDate) {
                PGPSignature current = null;
                for (PGPSignature signature : signatures) {
                    SelectSignatureFromKey.isValidAt(validationDate).accept(signature, );
                }
            }
        };
    }
}
