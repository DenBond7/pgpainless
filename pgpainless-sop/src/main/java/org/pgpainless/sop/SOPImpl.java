// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop;

import sop.SOP;
import sop.operation.Armor;
import sop.operation.Dearmor;
import sop.operation.Decrypt;
import sop.operation.DetachedSign;
import sop.operation.DetachedVerify;
import sop.operation.InlineDetach;
import sop.operation.Encrypt;
import sop.operation.ExtractCert;
import sop.operation.GenerateKey;
import sop.operation.InlineSign;
import sop.operation.InlineVerify;
import sop.operation.Version;

public class SOPImpl implements SOP {

    @Override
    public Version version() {
        return new VersionImpl();
    }

    @Override
    public GenerateKey generateKey() {
        return new GenerateKeyImpl();
    }

    @Override
    public ExtractCert extractCert() {
        return new ExtractCertImpl();
    }

    @Override
    public DetachedSign sign() {
        return detachedSign();
    }

    @Override
    public DetachedSign detachedSign() {
        return new DetachedSignImpl();
    }

    @Override
    public InlineSign inlineSign() {
        return new InlineSignImpl();
    }

    @Override
    public DetachedVerify verify() {
        return detachedVerify();
    }

    @Override
    public DetachedVerify detachedVerify() {
        return new DetachedVerifyImpl();
    }

    @Override
    public InlineVerify inlineVerify() {
        return new InlineVerifyImpl();
    }

    @Override
    public Encrypt encrypt() {
        return new EncryptImpl();
    }

    @Override
    public Decrypt decrypt() {
        return new DecryptImpl();
    }

    @Override
    public Armor armor() {
        return new ArmorImpl();
    }

    @Override
    public Dearmor dearmor() {
        return new DearmorImpl();
    }

    @Override
    public InlineDetach inlineDetach() {
        return new InlineDetachImpl();
    }
}
