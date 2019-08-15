/*
PrevailProtocol.
Copyright (C) 2019  https://github.com/OughtToPrevail

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
package oughttoprevail.prevailprotocol.asymmetriccryptography;

import org.whispersystems.curve25519.Curve25519;
import org.whispersystems.curve25519.Curve25519KeyPair;

import oughttoprevail.prevailprotocol.keys.KeyPair;

/**
 * A Ed25519 implementation of {@link AsymmetricCryptography}.
 * This implementation is a JNI implementation of Ed25519 using an Ed25519 C Library.
 *
 * @see <a href="https://ed25519.cr.yp.to/">Ed25519</a>
 * @see <a href="https://github.com/orlp/ed25519">Ed25519 C Library</a>
 */
public class X25519 implements AsymmetricCryptography
{
	/**
	 * Size of an Ed25519 public key in bytes
	 */
	private static final int PUBLIC_KEY_SIZE = 32;
	/**
	 * Size of a signature
	 */
	private static final int SIGNATURE_SIZE = 64;
	
	/**
	 * Curve to use
	 */
	private final Curve25519 curve = Curve25519.getInstance(Curve25519.BEST);
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public KeyPair generateKeyPair()
	{
		Curve25519KeyPair curve25519KeyPair = curve.generateKeyPair();
		return new KeyPair(curve25519KeyPair.getPrivateKey(), curve25519KeyPair.getPublicKey());
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public byte[] keyExchange(byte[] publicKey, byte[] privateKey)
	{
		return curve.calculateAgreement(publicKey, privateKey);
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public byte[] sign(byte[] message, byte[] privateKey)
	{
		return curve.calculateSignature(privateKey, message);
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean verify(byte[] signature, byte[] message, byte[] publicKey)
	{
		return curve.verifySignature(publicKey, message, signature);
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public int getPublicKeySize()
	{
		return PUBLIC_KEY_SIZE;
	}
	
	@Override
	public int getSignatureSize()
	{
		return SIGNATURE_SIZE;
	}
}