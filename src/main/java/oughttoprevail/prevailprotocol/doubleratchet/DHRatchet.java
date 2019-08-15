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
package oughttoprevail.prevailprotocol.doubleratchet;

import java.security.InvalidKeyException;

import oughttoprevail.prevailprotocol.asymmetriccryptography.AsymmetricCryptography;
import oughttoprevail.prevailprotocol.kdf.KDF;
import oughttoprevail.prevailprotocol.keys.KeyPair;
import oughttoprevail.prevailprotocol.session.Session;
import oughttoprevail.prevailprotocol.settings.Settings;
import oughttoprevail.prevailprotocol.util.Util;

/**
 * A {@link DHRatchet} provides break-in-recovery by changing the ratchet keys of sending and receiving {@link SymmetricKeyRatchet}.
 *
 * @see <a href="https://signal.org/docs/specifications/doubleratchet/">Double-Ratchet</a>
 */
public class DHRatchet
{
	/**
	 * Derives and returns a new root key and new key in the specified outputSize with the specified settings and kdf from the specified rootKey and
	 * {@link AsymmetricCryptography#keyExchange(byte[], byte[])} of specified receivedRatchetKey and specified privateRatchetKey.
	 *
	 * @param kdf to derive keys with
	 * @param rootKey is the current rootKey, this will update the values in this to match the new rootKey
	 * @param receivedRatchetKey to be the publicKey in keyExchange
	 * @param ratchetKeyPair is the current ratchet key pair, it's private key will be the privateKey in keyExchange
	 * @param outputSize of the new key to be returned
	 * @param settings to be used for derivation
	 * @return a new derived key with the specified outputSize as the length
	 * @throws InvalidKeyException if the specified {@link KDF} threw {@link InvalidKeyException}
	 */
	public static byte[] deriveKeys(KDF kdf, byte[] rootKey, byte[] receivedRatchetKey, KeyPair ratchetKeyPair, int outputSize, Settings settings)
			throws InvalidKeyException
	{
		int rootKeySize = settings.getSymmetricKeySize();
		byte[] keys = kdf.deriveKey(rootKey,
				settings.getAsymmetricCryptography().keyExchange(receivedRatchetKey, ratchetKeyPair.getPrivateKey()),
				settings.getDHRatchetInfo(),
				rootKeySize + outputSize);
		System.arraycopy(keys, 0, rootKey, 0, rootKeySize);
		return Util.range(keys, rootKeySize, outputSize);
	}
	
	/**
	 * Invokes {@link #deriveKeys(KDF, byte[], byte[], KeyPair, int, Settings)} with the outputSize as specified settings {@link Settings#getSymmetricKeySize()}.
	 */
	public static byte[] deriveKey(KDF kdf, byte[] rootKey, byte[] receivedRatchetKey, KeyPair privateRatchetKey, Settings settings)
			throws InvalidKeyException
	{
		return deriveKeys(kdf, rootKey, receivedRatchetKey, privateRatchetKey, settings.getSymmetricKeySize(), settings);
	}
	
	/**
	 * Session to use
	 */
	private final Session session;
	/**
	 * Will be used to derive new keys
	 */
	private final KDF kdf;
	/**
	 * Settings to use
	 */
	private final Settings settings;
	
	/**
	 * Constructs a new {@link DHRatchet} for the specified session and settings.
	 *
	 * @param session to use
	 * @param settings to use
	 */
	public DHRatchet(Session session, Settings settings)
	{
		this.session = session;
		this.kdf = session.getKDF();
		this.settings = settings;
	}
	
	/**
	 * Performs a DH ratchet step using the specified receivedRatchetKey.
	 * A DH ratchet step will derive new sending and receiving keys based on the specified receivedRatchetKey.
	 * This should only be invoked if the receivedRatchetKey doesn't match the last receivedRatchetKey.
	 *
	 * @param receivedRatchetKey to derive keys with
	 */
	public void step(byte[] receivedRatchetKey) throws InvalidKeyException
	{
		changeChainKey(session.getReceivingRatchet(), session.getReceivingHeaderRatchet(), receivedRatchetKey);
		session.setRatchetKeyPair(settings.getAsymmetricCryptography().generateKeyPair());
		changeChainKey(session.getSendingRatchet(), session.getSendingHeaderRatchet(), receivedRatchetKey);
		session.dhRatchetChange(receivedRatchetKey);
	}
	
	/**
	 * Changes the chainKey for the specified symmetricRatchet by deriving new keys from the specified receivedRatchetKey.
	 *
	 * @param symmetricRatchet in which to change chainKey
	 * @param headerKeyRatchet in which to change header keys
	 * @param receivedRatchetKey to derive new keys from
	 */
	private void changeChainKey(SymmetricKeyRatchet symmetricRatchet, HeaderKeyRatchet headerKeyRatchet, byte[] receivedRatchetKey)
			throws InvalidKeyException
	{
		byte[] chainKey;
		byte[] rootKey = session.getRootKey();
		//current ratchet private key
		KeyPair privateRatchetKey = session.getRatchetKeyPair();
		if(settings.isUseHeaderEncryption())
		{
			//if use header encryption then derive a nextHeaderChainKey and possibly nextAuthHeaderKey if needed
			int chainKeySize = settings.getSymmetricKeySize();
			boolean needAuthKeys = !settings.isUseUpdateAAD();
			byte[] deriveKeys = deriveKeys(kdf, rootKey, receivedRatchetKey, privateRatchetKey, chainKeySize * (needAuthKeys ? 3 : 2), settings);
			byte[][] split = Util.split(deriveKeys, chainKeySize);
			chainKey = split[0];
			byte[] nextHeaderChainKey = split[1];
			byte[] nextAuthHeaderKey = needAuthKeys ? split[2] : null;
			//update change
			headerKeyRatchet.step(nextHeaderChainKey, nextAuthHeaderKey);
		} else
		{
			chainKey = deriveKey(kdf, rootKey, receivedRatchetKey, privateRatchetKey, settings);
		}
		symmetricRatchet.chainKeyChanged(chainKey);
	}
}