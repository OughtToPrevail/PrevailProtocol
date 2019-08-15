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
package oughttoprevail.prevailprotocol.x3dh;

import java.security.InvalidKeyException;

import oughttoprevail.prevailprotocol.asymmetriccryptography.AsymmetricCryptography;
import oughttoprevail.prevailprotocol.doubleratchet.DHRatchet;
import oughttoprevail.prevailprotocol.exception.VerificationFailedException;
import oughttoprevail.prevailprotocol.kdf.KDF;
import oughttoprevail.prevailprotocol.keys.IdentifiableKey;
import oughttoprevail.prevailprotocol.keys.KeyPair;
import oughttoprevail.prevailprotocol.session.Session;
import oughttoprevail.prevailprotocol.settings.Settings;
import oughttoprevail.prevailprotocol.util.Util;

/**
 * A X3DH key exchanger, handling key agreement of both sides, "Alice" and "Bob".
 *
 * @see <a href="https://signal.org/docs/specifications/x3dh/">X3DH</a>
 */
public class X3DHKeyExchange
{
	/**
	 * Performs a X3DH key agreement with this user playing the role of "Alice".
	 * Here "Alice" is the initiator (also caller of this method) and "Bob" is the receiver
	 *
	 * @param session to update with result of the key agreement
	 * @param identityPrivateKey Alice's identity private key
	 * @param ephemeralKeyPair Alice's ephemeral key pair
	 * @param bobIdentityKey Bob's public identity key
	 * @param bobSignedPreKey Bob's public signed pre key
	 * @param bobPreKeySignature Bob's pre key signature
	 * @param bobOneTimePreKey Bob's public one time pre key or {@code null} if a one time pre key isn't specified
	 * @param settings to use
	 * @throws VerificationFailedException if verification of the keys failed
	 */
	public static void aliceKeyAgreement(Session session,
										 byte[] identityPrivateKey,
										 KeyPair ephemeralKeyPair,
										 byte[] bobIdentityKey,
										 byte[] bobSignedPreKey,
										 byte[] bobPreKeySignature,
										 byte[] bobOneTimePreKey,
										 Settings settings) throws InvalidKeyException, VerificationFailedException
	{
		//verify the keys
		AsymmetricCryptography asymmetricCryptography = settings.getAsymmetricCryptography();
		if(!asymmetricCryptography.verify(bobPreKeySignature, bobSignedPreKey, bobIdentityKey))
		{
			//verification failed
			throw new VerificationFailedException("Failed verification!");
		}
		byte[] ephemeralKey = ephemeralKeyPair.getPrivateKey();
		//Create a shared secret
		byte[] sharedSecret = Util.combine(asymmetricCryptography.keyExchange(bobSignedPreKey, identityPrivateKey),
				asymmetricCryptography.keyExchange(bobIdentityKey, ephemeralKey),
				asymmetricCryptography.keyExchange(bobSignedPreKey, ephemeralKey),
				bobOneTimePreKey == null ? null : asymmetricCryptography.keyExchange(bobOneTimePreKey, ephemeralKey));
		KeyPair aliceRatchetKeypair = asymmetricCryptography.generateKeyPair();
		KDF kdf = session.getKDF();
		byte[][] keys = deriveRootAndChainKeys(sharedSecret, kdf, settings);
		byte[] rootKey = keys[0];
		byte[] receivingChainKey = keys[1];
		byte[] sendingChainKey;
		byte[] sendingHeaderChainKey = null;
		byte[] authSendingHeaderChainKey = null;
		byte[] nextSendingHeaderChainKey = null;
		byte[] nextAuthSendingHeaderChainKey = null;
		byte[] nextReceivingHeaderChainKey = null;
		byte[] nextAuthReceivingHeaderChainKey = null;
		if(settings.isUseHeaderEncryption())
		{
			//if we're using header encryption we need to derive keys for header ratchets
			boolean needAuthKeys = !settings.isUseUpdateAAD();
			int symmetricKeySize = settings.getSymmetricKeySize();
			if(needAuthKeys)
			{
				byte[][] headerKeys = Util.split(kdf.deriveKey(rootKey, settings.getHeaderKeyInfo(), symmetricKeySize * 5), symmetricKeySize);
				rootKey = headerKeys[0];
				sendingHeaderChainKey = headerKeys[1];
				nextReceivingHeaderChainKey = headerKeys[2];
				authSendingHeaderChainKey = headerKeys[3];
				nextAuthReceivingHeaderChainKey = headerKeys[4];
			} else
			{
				byte[][] headerKeys = Util.split(kdf.deriveKey(rootKey, settings.getHeaderKeyInfo(), symmetricKeySize * 3), symmetricKeySize);
				rootKey = headerKeys[0];
				sendingHeaderChainKey = headerKeys[1];
				nextReceivingHeaderChainKey = headerKeys[2];
			}
			byte[] derivedRatchetKeys = DHRatchet.deriveKeys(kdf,
					rootKey,
					bobSignedPreKey,
					aliceRatchetKeypair,
					symmetricKeySize * (needAuthKeys ? 3 : 2),
					settings);
			byte[][] splitDerivedRatchetKeys = Util.split(derivedRatchetKeys, symmetricKeySize);
			sendingChainKey = splitDerivedRatchetKeys[0];
			nextSendingHeaderChainKey = splitDerivedRatchetKeys[1];
			if(needAuthKeys)
			{
				nextAuthSendingHeaderChainKey = splitDerivedRatchetKeys[2];
			}
		} else
		{
			//if no header encryption is used, only derive a sending chain key
			sendingChainKey = DHRatchet.deriveKey(kdf, rootKey, bobSignedPreKey, aliceRatchetKeypair, settings);
		}
		//update session
		session.keyAgreement(bobIdentityKey,
				aliceRatchetKeypair,
				rootKey,
				bobSignedPreKey,
				sendingChainKey,
				receivingChainKey,
				sendingHeaderChainKey,
				authSendingHeaderChainKey,
				nextSendingHeaderChainKey,
				nextAuthSendingHeaderChainKey,
				nextReceivingHeaderChainKey,
				nextAuthReceivingHeaderChainKey);
	}
	
	/**
	 * Performs a X3DH key agreement with this user playing the role of "Bob".
	 * Here "Alice" is the initiator and "Bob" is the receiver (also caller of this method)
	 *
	 * @param session to update with the result of the key agreement
	 * @param identityPrivateKey Bob's identity private key
	 * @param aliceIdentityKey Alice's public identity key
	 * @param usedSignedPreKey Bob's signed pre key pair which Alice used in her part of the key agreement
	 * @param usedOneTimePreKey Bob's one time pre key pair which Alice used in her part of the key agreement
	 * @param aliceEphemeralKey Alice's public ephemeral key
	 * @param settings to use
	 */
	public static void bobKeyAgreement(Session session,
									   byte[] identityPrivateKey,
									   byte[] aliceIdentityKey,
									   KeyPair usedSignedPreKey,
									   IdentifiableKey usedOneTimePreKey,
									   byte[] aliceEphemeralKey,
									   Settings settings) throws InvalidKeyException
	{
		byte[] signedPreKey = usedSignedPreKey.getPrivateKey();
		AsymmetricCryptography asymmetricCryptography = settings.getAsymmetricCryptography();
		//Create a shared secret
		byte[] sharedSecret = Util.combine(asymmetricCryptography.keyExchange(aliceIdentityKey, signedPreKey),
				asymmetricCryptography.keyExchange(aliceEphemeralKey, identityPrivateKey),
				asymmetricCryptography.keyExchange(aliceEphemeralKey, signedPreKey),
				usedOneTimePreKey == null ? null : asymmetricCryptography.keyExchange(aliceEphemeralKey, usedOneTimePreKey.getKey()));
		KDF kdf = session.getKDF();
		int chainKeySize = settings.getSymmetricKeySize();
		byte[][] keys = deriveRootAndChainKeys(sharedSecret, kdf, settings);
		byte[] rootKey = keys[0];
		byte[] sendingChainKey = keys[1];
		byte[] nextSendingHeaderKey = null;
		byte[] authNextSendingHeaderKey = null;
		byte[] nextReceivingHeaderKey = null;
		byte[] authNextReceivingHeaderKey = null;
		if(settings.isUseHeaderEncryption())
		{
			boolean needAuthKeys = !settings.isUseHeaderEncryption();
			byte[] derivedHeaderKeys = kdf.deriveKey(rootKey, settings.getHeaderKeyInfo(), chainKeySize * (needAuthKeys ? 5 : 3));
			byte[][] splitHeaderKeys = Util.split(derivedHeaderKeys, chainKeySize);
			rootKey = splitHeaderKeys[0];
			nextReceivingHeaderKey = splitHeaderKeys[1];
			nextSendingHeaderKey = splitHeaderKeys[2];
			if(needAuthKeys)
			{
				authNextReceivingHeaderKey = splitHeaderKeys[3];
				authNextSendingHeaderKey = splitHeaderKeys[4];
			}
		}
		session.keyAgreement(aliceIdentityKey,
				usedSignedPreKey,
				rootKey,
				null,
				sendingChainKey,
				null,
				null,
				null,
				nextSendingHeaderKey,
				authNextSendingHeaderKey,
				nextReceivingHeaderKey,
				authNextReceivingHeaderKey);
	}
	
	/**
	 * Derives root key and a chain key using the specified sharedSecret and specified kdf.
	 *
	 * @param sharedSecret to be the derivation input key
	 * @param kdf to derive with
	 * @param settings to use
	 * @return the derived keys (root key on element [0] and chain key on element [1])
	 */
	private static byte[][] deriveRootAndChainKeys(byte[] sharedSecret, KDF kdf, Settings settings) throws InvalidKeyException
	{
		int symmetricKeySize = settings.getSymmetricKeySize();
		return Util.split(kdf.deriveKey(sharedSecret, settings.getDHRatchetInfo(), symmetricKeySize * 2), symmetricKeySize);
	}
}