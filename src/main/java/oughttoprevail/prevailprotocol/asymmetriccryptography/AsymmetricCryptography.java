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

import oughttoprevail.prevailprotocol.keys.KeyPair;

/**
 * A {@link AsymmetricCryptography} controls all asymmetric operationsa.
 */
public interface AsymmetricCryptography
{
	/**
	 * Generates and returns a new {@link KeyPair}.
	 *
	 * @return a new generated {@link KeyPair}
	 */
	KeyPair generateKeyPair();
	
	/**
	 * Establishes a shared secret based on the specified publicKey and
	 * specified privateKey.
	 *
	 * @param publicKey parameter of the keyExchange
	 * @param privateKey parameter of the keyExchange
	 * @return shared secret based on the specified parameters
	 */
	byte[] keyExchange(byte[] publicKey, byte[] privateKey);
	
	/**
	 * Signs the specified message with the specified keyPair
	 * and returns the signature.
	 *
	 * @param message to sign
	 * @param privateKey to sign the message with
	 * @return signature of the specified message after signing with the
	 * specified privateKey
	 */
	byte[] sign(byte[] message, byte[] privateKey);
	
	/**
	 * Verifies the specified signature that was signed with the specified
	 * message and the specified publicKey.
	 *
	 * @param signature to verify
	 * @param message which was initially signed
	 * @param publicKey which initially signed the specified message
	 * @return {@code true} if the verification was successful or {@code false}
	 * if verification failed
	 */
	boolean verify(byte[] signature, byte[] message, byte[] publicKey);
	
	/**
	 * @return the size of a public key in bytes
	 */
	int getPublicKeySize();
	
	/**
	 * @return the signature (result of {@link #sign(byte[], byte[])}) size in bytes
	 */
	int getSignatureSize();
}