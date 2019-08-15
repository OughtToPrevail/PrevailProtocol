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
package oughttoprevail.prevailprotocol.kdf;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;

import oughttoprevail.prevailprotocol.settings.Settings;
import oughttoprevail.prevailprotocol.util.Util;

/**
 * A Hash-based key derivation function implementation of {@link KDF}.
 *
 * @see <a href="https://tools.ietf.org/html/rfc5869">HMAC-based Extract-and-Expand Key Derivation Function (HKDF)</a>
 */
public class HKDF implements KDF
{
	/**
	 * Default salt, will be used if the {@link Settings#getOutputHashSize()} matches the one in {@link Settings#getDefaultSettings()} to
	 * increase efficiency instead of creating a new salt for each kdf
	 */
	private static final byte[] DEFAULT_ZERO_SALT = new byte[Settings.getDefaultSettings().getOutputHashSize()];
	
	/**
	 * Will be used to derive the keys
	 */
	private final Mac mac;
	/**
	 * Defines necessary variables
	 */
	private final Settings settings;
	/**
	 * Defines an empty (full with zero) {@code byte[]} which is used when a salt is not provided.
	 */
	private final byte[] zeroSalt;
	
	/**
	 * Constructs a new {@link HKDF} with the specified mac and specified settings.
	 *
	 * @param mac to derive keys with
	 * @param settings to use
	 */
	HKDF(Mac mac, Settings settings)
	{
		this.settings = settings;
		this.mac = mac;
		//set zeroSalt to DEFAULT_ZERO_SALT if available, else create a new byte[] matching the Settings.getOutputHashSize()
		this.zeroSalt = settings.getOutputHashSize() == DEFAULT_ZERO_SALT.length ? DEFAULT_ZERO_SALT : new byte[settings.getOutputHashSize()];
	}
	
	/**
	 * Invokes {@link #deriveKey(byte[], byte[], byte[], int)} with the salt as {@link #zeroSalt}.
	 */
	public byte[] deriveKey(byte[] inputKey, byte[] info, int outputSize) throws InvalidKeyException
	{
		return deriveKey(zeroSalt, inputKey, info, outputSize);
	}
	
	/**
	 * Derives a new key using the specified parameters.
	 * Deriving will use extract and expand strategy.
	 *
	 * {@inheritDoc}
	 */
	public byte[] deriveKey(byte[] salt, byte[] inputKey, byte[] info, int outputSize) throws InvalidKeyException
	{
		byte[] generatedKey = extract(salt, inputKey);
		return expand(generatedKey, info, outputSize);
	}
	
	/**
	 * Returns an extracted new key which was generated
	 * with the specified salt and input.
	 * The salt will be a {@link SecretKeySpec} and the inputKey
	 * will be the data passed into the mac.
	 *
	 * @param salt is the key for the mac
	 * @param inputKey the input key for the mac
	 * @return a new derived key generated using the specified parameters
	 */
	private byte[] extract(byte[] salt, byte[] inputKey) throws InvalidKeyException
	{
		mac.init(Util.newMacKey(salt, settings));
		return mac.doFinal(inputKey);
	}
	
	/**
	 * Expands the specified key into the specified outputLength.
	 * The specified info will be used when hashing to add distinction between keys.
	 * Returns the new expanded key.
	 *
	 * @param key to expand
	 * @param info is used for distinction between keys
	 * @param outputLength the requested length for the output key
	 * @return a new expanded key
	 */
	private byte[] expand(byte[] key, byte[] info, int outputLength) throws InvalidKeyException
	{
		mac.init(Util.newMacKey(key, settings));
		int iterations = (int) Math.ceil((double) outputLength / settings.getOutputHashSize());
		byte[] lastHash = null;
		byte[] result = new byte[outputLength];
		int resultIndex = 0;
		for(int i = 0; i < iterations; i++)
		{
			mac.update(lastHash);
			mac.update(info);
			mac.update((byte) i);
			byte[] newHash = mac.doFinal();
			int length = newHash.length;
			System.arraycopy(newHash, 0, result, resultIndex, Math.min(length, outputLength - resultIndex));
			resultIndex += length;
			lastHash = newHash;
		}
		return result;
	}
}