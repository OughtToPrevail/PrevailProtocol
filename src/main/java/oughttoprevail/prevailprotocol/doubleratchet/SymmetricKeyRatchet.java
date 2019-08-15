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

import oughttoprevail.prevailprotocol.kdf.KDF;
import oughttoprevail.prevailprotocol.kdf.SimpleKDF;
import oughttoprevail.prevailprotocol.messenger.MessageKeys;
import oughttoprevail.prevailprotocol.settings.Settings;
import oughttoprevail.prevailprotocol.storage.Storage;
import oughttoprevail.prevailprotocol.storage.fields.CounterField;
import oughttoprevail.prevailprotocol.storage.fields.Field;
import oughttoprevail.prevailprotocol.storage.fields.JavaSerDes;
import oughttoprevail.prevailprotocol.util.Util;

/**
 * A {@link SymmetricKeyRatchet} provides forward-secrecy meaning if a key was found in the future, it would not assist with calculating past keys.
 * This is done by deriving a new chain key and message key every step.
 *
 * @see <a href="https://signal.org/docs/specifications/doubleratchet/">Double-Ratchet</a>
 */
public class SymmetricKeyRatchet
{
	/**
	 * Will be used to derive new keys
	 */
	private final KDF kdf;
	/**
	 * Will be used to derive simple keys
	 */
	private final SimpleKDF simpleKDF;
	/**
	 * Storage to store fields
	 */
	private final Storage storage;
	/**
	 * Settings to use
	 */
	private final Settings settings;
	
	/**
	 * Defines the current kdf key, chainKeys will be used to derive new {@link MessageKeys}
	 */
	private final Field<byte[]> chainKey;
	/**
	 * Defines the current counter, resets to 0 every time the {@link #chainKey} value changes by the {@link DHRatchet}
	 * and increments every time a new {@link MessageKeys} is derived
	 */
	private final CounterField counter;
	
	/**
	 * Constructs a new {@link SymmetricKeyRatchet}.
	 */
	public SymmetricKeyRatchet(KDF kdf, SimpleKDF simpleKDF, Storage storage, Settings settings)
	{
		//set fields values
		this.kdf = kdf;
		this.simpleKDF = simpleKDF;
		this.storage = storage;
		this.settings = settings;
		
		//create fields
		this.chainKey = storage.getField(JavaSerDes.BYTE_ARRAY_SER_DES);
		this.counter = new CounterField(storage);
	}
	
	/**
	 * @return the current chainKey bytes
	 */
	public byte[] getChainKey()
	{
		return chainKey.get();
	}
	
	/**
	 * @return the current counter
	 */
	public int getCounter()
	{
		return counter.get();
	}
	
	/**
	 * @return the current counter as bytes
	 */
	public byte[] getCounterBytes()
	{
		return counter.getBytes();
	}
	
	/**
	 * Changes the current value of the specified chainKey and resets the value of the counter to 0.
	 *
	 * @param chainKey to be the new value of the chainKey
	 */
	public void chainKeyChanged(byte[] chainKey)
	{
		this.chainKey.set(chainKey);
		counter.reset();
	}
	
	/**
	 * Equals to {@link #step(boolean)} with the generateMacKey being {@code !{@link Settings#isUseUpdateAAD()}}
	 */
	public MessageKeys step() throws InvalidKeyException
	{
		return step(!settings.isUseUpdateAAD());
	}
	
	/**
	 * Performs a Symmetric-key Ratchet step.
	 *
	 * @param generateMacKey whether to generate a mac key in the {@link MessageKeys}
	 * @return newly derived {@link MessageKeys}
	 */
	public MessageKeys step(boolean generateMacKey) throws InvalidKeyException
	{
		//first derive inputKeyMaterial for the KDF
		byte[] inputKeyMaterial = deriveKey(settings.getMessageKeySeed());
		//derive multiple keys here using the settings symmetricRatchetInfo and inputKeyMaterial
		int symmetricKeySize = settings.getSymmetricKeySize();
		int ivSize = settings.getIVSize();
		int macKeySize = generateMacKey ? settings.getMacKeySize() : 0;
		int outputSize = symmetricKeySize + ivSize + macKeySize;
		byte[] derivedKeys = kdf.deriveKey(inputKeyMaterial, settings.getSymmetricRatchetInfo(), outputSize);
		//split the derivedKeys into a message key an iv and if isUseUpdateAAD is false, then a macKey
		byte[][] split = Util.splitLengths(derivedKeys, symmetricKeySize, ivSize, macKeySize);
		byte[] messageKey = split[0];
		byte[] iv = split[1];
		byte[] macKey = null;
		if(generateMacKey)
		{
			macKey = split[2];
		}
		//update the chainKey
		chainKey.set(deriveKey(settings.getChainKeySeed()));
		//increment the counter
		counter.increment();
		//flush storage
		storage.flush();
		//return new MessageKeys object with all the new generated derived keys
		return new MessageKeys(settings, messageKey, iv, macKey);
	}
	
	/**
	 * Derives a new simple key using the specified seed and the current chainKey.
	 *
	 * @param seed to derive key with
	 * @return the new derived key
	 */
	private byte[] deriveKey(byte[] seed) throws InvalidKeyException
	{
		return simpleKDF.deriveKey(getChainKey(), seed);
	}
}