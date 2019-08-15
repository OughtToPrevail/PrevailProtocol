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
import java.security.InvalidKeyException;

import oughttoprevail.prevailprotocol.settings.Settings;
import oughttoprevail.prevailprotocol.util.Util;

/**
 * A {@link SimpleKDF} provides a very simple KDF which takes a key and a seed (constant) and provide a new derived key.
 */
public class SimpleKDF
{
	/**
	 * Mac to derive with
	 */
	private final Mac mac;
	/**
	 * Settings to use
	 */
	private final Settings settings;
	
	/**
	 * Constructs a new {@link SimpleKDF} with the specified settings and specified mac.
	 *
	 * @param mac to derive with
	 * @param settings to use
	 */
	public SimpleKDF(Mac mac, Settings settings)
	{
		this.settings = settings;
		this.mac = mac;
	}
	
	/**
	 * Derives a new key from the specified key and with specified seed.
	 *
	 * @param key to derive new key from
	 * @param seed to derive new key with
	 * @return a new derived key based on the specified parameters
	 */
	public byte[] deriveKey(byte[] key, byte[] seed) throws InvalidKeyException
	{
		mac.init(Util.newMacKey(key, settings));
		return mac.doFinal(seed);
	}
}