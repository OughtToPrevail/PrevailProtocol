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
package oughttoprevail.prevailprotocol.util;

import javax.crypto.spec.SecretKeySpec;

/**
 * A {@link KeySpec} is equal to {@link SecretKeySpec} in every way except the key can be gotten with {@link #getKey()} unlike {@link #getEncoded()}
 * which returns a clone of the key.
 */
public class KeySpec extends SecretKeySpec
{
	/**
	 * The secret key
	 */
	private final byte[] key;
	
	/**
	 * Constructs a new {@link KeySpec} with the specified key and specified algorithm.
	 *
	 * @param key to use
	 * @param algorithm to use
	 */
	KeySpec(byte[] key, String algorithm)
	{
		super(key, algorithm);
		this.key = key;
	}
	
	/**
	 * @return the secret key
	 */
	public byte[] getKey()
	{
		return key;
	}
}