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

import java.security.InvalidKeyException;

/**
 * A {@link KDF} derives new keys for a specified outputSize based on inputKeys, info and possibly salt (if provided).
 */
public interface KDF
{
	/**
	 * Derives a new key with the specified outputSize based on the specified inputKey and specified info.
	 *
	 * @param inputKey to input
	 * @param info is used for distinction between derived keys
	 * @param outputSize for the new derived key
	 * @return the new derived key
	 * @throws InvalidKeyException if a key used in the process is invalid
	 */
	byte[] deriveKey(byte[] inputKey, byte[] info, int outputSize) throws InvalidKeyException;
	
	/**
	 * Derives a new key with the specified outputSize based on the specified salt, inputKey and specified info.
	 *
	 * @param salt to add to the derivation process
	 * @param inputKey to input
	 * @param info is used for distinction between derived keys
	 * @param outputSize for the new derived key
	 * @return the new derived key
	 * @throws InvalidKeyException if a key used in the process is invalid
	 */
	byte[] deriveKey(byte[] salt, byte[] inputKey, byte[] info, int outputSize) throws InvalidKeyException;
}