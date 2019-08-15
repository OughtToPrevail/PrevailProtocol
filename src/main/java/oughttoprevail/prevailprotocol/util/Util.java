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

import java.util.Arrays;

import oughttoprevail.prevailprotocol.settings.Settings;

/**
 * A utility class.
 */
public interface Util
{
	int BYTE_SIZE = Byte.SIZE;
	int BYTE_BYTES = 1;
	int CHAR_BYTES = Character.SIZE / BYTE_SIZE;
	int SHORT_BYTES = Short.SIZE / BYTE_SIZE;
	int INT_BYTES = Integer.SIZE / BYTE_SIZE;
	int FLOAT_BYTES = Float.SIZE / BYTE_SIZE;
	int LONG_BYTES = Long.SIZE / BYTE_SIZE;
	int DOUBLE_BYTES = Double.SIZE / BYTE_SIZE;
	
	/**
	 * Combines all specified arrays together into one byte[].
	 * Note: the specified arrays cannot be {@code null} but an array inside the the specified arrays
	 * can be {@code null}.
	 * If it is {@code null} it will be ignored when combining into the final result.
	 *
	 * @param arrays the arrays to be combined
	 * @return a new combined byte[] from all the specified arrays
	 */
	static byte[] combine(byte[]... arrays)
	{
		int totalLength = 0;
		for(byte[] in : arrays)
		{
			if(in != null)
			{
				totalLength += in.length;
			}
		}
		byte[] out = new byte[totalLength];
		int offset = 0;
		for(byte[] in : arrays)
		{
			if(in != null)
			{
				int length = in.length;
				System.arraycopy(in, 0, out, offset, length);
				offset += length;
			}
		}
		return out;
	}
	
	/**
	 * @param bytes to split
	 * @param splitLength to be the length of each split {@code byte[]}
	 * @return the specified bytes split into {@code byte[][]} with each {@code byte[]} is a range from the last split (0 if this is the first split)
	 * to the specified splitLength.
	 */
	static byte[][] split(byte[] bytes, int splitLength)
	{
		int totalLength = bytes.length;
		byte[][] split = new byte[totalLength / splitLength][];
		int arrayIndex = 0;
		int position = 0;
		while(position < totalLength)
		{
			split[arrayIndex++] = range(bytes, position, splitLength);
			position += splitLength;
		}
		return split;
	}
	
	/**
	 * @param bytes to split
	 * @param lengths an array of {@code int} with each element being a length to split the {@code byte[]} into
	 * @return the specified bytes split into {@code byte[][]}, each {@code byte[]} is a range from the last split (0 if this is the first split) to
	 * number in the specified lengths at the same index.
	 * If a length in the specified lengths is equal to {@code 0} it will be ignored
	 */
	static byte[][] splitLengths(byte[] bytes, int... lengths)
	{
		int totalLength = bytes.length;
		int splitLength = lengths.length;
		byte[][] split = new byte[splitLength][];
		int arrayIndex = 0;
		int position = 0;
		while(position < totalLength && arrayIndex < splitLength)
		{
			int length = lengths[arrayIndex];
			if(length == 0)
			{
				arrayIndex++;
				continue;
			}
			split[arrayIndex++] = range(bytes, position, length);
			position += length;
		}
		return split;
	}
	
	/**
	 * @param bytes to return the range of
	 * @param offset of the range
	 * @param length of the range
	 * @return a range of the specified bytes from the specified offset to the offset + specified length
	 */
	static byte[] range(byte[] bytes, int offset, int length)
	{
		return rangeTo(bytes, offset, offset + length);
	}
	
	/**
	 * @param bytes to return range of
	 * @param from where to start the range
	 * @param to to end the range
	 * @return a range of the specified bytes from the specified from to the specified to
	 */
	static byte[] rangeTo(byte[] bytes, int from, int to)
	{
		return Arrays.copyOfRange(bytes, from, to);
	}
	
	/**
	 * A {@code byte[]} defining a {@code true} boolean
	 */
	byte[] TRUE = new byte[]{1};
	/**
	 * A {@code byte[]} defining a {@code false} boolean
	 */
	byte[] FALSE = new byte[]{0};
	
	/**
	 * @param value to convert to {@code byte[]}
	 * @return the specified value as a {@code byte[]}
	 */
	static byte[] booleanToBytes(boolean value)
	{
		return value ? TRUE : FALSE;
	}
	
	/**
	 * @param bytes to convert to {@code boolean}
	 * @return the specified bytes as a {@code boolean}
	 */
	static boolean booleanFromBytes(byte[] bytes)
	{
		return bytes[0] == TRUE[0];
	}
	
	/**
	 * @param value to convert to {@code byte[]}
	 * @return the specified value as a {@code byte[]}
	 */
	static byte[] intToBytes(int value)
	{
		return new byte[]{(byte) (value >>> 24), (byte) (value >>> 16), (byte) (value >>> 8), (byte) value};
	}
	
	/**
	 * @param bytes to convert to {@code int}
	 * @return the specified bytes as a {@code int}
	 */
	static int bytesToInt(byte[] bytes)
	{
		return ((bytes[0] & 0xFF) << 24) | ((bytes[1] & 0xFF) << 16) | ((bytes[2] & 0xFF) << 8) | ((bytes[3] & 0xFF));
	}
	
	/**
	 * Equals to {@link Arrays#hashCode(Object[])} just using varargs instead of array.
	 *
	 * @param objects to return hashCode of
	 * @return the hashCode of the all specified objects
	 */
	static int hashCode(Object... objects)
	{
		return Arrays.hashCode(objects);
	}
	
	/**
	 * @param key to create a {@link KeySpec} for
	 * @param settings to use in the {@link KeySpec}
	 * @return the specified key as a {@link KeySpec} using the specified settings
	 */
	static KeySpec newSymmetricKey(byte[] key, Settings settings)
	{
		return new KeySpec(key, settings.getSymmetricAlgorithm());
	}
	
	/**
	 * @param key to create a {@link KeySpec} for
	 * @param settings to use in the {@link KeySpec}
	 * @return the specified key as a {@link KeySpec} using the specified settings
	 */
	static KeySpec newMacKey(byte[] key, Settings settings)
	{
		return new KeySpec(key, settings.getMacAlgorithm());
	}
	
	/**
	 * @param iv to create a {@link IvSpec} for
	 * @param settings to use in the {@link IvSpec}
	 * @return the specified iv as a {@link IvSpec} using the specified settings
	 */
	static IvSpec newIV(byte[] iv, Settings settings)
	{
		if(settings.isUseUpdateAAD())
		{
			return new GCMIvSpec(settings.getMessageMacSize() * Byte.SIZE, iv);
		}
		return new IvSpecImpl(iv);
	}
}